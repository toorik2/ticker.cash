//! ticker-node — operator daemon entry point.
//!
//! One unified process: cycle loop + optional `/stats` endpoint. Configured by
//! the manifest + per-role keyfile; CLI is a minimal four-flag surface
//! (`--publisher`, `--once`, `--stats-bind`, `--slot`).

mod real_env;
mod stats_collector;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ticker_core::chain::sources::SOURCES;
use ticker_core::covenant::{
    locking::p2sh32_locking_bytecode, redeem_oracle, redeem_ticker, specialize_slot_body,
};
use ticker_core::cycle::orchestrator::{run_publisher, RunOpts};
use ticker_core::cycle::state::CycleConfig;
use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::{load_manifest_hash_pinned, resolve_identity, Manifest, OperatorKey};
use ticker_core::log_error;
use ticker_core::log_info;
use ticker_core::stats::run_stats;

use real_env::RealEnv;
use stats_collector::RealStatsCollector;

const TICKER_HOME_ENV: &str = "TICKER_HOME";

/// Resolve a path inside `$TICKER_HOME/`. Defaults to `$HOME/.ticker/` if the
/// env var is unset. Errors out only if BOTH `TICKER_HOME` and `HOME` are
/// unset, which would be a deeply unusual systemd or container config.
fn home_path(suffix: &str) -> PathBuf {
    let base = std::env::var(TICKER_HOME_ENV).unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| {
            eprintln!("ticker-node: neither TICKER_HOME nor HOME is set; falling back to ./.ticker");
            ".".to_string()
        });
        format!("{home}/.ticker")
    });
    PathBuf::from(base).join(suffix)
}
const ELECTRUM_TIMEOUT_SEC: u64 = 30;
const POLL_INTERVAL_SEC: u64 = 3;
const QUORUM_WAIT_SEC: u64 = 25;

fn main() {
    // v24 P04 — install panic hook BEFORE any allocation so a panic during
    // setup can still suppress its core dump. Then funnel all exit paths
    // through a single std::process::exit AFTER real_main has dropped its
    // locals (Drop bypasses on process::exit, so the call site has to come
    // after the Drop region we care about).
    install_panic_hook();
    let code = match real_main() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ticker-node fatal: {e}");
            1
        }
    };
    std::process::exit(code);
}

/// v24 P04 — disable core dumps from the panic hook so any privkey heap
/// residue cannot be post-mortem-extracted via core file. Layers with
/// systemd `LimitCORE=0` (P07): two independent gates, both apply.
fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("ticker-node panic: {info}");
        unsafe {
            let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            libc::setrlimit(libc::RLIMIT_CORE, &lim);
        }
        prev(info);
    }));
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = pico_args::Arguments::from_env();
    let want_publisher = args.contains("--publisher");
    let once = args.contains("--once");
    let stats_bind: Option<String> = args.opt_value_from_str("--stats-bind")?;
    let slot_flag: Option<u8> = args.opt_value_from_str("--slot")?;

    if !want_publisher {
        return Err("ticker-node: must specify --publisher (example: --publisher --slot 0)".into());
    }

    let manifest_path = home_path("manifest.json");
    // v24 P05 — TOFU hash-pin: writes manifest.sha256 sidecar on first load,
    // refuses to start on any subsequent on-disk divergence. Closes F09.
    let manifest = load_manifest_hash_pinned(&manifest_path)?;
    let proc_start = SystemTime::now();

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handlers(shutdown.clone());

    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

    let publisher_identity = resolve_identity(
        &manifest_path,
        home_path("publisher.key"),
        slot_flag,
    )?;

    // ─── publisher thread ───────────────────────────────────────────────
    let cfg = build_publisher_cfg(&manifest, &publisher_identity.key, publisher_identity.slot)?;
    let endpoints = manifest.electrum.endpoint_pool();
    log_info!(
        "publisher: electrum pool",
        "primary" => format!("{}:{}", endpoints[0].host, endpoints[0].port),
        "fallback_count" => endpoints.len() - 1,
    );
    // Resilient boot: a brief Fulcrum outage at process start shouldn't kill
    // the daemon and trigger a systemd restart loop. Retry until we connect,
    // or until shutdown is signalled.
    let electrum = loop {
        match ElectrumClient::connect_pool(
            endpoints.clone(),
            Duration::from_secs(ELECTRUM_TIMEOUT_SEC),
        ) {
            Ok(c) => break c,
            Err(_) if shutdown.load(Ordering::Relaxed) => return Ok(()),
            Err(e) => {
                log_error!(
                    "publisher: electrum pool unreachable at boot — retrying",
                    "err" => e.to_string()
                );
                std::thread::sleep(Duration::from_secs(15));
            }
        }
    };
    let mut env = RealEnv {
        electrum: Mutex::new(electrum),
        state_dir: home_path(""),
        prover: ticker_core::prover::HttpsPlainProver {
            timeout: Duration::from_secs(5),
        },
    };
    let shutdown_c = shutdown.clone();
    // v24 P04 — publisher thread returns Result instead of calling exit.
    // Lets the main thread propagate the outcome through real_main's
    // Result chain, so the single `process::exit` in main() fires after
    // all stack locals (including CycleConfig holding the privkey copy)
    // have dropped and zeroized.
    let publisher_thread: std::thread::JoinHandle<Result<(), String>> = std::thread::Builder::new()
        .name("publisher".to_string())
        .spawn(move || {
            let opts = RunOpts { once };
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_publisher(&mut env, &cfg, &shutdown_c, opts)
            }));
            match r {
                Ok(Ok(())) => {
                    log_info!("publisher exited cleanly");
                    Ok(())
                }
                Ok(Err(e)) => {
                    log_error!("publisher fatal", "msg" => e.to_string());
                    Err(e.to_string())
                }
                Err(_) => {
                    log_error!("publisher thread panic");
                    Err("publisher panic".into())
                }
            }
        })?;

    // ─── stats thread ───────────────────────────────────────────────────
    if let Some(bind) = stats_bind {
        let collector = Arc::new(RealStatsCollector {
            state_dir: home_path(""),
        });
        let bind_c = bind.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_stats(&bind_c, collector, proc_start) {
                log_error!("stats server stopped", "msg" => e.to_string());
            }
        }));
    }

    // v24 P04 — propagate publisher result through real_main's Result.
    // Main() drives the single process::exit afterwards. The stats thread
    // is implicitly cancelled by the process exit.
    let result: Result<(), Box<dyn std::error::Error>> = match publisher_thread.join() {
        Ok(Ok(()))  => Ok(()),
        Ok(Err(e))  => Err(e.into()),
        Err(_panic) => Err("publisher join panic".into()),
    };
    log_info!("ticker-node exit");
    result
}

fn install_signal_handlers(shutdown: Arc<AtomicBool>) {
    // Avoid pulling `signal-hook` for two signals. `signal()` is portable
    // enough for the SIGINT/SIGTERM use; glibc preserves the handler across
    // deliveries, which is what we need.
    extern "C" fn handle(_sig: i32) {
        SHUTDOWN_FLAG.store(true, Ordering::Relaxed);
    }
    extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> extern "C" fn(i32);
    }
    static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);
    unsafe {
        let _ = signal(2 /* SIGINT */, handle);
        let _ = signal(15 /* SIGTERM */, handle);
    }
    std::thread::spawn(move || loop {
        if SHUTDOWN_FLAG.load(Ordering::Relaxed) {
            shutdown.store(true, Ordering::Relaxed);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    });
}

/// Electrum scripthash convention: `sha256(locking_script)`, reversed, lowercase hex.
fn scripthash_of(locking_script: &[u8]) -> String {
    let mut h = ticker_core::crypto::sha256(locking_script);
    h.reverse();
    hex::encode(h)
}

fn build_publisher_cfg(
    m: &Manifest,
    key: &OperatorKey,
    slot: u8,
) -> Result<CycleConfig, Box<dyn std::error::Error>> {
    // Build redeem scripts from manifest fields and verify against lockingBytecode.
    let oracle_cat_be = hex::decode(&m.oracle.category)?;
    let mut oracle_cat_le: [u8; 32] = oracle_cat_be.as_slice().try_into()?;
    oracle_cat_le.reverse();
    let slot_cat_be = hex::decode(&m.slot_category)?;
    let mut slot_cat_le: [u8; 32] = slot_cat_be.as_slice().try_into()?;
    slot_cat_le.reverse();

    let ticker_lb: [u8; 35] = hex::decode(&m.ticker.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;
    let oracle_lb: [u8; 35] = hex::decode(&m.oracle.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;

    let oracle_redeem = redeem_oracle(&ticker_lb, &slot_cat_le)?;
    let oracle_lb_derived = p2sh32_locking_bytecode(&oracle_redeem);
    if oracle_lb_derived != oracle_lb {
        return Err("oracle locking bytecode mismatch — wrong manifest?".into());
    }

    // v22: this daemon's slot is P2S — LB IS the specialized body bytes.
    // Source id is `slot + 1` (slot 0 → source 1, etc.).
    let source = SOURCES
        .get(slot as usize)
        .ok_or("slot exceeds SOURCES length")?;
    let oracle_cat_hash = ticker_core::crypto::hash160(&oracle_cat_le);

    // v24 P05 — verify ALL 13 cross-daemon slot LBs (closes W11-22.3).
    // Previously only this daemon's own slot was verified; a tampered
    // manifest could swap any of the OTHER 12 slot lockings without
    // detection on this publisher's box. Now every daemon validates
    // the full set on startup.
    let mut my_cn_hash: Option<[u8; 20]> = None;
    let mut my_slot_lb_expected: Option<Vec<u8>> = None;
    for s in &m.slots {
        let s_pkh: [u8; 20] = hex::decode(&s.publisher_pkh_hex)?
            .as_slice()
            .try_into()
            .map_err(|_| format!("slots[].sourceId={} publisherPkhHex not 20 B", s.source_id))?;
        let s_cn: [u8; 20] = hex::decode(&s.cn_hash_hex)?
            .as_slice()
            .try_into()
            .map_err(|_| format!("slots[].sourceId={} cnHashHex not 20 B", s.source_id))?;
        let s_lb_expected: Vec<u8> = hex::decode(&s.locking_bytecode_hex)?;
        let s_lb_derived = specialize_slot_body(&s_pkh, &s_cn, &oracle_cat_hash)?;
        if s_lb_derived != s_lb_expected {
            return Err(format!(
                "slot locking bytecode mismatch for sourceId={}: derived {} vs manifest {} \
                 — wrong manifest or wrong cnHash/pkh?",
                s.source_id,
                hex::encode(&s_lb_derived),
                hex::encode(&s_lb_expected),
            )
            .into());
        }
        if s.source_id == source.id {
            // Sanity: the manifest entry for THIS publisher's slot must agree
            // with the operator key's actual pkh.
            if s_pkh != key.pkh {
                return Err(format!(
                    "manifest slots[].sourceId={} publisherPkhHex {} != operator key pkh {} \
                     — wrong key for this slot?",
                    s.source_id,
                    hex::encode(s_pkh),
                    hex::encode(key.pkh),
                )
                .into());
            }
            my_cn_hash = Some(s_cn);
            my_slot_lb_expected = Some(s_lb_derived);
        }
    }
    let my_cn_hash = my_cn_hash
        .ok_or_else(|| format!("manifest missing slots[].sourceId={}", source.id))?;
    let my_slot_lb_expected = my_slot_lb_expected
        .expect("my_slot_lb_expected populated whenever my_cn_hash is");
    let slot_redeem = my_slot_lb_expected.clone();
    let ticker_redeem = redeem_ticker()?;

    // Precompute Electrum scripthashes (sha256(locking_script) reversed, lowercase hex).
    let pub_lock = ticker_core::tx::script::p2pkh_locking_script(&key.pkh).to_vec();
    let publisher_scripthash_hex = scripthash_of(&pub_lock);
    let oracle_scripthash_hex = scripthash_of(&oracle_lb);
    let slot_scripthash_hex = scripthash_of(&my_slot_lb_expected);
    let _ = ticker_redeem.len(); // silence unused-warning hint; used downstream

    // v16: pre-compute scripthashes for ALL 13 slots (each lives at its own
    // P2SH-32 in v16). Used by `get_slot_utxos` to aggregate the quorum.
    let all_slot_scripthashes_hex: Vec<String> = m
        .slots
        .iter()
        .map(|s| {
            let lb = hex::decode(&s.locking_bytecode_hex)?;
            Ok::<_, Box<dyn std::error::Error>>(scripthash_of(&lb))
        })
        .collect::<Result<_, _>>()?;

    // v17: pre-compute the pkh→cnHash table for all 13 slots (still useful
    // for daemon-side identity bookkeeping even though not used in tx build).
    let all_pkh_to_cn_hash: Vec<([u8; 20], [u8; 20])> = m
        .slots
        .iter()
        .map(|s| {
            let pkh: [u8; 20] = hex::decode(&s.publisher_pkh_hex)?
                .as_slice()
                .try_into()
                .map_err(|_| "slot pkh hex not 20 B")?;
            let cn: [u8; 20] = hex::decode(&s.cn_hash_hex)?
                .as_slice()
                .try_into()
                .map_err(|_| "slot cnHash hex not 20 B")?;
            Ok::<_, Box<dyn std::error::Error>>((pkh, cn))
        })
        .collect::<Result<_, _>>()?;

    // v22: pre-compute per-source pkhs (in source-id order, parallel to
    // all_slot_scripthashes_hex) and per-source P2S locking bytecodes.
    let all_slot_pkhs: Vec<[u8; 20]> = m
        .slots
        .iter()
        .map(|s| {
            let pkh: [u8; 20] = hex::decode(&s.publisher_pkh_hex)?
                .as_slice()
                .try_into()
                .map_err(|_| "slot pkh hex not 20 B")?;
            Ok::<_, Box<dyn std::error::Error>>(pkh)
        })
        .collect::<Result<_, _>>()?;
    let all_slot_lockings: Vec<Vec<u8>> = m
        .slots
        .iter()
        .map(|s| Ok::<_, Box<dyn std::error::Error>>(hex::decode(&s.locking_bytecode_hex)?))
        .collect::<Result<_, _>>()?;
    let all_pkh_to_locking: Vec<([u8; 20], Vec<u8>)> = all_slot_pkhs
        .iter()
        .zip(all_slot_lockings.iter())
        .map(|(p, lb)| (*p, lb.clone()))
        .collect();

    Ok(CycleConfig {
        slot,
        my_pkh: key.pkh,
        my_cn_hash20: my_cn_hash,
        publisher_privkey: key.private_key,
        publisher_pubkey: key.public_key,
        source_id: source.id,
        oracle_category_wire_le: oracle_cat_le,
        slot_category_wire_le: slot_cat_le,
        oracle_redeem_script: oracle_redeem,
        slot_redeem_script: slot_redeem,
        ticker_redeem_script: ticker_redeem,
        oracle_scripthash_hex,
        slot_scripthash_hex,
        all_slot_scripthashes_hex,
        all_pkh_to_cn_hash,
        all_slot_pkhs,
        all_slot_lockings,
        all_pkh_to_locking,
        publisher_scripthash_hex,
        oracle_category_be_hex: m.oracle.category.clone(),
        slot_category_be_hex: m.slot_category.clone(),
        poll_interval: Duration::from_secs(POLL_INTERVAL_SEC),
        quorum_wait: Duration::from_secs(QUORUM_WAIT_SEC),
    })
}
