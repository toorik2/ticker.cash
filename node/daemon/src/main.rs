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
    locking::p2sh32_locking_bytecode, redeem_oracle, redeem_publisher_slot, redeem_ticker,
};
use ticker_core::cycle::orchestrator::{run_publisher, RunOpts};
use ticker_core::cycle::state::CycleConfig;
use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::{load_manifest, resolve_identity, Manifest, OperatorKey};
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
    if let Err(e) = real_main() {
        eprintln!("ticker-node fatal: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = pico_args::Arguments::from_env();
    let want_publisher = args.contains("--publisher");
    let once = args.contains("--once");
    let stats_bind: Option<String> = args.opt_value_from_str("--stats-bind")?;
    let slot_flag: Option<u8> = args.opt_value_from_str("--slot")?;

    if !want_publisher {
        eprintln!("ticker-node: must specify --publisher");
        eprintln!("  example: ticker-node --publisher --slot 0");
        std::process::exit(2);
    }

    let manifest_path = home_path("manifest.json");
    let manifest = load_manifest(&manifest_path)?;
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
    let publisher_thread = std::thread::Builder::new()
        .name("publisher".to_string())
        .spawn(move || {
            let opts = RunOpts { once };
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_publisher(&mut env, &cfg, &shutdown_c, opts)
            }));
            match r {
                Ok(Ok(())) => {
                    log_info!("publisher exited cleanly");
                    std::process::exit(0);
                }
                Ok(Err(e)) => {
                    log_error!("publisher fatal", "msg" => e.to_string());
                    std::process::exit(1);
                }
                Err(_) => {
                    log_error!("publisher thread panic");
                    std::process::exit(1);
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

    // Wait on the publisher; it always exits the process directly (clean or
    // not), so this join just parks the main thread until that happens. The
    // stats thread is implicitly cancelled by the process exit.
    let _ = publisher_thread.join();
    log_info!("ticker-node exit");
    Ok(())
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

    // v16: this daemon's slot has its OWN redeem (per-source cnHash baked in).
    // Source id is `slot + 1` (slot 0 → source 1, etc.).
    let source = SOURCES
        .get(slot as usize)
        .ok_or("slot exceeds SOURCES length")?;
    let my_slot_entry = m
        .slot_for(source.id)
        .ok_or_else(|| format!("manifest missing slots[].sourceId={} entry", source.id))?;
    let my_slot_lb_expected: [u8; 35] = hex::decode(&my_slot_entry.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;
    let my_cn_hash: [u8; 20] = hex::decode(&my_slot_entry.cn_hash_hex)?
        .as_slice()
        .try_into()?;
    // Derive the redeem from this daemon's cnHash + oracle category, then
    // assert it matches what the manifest claims. Catches manifest tampering
    // or operator-keying-error at startup, fail-fast.
    let slot_redeem = redeem_publisher_slot(&my_cn_hash, &oracle_cat_le)?;
    let slot_lb_derived = p2sh32_locking_bytecode(&slot_redeem);
    if slot_lb_derived != my_slot_lb_expected {
        return Err(format!(
            "slot locking bytecode mismatch for sourceId={}: derived {} vs manifest {} \
             — wrong manifest or wrong cnHash?",
            source.id,
            hex::encode(slot_lb_derived),
            hex::encode(my_slot_lb_expected),
        )
        .into());
    }
    let ticker_redeem = redeem_ticker()?;

    // Precompute Electrum scripthashes (sha256(locking_script) reversed, lowercase hex).
    let pub_lock = ticker_core::tx::script::p2pkh_locking_script(&key.pkh).to_vec();
    let publisher_scripthash_hex = scripthash_of(&pub_lock);
    let oracle_scripthash_hex = scripthash_of(&oracle_lb);
    let slot_scripthash_hex = scripthash_of(&my_slot_lb_expected);

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

    Ok(CycleConfig {
        slot,
        my_pkh: key.pkh,
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
        publisher_scripthash_hex,
        oracle_category_be_hex: m.oracle.category.clone(),
        slot_category_be_hex: m.slot_category.clone(),
        poll_interval: Duration::from_secs(POLL_INTERVAL_SEC),
        quorum_wait: Duration::from_secs(QUORUM_WAIT_SEC),
    })
}
