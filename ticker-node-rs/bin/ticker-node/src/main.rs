//! ticker-node — operator daemon entry point.
//!
//! One unified process: optionally a notary (HTTP listener), optionally a
//! publisher (cycle loop), optionally a /stats endpoint. Configured by the
//! manifest + per-role keyfile; CLI is a minimal six-flag surface.
//!
//! Layout matches the TS daemon's invocation contract so existing systemd
//! units (`ticker-node-bundled@N.service`, `ticker-node-pub@N.service`) can
//! flip to this binary with only an `ExecStart` change.

mod notary_handler;
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
use ticker_core::identity::manifest::Network;
use ticker_core::identity::{
    load_manifest, resolve_identity, Manifest, OperatorKey, Role,
};
use ticker_core::log_error;
use ticker_core::log_info;
use ticker_core::notary_server::run_notary_server;
use ticker_core::prover::HttpsPlainProver;
use ticker_core::stats_server::run_stats_server;
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};

use notary_handler::{RealNotaryHandler, DEFAULT_PROVER_TIMEOUT};
use real_env::RealEnv;
use stats_collector::{NotaryIdentity, RealStatsCollector};

const NOTARY_BASE_PORT: u16 = 8081;
const TICKER_HOME_ENV: &str = "TICKER_HOME";
const DEFAULT_TICKER_HOME: &str = ".ticker";

/// Resolve a path inside `$TICKER_HOME/`, defaulting to `.ticker/` in the CWD.
fn home_path(suffix: &str) -> PathBuf {
    let base = std::env::var(TICKER_HOME_ENV).unwrap_or_else(|_| DEFAULT_TICKER_HOME.to_string());
    PathBuf::from(base).join(suffix)
}
const ELECTRUM_TIMEOUT_SEC: u64 = 30;
const NOTARY_HTTP_TIMEOUT_SEC: u64 = 10;
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
    let want_notary = args.contains("--notary");
    let want_publisher = args.contains("--publisher");
    let once = args.contains("--once");
    let stats_bind: Option<String> = args.opt_value_from_str("--stats-bind")?;
    let slot_flag: Option<u8> = args.opt_value_from_str("--slot")?;
    let notary_port_flag: Option<u16> = args.opt_value_from_str("--notary-port")?;
    let notary_urls: Vec<String> = collect_repeatable(&mut args, "--notary-url")?;

    if !want_notary && !want_publisher {
        eprintln!("ticker-node: must specify --notary and/or --publisher");
        eprintln!("  examples:");
        eprintln!("    ticker-node --notary");
        eprintln!("    ticker-node --publisher");
        eprintln!("    ticker-node --notary --publisher");
        std::process::exit(2);
    }

    let manifest_path = home_path("manifest.json");
    let manifest = load_manifest(&manifest_path)?;
    let proc_start = SystemTime::now();

    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handlers(shutdown.clone());

    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();

    // Resolve identities up-front so we can fail fast on mismatch.
    let notary_identity = if want_notary {
        Some(resolve_identity(
            Role::Notary,
            &manifest_path,
            home_path("notary.key"),
            slot_flag,
        )?)
    } else {
        None
    };
    let publisher_identity = if want_publisher {
        Some(resolve_identity(
            Role::Publisher,
            &manifest_path,
            home_path("publisher.key"),
            slot_flag,
        )?)
    } else {
        None
    };

    // ─── notary thread ──────────────────────────────────────────────────
    let mut notary_listen_addr: Option<String> = None;
    let mut notary_stats_identity: Option<NotaryIdentity> = None;
    if let Some(id) = &notary_identity {
        let port = notary_port_flag.unwrap_or(NOTARY_BASE_PORT + id.slot as u16);
        let addr = format!("127.0.0.1:{port}");
        notary_listen_addr = Some(addr.clone());
        notary_stats_identity = Some(NotaryIdentity {
            slot: id.slot,
            port,
            address: id.key.label.clone(), // see below — refined to CashAddr after manifest network derive
            pubkey_hex: hex::encode(id.key.public_key),
        });
        let prefix = address_prefix_for(&manifest.network);
        let cash_addr = encode_p2pkh_cashaddr(&id.key.pkh, prefix);
        if let Some(stats) = notary_stats_identity.as_mut() {
            stats.address = cash_addr.clone();
        }
        let handler = Arc::new(RealNotaryHandler {
            slot: id.slot,
            address: cash_addr,
            privkey: id.key.private_key,
            pubkey: id.key.public_key,
            prover: HttpsPlainProver {
                timeout: DEFAULT_PROVER_TIMEOUT,
            },
        });
        let addr_c = addr.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_notary_server(&addr_c, handler) {
                log_error!("notary server stopped", "msg" => e.to_string());
            }
        }));
    }

    // ─── publisher thread ───────────────────────────────────────────────
    if let Some(id) = publisher_identity {
        let cfg = build_publisher_cfg(&manifest, &id.key, id.slot, &notary_urls)?;
        let electrum = ElectrumClient::connect(
            &manifest.electrum.host,
            manifest.electrum.port,
            Duration::from_secs(ELECTRUM_TIMEOUT_SEC),
        )?;
        let mut env = RealEnv {
            electrum: Mutex::new(electrum),
            state_dir: home_path(""),
            notary_http_timeout: Duration::from_secs(NOTARY_HTTP_TIMEOUT_SEC),
        };
        let shutdown_c = shutdown.clone();
        handles.push(std::thread::spawn(move || {
            let opts = RunOpts { once };
            match run_publisher(&mut env, &cfg, &shutdown_c, opts) {
                Ok(()) => log_info!("publisher exited cleanly"),
                Err(e) => log_error!("publisher fatal", "msg" => e.to_string()),
            }
        }));
    }

    // ─── stats thread ───────────────────────────────────────────────────
    if let Some(bind) = stats_bind {
        let collector = Arc::new(RealStatsCollector {
            state_dir: home_path(""),
            notary: notary_stats_identity.clone(),
        });
        let bind_c = bind.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = run_stats_server(&bind_c, collector, proc_start) {
                log_error!("stats server stopped", "msg" => e.to_string());
            }
        }));
    }

    // Held thread joins keep the process alive. SIGINT/SIGTERM flips
    // `shutdown` → publisher loop notices and exits → join.
    for h in handles {
        let _ = h.join();
    }
    log_info!("ticker-node exit", "notary_listen" => notary_listen_addr);
    Ok(())
}

fn collect_repeatable(
    args: &mut pico_args::Arguments,
    flag: &'static str,
) -> Result<Vec<String>, pico_args::Error> {
    let mut out = Vec::new();
    while let Some(v) = args.opt_value_from_str::<&'static str, String>(flag)? {
        out.push(v);
    }
    Ok(out)
}

fn install_signal_handlers(shutdown: Arc<AtomicBool>) {
    // Use a tiny libc-based handler to avoid pulling `signal-hook` for two signals.
    extern "C" fn handle(_sig: i32) {
        SHUTDOWN_FLAG.store(true, Ordering::Relaxed);
    }
    static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);
    unsafe {
        libc_signal(2 /* SIGINT */, handle);
        libc_signal(15 /* SIGTERM */, handle);
    }
    std::thread::spawn(move || loop {
        if SHUTDOWN_FLAG.load(Ordering::Relaxed) {
            shutdown.store(true, Ordering::Relaxed);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    });
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> extern "C" fn(i32);
}
unsafe fn libc_signal(num: i32, handler: extern "C" fn(i32)) {
    let _ = signal(num, handler);
}

fn address_prefix_for(network: &Network) -> AddressPrefix {
    match network {
        Network::Mainnet => AddressPrefix::Mainnet,
        Network::Chipnet => AddressPrefix::Chipnet,
    }
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
    notary_urls_cli: &[String],
) -> Result<CycleConfig, Box<dyn std::error::Error>> {
    // Build redeem scripts from manifest fields and verify against lockingBytecode.
    let oracle_cat_be = hex::decode(&m.oracle.category)?;
    let mut oracle_cat_le: [u8; 32] = oracle_cat_be.as_slice().try_into()?;
    oracle_cat_le.reverse();
    let slot_cat_be = hex::decode(&m.slot.category)?;
    let mut slot_cat_le: [u8; 32] = slot_cat_be.as_slice().try_into()?;
    slot_cat_le.reverse();

    let ticker_lb: [u8; 35] = hex::decode(&m.ticker.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;
    let oracle_lb: [u8; 35] = hex::decode(&m.oracle.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;
    let slot_lb_expected: [u8; 35] = hex::decode(&m.slot.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;

    let oracle_redeem = redeem_oracle(&ticker_lb, &slot_cat_le)?;
    let oracle_lb_derived = p2sh32_locking_bytecode(&oracle_redeem);
    if oracle_lb_derived != oracle_lb {
        return Err("oracle locking bytecode mismatch — wrong manifest?".into());
    }

    let mut notary_pubkeys = [[0u8; 33]; 7];
    for (i, hexk) in m.notary_pubkeys.iter().enumerate() {
        let v = hex::decode(hexk)?;
        notary_pubkeys[i].copy_from_slice(&v);
    }
    let cn_hashes = ticker_core::chain::sources::packed_cn_hashes();
    let slot_redeem =
        redeem_publisher_slot(&notary_pubkeys, &cn_hashes, &oracle_cat_le, &oracle_lb)?;
    let slot_lb_derived = p2sh32_locking_bytecode(&slot_redeem);
    if slot_lb_derived != slot_lb_expected {
        return Err("slot locking bytecode mismatch — wrong manifest?".into());
    }
    let ticker_redeem = redeem_ticker()?;

    // Source id is `slot + 1` because slot 0 → source 1, etc. (per current TS deploy).
    let source = SOURCES
        .get(slot as usize)
        .ok_or("slot exceeds SOURCES length")?;

    let notary_urls = if notary_urls_cli.is_empty() {
        (0..7)
            .map(|i| format!("http://127.0.0.1:{}", NOTARY_BASE_PORT + i))
            .collect()
    } else {
        notary_urls_cli.to_vec()
    };

    let prefix = address_prefix_for(&m.network);
    let publisher_address = encode_p2pkh_cashaddr(&key.pkh, prefix);

    // Precompute Electrum scripthashes (sha256(locking_script) reversed, lowercase hex).
    let pub_lock = ticker_core::tx::script::p2pkh_locking_script(&key.pkh).to_vec();
    let publisher_scripthash_hex = scripthash_of(&pub_lock);
    let oracle_scripthash_hex = scripthash_of(&oracle_lb);
    let slot_scripthash_hex = scripthash_of(&slot_lb_expected);

    Ok(CycleConfig {
        slot,
        my_pkh: key.pkh,
        publisher_privkey: key.private_key,
        publisher_pubkey: key.public_key,
        source_id: source.id,
        notary_urls,
        oracle_category_wire_le: oracle_cat_le,
        slot_category_wire_le: slot_cat_le,
        oracle_redeem_script: oracle_redeem,
        slot_redeem_script: slot_redeem,
        ticker_redeem_script: ticker_redeem,
        publisher_address,
        oracle_address: m.oracle.address.clone(),
        slot_address: m.slot.address.clone(),
        oracle_scripthash_hex,
        slot_scripthash_hex,
        publisher_scripthash_hex,
        oracle_category_be_hex: m.oracle.category.clone(),
        slot_category_be_hex: m.slot.category.clone(),
        poll_interval: Duration::from_secs(POLL_INTERVAL_SEC),
        quorum_wait: Duration::from_secs(QUORUM_WAIT_SEC),
    })
}

