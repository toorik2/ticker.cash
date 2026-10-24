//! ticker-node — the v25 operator: prover, builder, sweeper, genesis.
//!
//! None of these roles is privileged. A prover opens TLSNotary sessions with the notaries and
//! collects their statements; a builder posts an update whenever a new minute has a quorum;
//! a sweeper reclaims aged Ticker dust. `run` does all three in one process.
//!
//! Files under `$TICKER_HOME` (default `~/.ticker-node`):
//!   manifest.json   the public deployment manifest (written by `genesis`)
//!   genesis.json    table + electrum pool used once by `genesis`
//!   operator.key    32-byte hex key: funds genesis and reserve top-ups, receives sweeps

mod api;
mod builder;
mod chain;
mod genesis;
mod prover;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ticker_core::keyfile::{generate_key_file, load_key};
use ticker_core::manifest::Manifest;
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::{log_error, log_info};

pub(crate) fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("TICKER_HOME") {
        return PathBuf::from(h);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ticker-node")
}

fn main() {
    let code = match real_main() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ticker-node: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn real_main() -> Result<()> {
    let mut args = pico_args::Arguments::from_env();
    let home: PathBuf = args.opt_value_from_str::<&str, String>("--home")?.map(PathBuf::from).unwrap_or_else(home_dir);
    let sub = args.subcommand()?.unwrap_or_else(|| "help".into());
    match sub.as_str() {
        "keygen" => {
            std::fs::create_dir_all(&home)?;
            let network: String = args.opt_value_from_str("--network")?.unwrap_or_else(|| "chipnet".into());
            let prefix = AddressPrefix::from_network(&network).ok_or_else(|| anyhow!("network must be chipnet or mainnet"))?;
            let k = generate_key_file(home.join("operator.key"))?;
            println!("{}", encode_p2pkh_cashaddr(&k.pkh, prefix));
            Ok(())
        }
        "address" => {
            let network: String = args.opt_value_from_str("--network")?.unwrap_or_else(|| "chipnet".into());
            let prefix = AddressPrefix::from_network(&network).ok_or_else(|| anyhow!("network must be chipnet or mainnet"))?;
            let k = load_key(home.join("operator.key"))?;
            println!("{}", encode_p2pkh_cashaddr(&k.pkh, prefix));
            Ok(())
        }
        "derive" => {
            // print the locks and head address a genesis.json table would produce (no network, no funds)
            let raw = std::fs::read_to_string(home.join("genesis.json")).context("genesis.json")?;
            let spec: serde_json::Value = serde_json::from_str(&raw)?;
            let network = spec["network"].as_str().unwrap_or("chipnet").to_string();
            let prefix = AddressPrefix::from_network(&network).ok_or_else(|| anyhow!("network must be chipnet or mainnet"))?;
            let rows: Vec<ticker_core::manifest::TableRow> = serde_json::from_value(spec["table"].clone())?;
            let m = Manifest {
                version: 25,
                network,
                category: "00".repeat(32),
                genesis_txid: String::new(),
                oracle_lock: String::new(),
                ticker_lock: hex::encode(ticker_core::tx::covenant::ticker_lock()),
                table: rows,
                electrum: vec![ticker_core::manifest::ElectrumEndpoint { host: "x".into(), port: 1, tls: true }],
            };
            let table = m.table_bytes();
            let lock = ticker_core::tx::covenant::oracle_lock_for_table(&table);
            let mut m = m;
            m.oracle_lock = hex::encode(lock);
            m.validate().context("table")?;
            println!("oracle_lock  {}", m.oracle_lock);
            println!("ticker_lock  {}", m.ticker_lock);
            println!("head address {}", ticker_core::tx::cashaddr::encode_p2sh32_cashaddr(&lock, prefix));
            println!("table sha256 {}", hex::encode(ticker_core::crypto::sha256(&table)));
            Ok(())
        }
        "genesis" => {
            let reserve: u64 = args.value_from_str("--reserve")?;
            let dry: bool = args.contains("--dry-run");
            let prepare: bool = args.contains("--prepare");
            genesis::genesis(&home, reserve, dry, prepare)
        }
        "prove" | "build" | "sweep" | "run" | "status" | "status-json" | "topup" => {
            let manifest = Manifest::load(home.join("manifest.json")).context("manifest.json")?;
            let once = args.contains("--once");
            let rows: Option<String> = args.opt_value_from_str("--rows")?;
            let mode: String = args.opt_value_from_str("--mode")?.unwrap_or_else(|| "auto".into());
            let topup_sats: Option<u64> = args.opt_value_from_str("--sats")?;
            let min_age: i64 = args.opt_value_from_str("--min-age-blocks")?.unwrap_or(144);
            let rows: Vec<u8> = match rows {
                Some(r) => r.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse::<u8>()).collect::<Result<_, _>>()?,
                None => (0..manifest.table.len() as u8).collect(),
            };
            let ctx = Arc::new(Ctx { home: home.clone(), manifest, prover_mode: mode, min_age_blocks: min_age });
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(async move {
                match sub.as_str() {
                    "prove" => prover::prove_loop(ctx, rows, once).await,
                    "build" => builder::build_loop(ctx, once, None).await,
                    "topup" => builder::build_loop(ctx, true, Some(topup_sats.ok_or_else(|| anyhow!("--sats required"))?)).await,
                    "sweep" => builder::sweep_loop(ctx, once).await,
                    "status" => builder::status(ctx).await,
                    "status-json" => { println!("{}", serde_json::to_string_pretty(&builder::status_json(&ctx).await)?); Ok(()) }
                    _ => {
                        let c1 = ctx.clone();
                        let c2 = ctx.clone();
                        let c3 = ctx.clone();
                        let prove = tokio::spawn(async move { prover::prove_loop(c1, rows, false).await });
                        let build = tokio::spawn(async move { builder::build_loop(c2, false, None).await });
                        let sweep = tokio::spawn(async move { builder::sweep_loop(c3, false).await });
                        let publish = match std::env::var("TICKER_PUBLISH_DIR") {
                            Ok(dir) => { let c4 = ctx.clone(); tokio::spawn(async move { builder::publish_loop(c4, PathBuf::from(dir), Duration::from_secs(10)).await }) }
                            Err(_) => tokio::spawn(async { std::future::pending::<Result<()>>().await }),
                        };
                        tokio::select! {
                            r = publish => { log_error!("publish loop ended"); r? }
                            _ = tokio::signal::ctrl_c() => { log_info!("stop: ctrl-c"); Ok(()) }
                            _ = sigterm() => { log_info!("stop: sigterm"); Ok(()) }
                            r = prove => { log_error!("prover loop ended"); r? }
                            r = build => { log_error!("builder loop ended"); r? }
                            r = sweep => { log_error!("sweeper loop ended"); r? }
                        }
                    }
                }
            })
        }
        _ => {
            println!(
                "ticker-node v25\n  keygen [--network chipnet|mainnet]      create operator.key, print its address\n  address [--network ..]                  print the operator address\n  derive                                  print the locks a genesis.json table produces\n  genesis --reserve SATS --prepare        create the vout-0 funding coin and print the future category\n  genesis --reserve SATS [--dry-run]      mint the head from genesis.json, write manifest.json\n  run                                     prover + builder + sweeper\n  prove [--rows 0,1] [--once] [--mode auto|proxy|mpc]\n  build [--once]\n  topup --sats N                          one update that also moves N sats from operator.key into the reserve\n  sweep [--once] [--min-age-blocks 144]\n  status | status-json\n  env TICKER_PUBLISH_DIR=DIR            run also writes manifest.json + status.json there every 10 s\nFiles live in --home or $TICKER_HOME (default ~/.ticker-node)"
            );
            Ok(())
        }
    }
}

pub(crate) struct Ctx {
    pub home: PathBuf,
    pub manifest: Manifest,
    pub prover_mode: String,
    pub min_age_blocks: i64,
}

pub(crate) async fn sigterm() {
    #[cfg(unix)]
    {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await;
}

/// Sleep until `secs_into_minute` seconds past the next minute boundary.
pub(crate) async fn sleep_until_next_minute(secs_into_minute: u64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let next = (now / 60.0).floor() * 60.0 + 60.0 + secs_into_minute as f64;
    let wait = (next - now).max(0.0);
    tokio::time::sleep(Duration::from_secs_f64(wait)).await;
}
