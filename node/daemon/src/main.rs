//! ticker-node — the v27 operator: builder, recycler, status publisher, genesis, rotation, migration.
//!
//! None of these roles is privileged. The builder reads every row's statement for the current
//! minute from the notaries' APIs and posts one update; the same transaction recycles Tickers whose
//! hour is up. `run` does both and publishes `manifest.json` and `status.json` for the web pages.
//!
//! Files under `$TICKER_HOME` (default `~/.ticker-node`):
//!   manifest.json   the public deployment manifest (written by `genesis`, rewritten by `rotate`)
//!   genesis.json    table + electrum pool used once by `genesis`
//!   operator.key    32-byte hex key: funds genesis and reserve top-ups

mod api;
mod builder;
mod chain;
mod genesis;
mod rotate;

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
        "derive" => genesis::derive(&home),
        "genesis" => {
            let reserve: u64 = args.value_from_str("--reserve")?;
            let dry: bool = args.contains("--dry-run");
            let prepare: bool = args.contains("--prepare");
            genesis::genesis(&home, reserve, dry, prepare)
        }
        "approval-request" => {
            let manifest = Manifest::load(home.join("manifest.json")).context("manifest.json")?;
            let migrate = args.contains("--migrate");
            if !migrate {
                manifest.require_current()?;
            }
            let plan = rotate::plan(&manifest, args.opt_value_from_str::<&str, String>("--table")?.map(PathBuf::from), args.opt_value_from_str("--retire-to")?, migrate)?;
            rotate::approval_request(&manifest, &plan)
        }
        "migrate" => {
            let manifest = Manifest::load(home.join("manifest.json")).context("manifest.json")?;
            let approvals: PathBuf = args.value_from_str::<&str, String>("--approvals").map(PathBuf::from).context("--approvals DIR required")?;
            let dry = args.contains("--dry-run");
            let ctx = Arc::new(Ctx { home: home.clone(), manifest });
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(rotate::migrate(ctx, approvals, dry))
        }
        "rotate" => {
            let manifest = Manifest::load(home.join("manifest.json")).context("manifest.json")?;
            manifest.require_current()?;
            let plan = rotate::plan(&manifest, args.opt_value_from_str::<&str, String>("--table")?.map(PathBuf::from), args.opt_value_from_str("--retire-to")?, false)?;
            let approvals: PathBuf = args.value_from_str::<&str, String>("--approvals").map(PathBuf::from).context("--approvals DIR required")?;
            let dry = args.contains("--dry-run");
            let ctx = Arc::new(Ctx { home: home.clone(), manifest });
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(rotate::rotate(ctx, plan, approvals, dry))
        }
        "build" | "run" | "status" | "status-json" | "topup" => {
            let manifest = Manifest::load(home.join("manifest.json")).context("manifest.json")?;
            manifest.require_current()?;
            let once = args.contains("--once");
            let topup_sats: Option<u64> = args.opt_value_from_str("--sats")?;
            let ctx = Arc::new(Ctx { home: home.clone(), manifest });
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            rt.block_on(async move {
                match sub.as_str() {
                    "build" => builder::build_loop(ctx, once, None).await,
                    "topup" => builder::build_loop(ctx, true, Some(topup_sats.ok_or_else(|| anyhow!("--sats required"))?)).await,
                    "status" => builder::status(ctx).await,
                    "status-json" => {
                        println!("{}", serde_json::to_string_pretty(&builder::status_json(&ctx).await)?);
                        Ok(())
                    }
                    _ => {
                        let c2 = ctx.clone();
                        let build = tokio::spawn(async move { builder::build_loop(c2, false, None).await });
                        let publish = match std::env::var("TICKER_PUBLISH_DIR") {
                            Ok(dir) => {
                                let c4 = ctx.clone();
                                tokio::spawn(async move { builder::publish_loop(c4, PathBuf::from(dir), Duration::from_secs(10)).await })
                            }
                            Err(_) => tokio::spawn(async { std::future::pending::<Result<()>>().await }),
                        };
                        tokio::select! {
                            r = publish => { log_error!("publish loop ended"); r? }
                            _ = tokio::signal::ctrl_c() => { log_info!("stop: ctrl-c"); Ok(()) }
                            _ = sigterm() => { log_info!("stop: sigterm"); Ok(()) }
                            r = build => { log_error!("builder loop ended"); r? }
                        }
                    }
                }
            })
        }
        _ => {
            println!(
                "ticker-node v27\n  keygen [--network chipnet|mainnet]      create operator.key, print its address\n  address [--network ..]                  print the operator address\n  derive                                  print the locks, head address and table hash a genesis.json produces\n  genesis --reserve SATS --prepare        create the vout-0 funding coin and print the future category\n  genesis --reserve SATS [--dry-run]      mint the head from genesis.json, write manifest.json\n  run                                     builder + recycler; publishes status when TICKER_PUBLISH_DIR is set\n  build [--once]                          builder only\n  topup --sats N                          one update that also moves a coin of at least N sats into the reserve\n  approval-request --table FILE | --retire-to ADDR | --migrate\n                                          print what the rows must sign (ticker-notary sign-rotate)\n  rotate (--table FILE | --retire-to ADDR) --approvals DIR [--dry-run]\n                                          post the rotation and rewrite manifest.json\n  migrate --approvals DIR [--dry-run]     move a v26 head into the v27 lock; rewrites manifest.json\n  status | status-json\n  env TICKER_PUBLISH_DIR=DIR            run also writes manifest.json + status.json there every 10 s\nFiles live in --home or $TICKER_HOME (default ~/.ticker-node)"
            );
            Ok(())
        }
    }
}

pub(crate) struct Ctx {
    pub home: PathBuf,
    pub manifest: Manifest,
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
