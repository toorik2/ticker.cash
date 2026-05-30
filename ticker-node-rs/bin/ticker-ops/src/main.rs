//! ticker-ops — coordinator-side tooling.
//!
//! Subcommands:
//!   ticker-ops dump-state [--state-dir .ticker]
//!     Print deploy + per-publisher state as JSON.
//!
//!   ticker-ops fund --per N [--seed .ticker/seed.hex]
//!                  [--manifest .ticker/manifest.json] [--broadcast]
//!     Distribute N sats from master to each of 13 publisher wallets.
//!
//!   ticker-ops bake --output install.sh
//!                  [--seed .ticker/seed.hex] [--manifest .ticker/manifest.json]
//!                  --role notary|publisher --slot N
//!                  --binary-url URL --binary-sha256 HEX
//!     Produce a self-extracting bash installer bundling key + manifest +
//!     binary download URL for one operator.
//!
//!   ticker-ops deploy [--broadcast] [--seed PATH]
//!     Run the v12 genesis ceremony — Ticker mint, Oracle mint with bootstrap
//!     commit, PublisherSlot fleet mint (13 slots). Idempotent + resumable
//!     via .ticker/deploy-state.json.

mod bake;
mod deploy;
mod dump;
mod fund;
mod setup;
mod state;

fn main() {
    if let Err(e) = real_main() {
        eprintln!("ticker-ops: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = pico_args::Arguments::from_env();
    let subcmd = args
        .subcommand()?
        .ok_or("ticker-ops: missing subcommand (dump-state|fund|bake|deploy)")?;
    match subcmd.as_str() {
        "dump-state" => {
            let state_dir: String = args
                .opt_value_from_str("--state-dir")?
                .unwrap_or_else(|| ".ticker".to_string());
            dump::dump(&state_dir)
        }
        "fund" => {
            let per_publisher: u64 = args.value_from_str("--per")?;
            let seed: String = args
                .opt_value_from_str("--seed")?
                .unwrap_or_else(|| ".ticker/seed.hex".to_string());
            let manifest: String = args
                .opt_value_from_str("--manifest")?
                .unwrap_or_else(|| ".ticker/manifest.json".to_string());
            let only_slots: Option<Vec<u8>> = args
                .opt_value_from_str::<&'static str, String>("--slots")?
                .map(|s| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                    s.split(',')
                        .map(|n| n.trim().parse::<u8>().map_err(|e| e.into()))
                        .collect::<Result<Vec<u8>, _>>()
                })
                .transpose()?;
            let broadcast = args.contains("--broadcast");
            fund::fund(&seed, &manifest, per_publisher, only_slots, broadcast)
        }
        "bake" => {
            let output: String = args.value_from_str("--output")?;
            let role: String = args.value_from_str("--role")?;
            let slot: u8 = args.value_from_str("--slot")?;
            let binary_url: String = args.value_from_str("--binary-url")?;
            let binary_sha256: String = args.value_from_str("--binary-sha256")?;
            let seed: String = args
                .opt_value_from_str("--seed")?
                .unwrap_or_else(|| ".ticker/seed.hex".to_string());
            let manifest: String = args
                .opt_value_from_str("--manifest")?
                .unwrap_or_else(|| ".ticker/manifest.json".to_string());
            bake::bake(&seed, &manifest, &role, slot, &binary_url, &binary_sha256, &output)
        }
        "deploy" => {
            let broadcast = args.contains("--broadcast");
            let seed: String = args
                .opt_value_from_str("--seed")?
                .unwrap_or_else(|| ".ticker/seed.hex".to_string());
            deploy::deploy(&seed, broadcast)
        }
        "setup-all" => {
            let seed: String = args
                .opt_value_from_str("--seed")?
                .unwrap_or_else(|| ".ticker/seed.hex".to_string());
            let state: String = args
                .opt_value_from_str("--state")?
                .unwrap_or_else(|| ".ticker/deploy-state.json".to_string());
            let out_base: String = args
                .opt_value_from_str("--out-base")?
                .unwrap_or_else(|| {
                    std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
                });
            let network: String = args
                .opt_value_from_str("--network")?
                .unwrap_or_else(|| "chipnet".to_string());
            let electrum_host: String = args
                .opt_value_from_str("--electrum-host")?
                .unwrap_or_else(|| "fulcrum.layer1.cash".to_string());
            let electrum_port: u16 = args.opt_value_from_str("--electrum-port")?.unwrap_or(50002);
            let electrum_tls: bool = args.opt_value_from_str("--electrum-tls")?.unwrap_or(true);
            setup::setup_all(
                &seed,
                &state,
                &out_base,
                &network,
                &electrum_host,
                electrum_port,
                electrum_tls,
            )
        }
        other => Err(format!("ticker-ops: unknown subcommand '{other}'").into()),
    }
}
