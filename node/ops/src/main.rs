//! ticker-ops — coordinator-side tooling.
//!
//! Subcommands:
//!
//!   ticker-ops setup-all [--seed PATH] [--state PATH] [--out-base DIR]
//!                       [--network chipnet|mainnet]
//!                       [--electrum-host HOST] [--electrum-port PORT]
//!                       [--electrum-tls BOOL]
//!                       [--electrum-fallbacks "host:port,host:port,…"]
//!     Generate 13 per-slot install directories from seed + deploy-state.
//!     `--electrum-fallbacks` (default: two well-known public chipnet
//!     Fulcrums) populates the manifest's fallback pool; publishers fail
//!     over to these when the primary endpoint is unreachable.
//!
//!   ticker-ops dump-state [--state-dir .ticker]
//!     Print manifest + deploy-state + per-publisher state as JSON.
//!
//!   ticker-ops fund --per N [--slots N,M,K] [--seed PATH] [--manifest PATH]
//!                   [--broadcast]
//!     Distribute N sats from master to publishers. Without --slots, all 13.
//!
//!   ticker-ops send --seed PATH --label LABEL --to ADDR --amount SATS
//!                   [--electrum-host HOST] [--electrum-port PORT]
//!                   [--network chipnet|mainnet] [--broadcast]
//!     Sweep / top-up from any labeled wallet to a P2PKH address.

mod deploy;
mod dump;
mod fund;
mod p2pkh;
mod send;
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
        .ok_or("ticker-ops: missing subcommand (deploy|setup-all|dump-state|fund|send)")?;
    match subcmd.as_str() {
        "deploy" => {
            let seed: String = args
                .opt_value_from_str("--seed")?
                .unwrap_or_else(|| ".ticker/seed.hex".to_string());
            let state: String = args
                .opt_value_from_str("--state")?
                .unwrap_or_else(|| ".ticker/deploy-state.json".to_string());
            let network: String = args
                .opt_value_from_str("--network")?
                .unwrap_or_else(|| "chipnet".to_string());
            let electrum_host: String = args
                .opt_value_from_str("--electrum-host")?
                .unwrap_or_else(|| "chipnet.bch.ninja".to_string());
            let electrum_port: u16 = args.opt_value_from_str("--electrum-port")?.unwrap_or(50002);
            let broadcast = args.contains("--broadcast");
            deploy::deploy(&seed, &state, &network, &electrum_host, electrum_port, broadcast)
        }
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
        "send" => {
            let seed: String = args.value_from_str("--seed")?;
            let label: String = args.value_from_str("--label")?;
            let to: String = args.value_from_str("--to")?;
            let amount: u64 = args.value_from_str("--amount")?;
            let electrum_host: String = args
                .opt_value_from_str("--electrum-host")?
                .unwrap_or_else(|| "chipnet.bch.ninja".to_string());
            let electrum_port: u16 = args.opt_value_from_str("--electrum-port")?.unwrap_or(50002);
            let network: String = args
                .opt_value_from_str("--network")?
                .unwrap_or_else(|| "chipnet".to_string());
            let broadcast = args.contains("--broadcast");
            send::send(
                &seed,
                &label,
                &to,
                amount,
                &electrum_host,
                electrum_port,
                &network,
                broadcast,
            )
        }
        "setup-all" => {
            let seed: String = args
                .opt_value_from_str("--seed")?
                .unwrap_or_else(|| ".ticker/seed.hex".to_string());
            let state: String = args
                .opt_value_from_str("--state")?
                .unwrap_or_else(|| ".ticker/deploy-state.json".to_string());
            let out_base: String = args.opt_value_from_str("--out-base")?.unwrap_or_else(|| {
                std::env::var("HOME").unwrap_or_else(|_| ".".to_string())
            });
            let network: String = args
                .opt_value_from_str("--network")?
                .unwrap_or_else(|| "chipnet".to_string());
            let electrum_host: String = args
                .opt_value_from_str("--electrum-host")?
                .unwrap_or_else(|| "chipnet.bch.ninja".to_string());
            let electrum_port: u16 = args.opt_value_from_str("--electrum-port")?.unwrap_or(50002);
            let electrum_tls: bool = args.opt_value_from_str("--electrum-tls")?.unwrap_or(true);
            // --electrum-fallbacks: comma-separated "host:port,host:port,…"
            // Defaults to two well-known public chipnet Fulcrums for failover
            // when the primary (operator's own Fulcrum) is down. Set to empty
            // string to disable.
            let raw_fallbacks: String = args
                .opt_value_from_str("--electrum-fallbacks")?
                .unwrap_or_else(|| {
                    "chipnet.bch.ninja:50002,chipnet.imaginary.cash:50002".to_string()
                });
            let electrum_fallbacks: Vec<(String, u16)> = raw_fallbacks
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let (h, p) = s.split_once(':').ok_or_else(|| {
                        format!("--electrum-fallbacks entry '{s}' must be host:port")
                    })?;
                    let port: u16 = p.parse().map_err(|e| {
                        format!("--electrum-fallbacks entry '{s}' has bad port: {e}")
                    })?;
                    Ok::<(String, u16), String>((h.to_string(), port))
                })
                .collect::<Result<_, _>>()?;
            setup::setup_all(
                &seed,
                &state,
                &out_base,
                &network,
                &electrum_host,
                electrum_port,
                electrum_tls,
                &electrum_fallbacks,
            )
        }
        other => Err(format!("ticker-ops: unknown subcommand '{other}'").into()),
    }
}
