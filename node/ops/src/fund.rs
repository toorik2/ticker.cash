//! `ticker-ops fund` — distribute sats from master to publisher wallets.
//!
//! Without `--slots`, fans out to all 13. With `--slots N,M,K`, only those.

use std::time::Duration;

use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::manifest::{load_manifest, Network};
use ticker_core::identity::seed::{derive_wallet, load_seed};
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::encode::Output;
use ticker_core::tx::script::p2pkh_locking_script;

use crate::p2pkh::{build_signed_p2pkh_tx, Signer};

const ELECTRUM_TIMEOUT_SEC: u64 = 30;
const TX_FEE_BUFFER: u64 = 3_000;

pub fn fund(
    seed_path: &str,
    manifest_path: &str,
    per_publisher_sats: u64,
    only_slots: Option<Vec<u8>>,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = load_seed(seed_path)?;
    let master = derive_wallet(&seed, "master")?;
    let manifest = load_manifest(manifest_path)?;
    let prefix = match manifest.network {
        Network::Mainnet => AddressPrefix::Mainnet,
        Network::Chipnet => AddressPrefix::Chipnet,
    };
    let master_addr = encode_p2pkh_cashaddr(&master.pkh, prefix);
    println!("master address: {master_addr}");

    let slots: Vec<u8> = match only_slots {
        Some(v) if !v.is_empty() => {
            let mut v = v;
            v.sort_unstable();
            v.dedup();
            for s in &v {
                if *s > 12 {
                    return Err(format!("slot {s} out of range 0..=12").into());
                }
            }
            v
        }
        _ => (0..13).collect(),
    };

    let mut electrum = ElectrumClient::connect(
        &manifest.electrum.host,
        manifest.electrum.port,
        Duration::from_secs(ELECTRUM_TIMEOUT_SEC),
    )?;
    let master_utxos = electrum.list_unspent(&master_addr)?;
    let non_token: Vec<_> = master_utxos.into_iter().filter(|u| u.token_data.is_none()).collect();

    println!("funding {} slot(s): {:?}", slots.len(), slots);
    let mut outputs = Vec::with_capacity(slots.len());
    for i in &slots {
        let pub_w = derive_wallet(&seed, &format!("publisher-{i}"))?;
        let pub_addr = encode_p2pkh_cashaddr(&pub_w.pkh, prefix);
        println!("  publisher-{i}: {pub_addr} → {per_publisher_sats} sats");
        outputs.push(Output {
            value: per_publisher_sats,
            locking_script: p2pkh_locking_script(&pub_w.pkh).to_vec(),
            token: None,
        });
    }

    let signer = Signer {
        private_key: master.private_key,
        public_key: master.public_key,
        pkh: master.pkh,
    };
    let raw = build_signed_p2pkh_tx(&signer, &non_token, outputs, TX_FEE_BUFFER, prefix)?;
    println!("\nfund tx hex ({} bytes):\n{}", raw.len(), hex::encode(&raw));

    if broadcast {
        let txid = electrum.broadcast_raw(&raw)?;
        println!("\nbroadcast ok: {txid}");
    } else {
        println!("\n(dry-run — pass --broadcast to send)");
    }
    Ok(())
}
