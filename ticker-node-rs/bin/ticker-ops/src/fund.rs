//! `ticker-ops fund` — distribute sats from the master wallet to 13 publisher
//! wallets in a single tx. Single funder (master) + N P2PKH outputs.

use std::time::Duration;

use ticker_core::crypto::{double_sha256, sign_ecdsa};
use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::manifest::{load_manifest, Network};
use ticker_core::identity::seed::{derive_wallet, load_seed};
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::encode::{encode_tx, Input, Output, Tx, TxOutpoint, DEFAULT_SEQUENCE};
use ticker_core::tx::script::{p2pkh_locking_script, push_data};
use ticker_core::tx::sighash::{p2pkh_sighash_preimage, SIGHASH_BIT};

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
    let total: u64 = non_token.iter().map(|u| u.value).sum();
    let need = per_publisher_sats * slots.len() as u64 + TX_FEE_BUFFER;
    if total < need {
        return Err(format!("master too low: have {total} sats, need {need}").into());
    }

    println!("funding {} slot(s): {:?}", slots.len(), slots);
    // Derive each targeted publisher's pkh + locking script.
    let mut outputs = Vec::with_capacity(slots.len() + 1);
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
    let change = total - per_publisher_sats * slots.len() as u64 - TX_FEE_BUFFER;
    if change >= 546 {
        outputs.push(Output {
            value: change,
            locking_script: p2pkh_locking_script(&master.pkh).to_vec(),
            token: None,
        });
    }

    // Build inputs with empty unlock scripts first.
    let mut inputs = Vec::with_capacity(non_token.len());
    for u in &non_token {
        let mut txid_be = [0u8; 32];
        txid_be.copy_from_slice(&hex::decode(&u.tx_hash)?);
        inputs.push(Input {
            prev: TxOutpoint {
                txid_be,
                vout: u.tx_pos,
            },
            unlock_script: Vec::new(),
            sequence: DEFAULT_SEQUENCE,
        });
    }
    let mut tx = Tx::new(inputs, outputs);

    // Sign each input.
    let master_locking = p2pkh_locking_script(&master.pkh).to_vec();
    for (i, u) in non_token.iter().enumerate() {
        let preimage = p2pkh_sighash_preimage(&tx, i, &master_locking, u.value);
        let digest = double_sha256(&preimage);
        let sig = sign_ecdsa(&master.private_key, &digest)?;
        let mut sig_with_sighash = Vec::with_capacity(sig.len() + 1);
        sig_with_sighash.extend_from_slice(&sig);
        sig_with_sighash.push(SIGHASH_BIT);
        let mut unlock = Vec::with_capacity(100);
        push_data(&mut unlock, &sig_with_sighash);
        push_data(&mut unlock, &master.public_key);
        tx.inputs[i].unlock_script = unlock;
    }

    let raw = encode_tx(&tx);
    let hex_str = hex::encode(&raw);
    println!("\nfund tx hex ({} bytes):", raw.len());
    println!("{hex_str}");

    if broadcast {
        let txid = electrum.broadcast_raw(&raw)?;
        println!("\nbroadcast ok: {txid}");
    } else {
        println!("\n(dry-run — pass --broadcast to send)");
    }

    Ok(())
}
