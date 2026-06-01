//! `ticker-ops send` — sweep or top-up from a labeled wallet to a P2PKH address.
//!
//! Spends every non-token UTXO of the labeled wallet, emits one output of
//! `amount` to `--to` and a change output back to source if ≥ 546 sats.

use std::time::Duration;

use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::seed::{derive_wallet, load_seed};
use ticker_core::tx::cashaddr::{decode_p2pkh_cashaddr, encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::encode::Output;
use ticker_core::tx::script::p2pkh_locking_script;

use crate::p2pkh::{build_signed_p2pkh_tx, Signer};

const ELECTRUM_TIMEOUT_SEC: u64 = 30;
/// Fee buffer for `send`. Sized to cover ~2 KB at ≥ 1 sat/byte min-relay-fee
/// (10-input sweeps produce ~1.5-2 KB txs; previous 1_500 sat buffer was just
/// below threshold for 1.5 KB txs, tripping BCHN's mempool with "min relay
/// fee not met (code 66)").
const TX_FEE_BUFFER: u64 = 2_500;

pub fn send(
    seed_path: &str,
    label: &str,
    to_address: &str,
    amount_sats: u64,
    electrum_host: &str,
    electrum_port: u16,
    network: &str,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = load_seed(seed_path)?;
    let wallet = derive_wallet(&seed, label)?;
    let prefix = match network {
        "mainnet" => AddressPrefix::Mainnet,
        _ => AddressPrefix::Chipnet,
    };
    let from_addr = encode_p2pkh_cashaddr(&wallet.pkh, prefix);
    println!("source wallet ({label}): {from_addr}");
    println!("destination:             {to_address}");
    println!("amount:                  {amount_sats} sats");

    let mut electrum = ElectrumClient::connect(
        electrum_host,
        electrum_port,
        Duration::from_secs(ELECTRUM_TIMEOUT_SEC),
    )?;
    let utxos = electrum.list_unspent(&from_addr)?;
    let mut non_token: Vec<_> = utxos.into_iter().filter(|u| u.token_data.is_none()).collect();
    let total: u64 = non_token.iter().map(|u| u.value).sum();
    println!("source balance:          {total} sats ({} utxos)", non_token.len());

    // Select minimal UTXO set that covers amount + fee buffer. Sweeping ALL
    // UTXOs blocks the genesis-prep pattern of "create N distinct vout=0
    // UTXOs by bouncing master→master N times" because each sweep destroys
    // all prior bounces. Prefer largest-first so we use few inputs.
    non_token.sort_by(|a, b| b.value.cmp(&a.value));
    let need = amount_sats + TX_FEE_BUFFER;
    let mut acc = 0u64;
    let mut selected: Vec<_> = Vec::new();
    for u in non_token {
        if acc >= need { break; }
        acc += u.value;
        selected.push(u);
    }
    if acc < need {
        return Err(format!(
            "insufficient master balance: have {acc} across selected, need {need}"
        )
        .into());
    }
    println!("selected {} utxo(s), total {acc} sats", selected.len());

    let to_pkh = decode_p2pkh_cashaddr(to_address, prefix)?;
    let outputs = vec![Output {
        value: amount_sats,
        locking_script: p2pkh_locking_script(&to_pkh).to_vec(),
        token: None,
    }];

    let signer = Signer {
        private_key: wallet.private_key,
        public_key: wallet.public_key,
        pkh: wallet.pkh,
    };
    let raw = build_signed_p2pkh_tx(&signer, &selected, outputs, TX_FEE_BUFFER, prefix)?;
    println!("\ntx hex ({} bytes):\n{}", raw.len(), hex::encode(&raw));

    if broadcast {
        let txid = electrum.broadcast_raw(&raw)?;
        println!("\nbroadcast ok: {txid}");
    } else {
        println!("\n(dry-run — pass --broadcast to send)");
    }
    Ok(())
}
