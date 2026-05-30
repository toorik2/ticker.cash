//! `ticker-ops send` — sweep or top-up from a labeled wallet to an address.
//!
//! The labeled-sha256 derivation matches the ticker.cash and CashLink convention
//! (`priv = sha256(seed || utf8(label))`). One-shot for moving sats between any
//! pair of derivation-compatible wallets: treasury → master, master → some
//! external address, etc. Always uses ALL non-token UTXOs of the source wallet
//! as inputs; sends `amount` to `--to` and change back to source.

use std::time::Duration;

use ticker_core::crypto::{double_sha256, sign_ecdsa};
use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::seed::{derive_wallet, load_seed};
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::encode::{encode_tx, Input, Output, Tx, TxOutpoint, DEFAULT_SEQUENCE};
use ticker_core::tx::script::{p2pkh_locking_script, push_data};
use ticker_core::tx::sighash::{p2pkh_sighash_preimage, SIGHASH_BIT};

const ELECTRUM_TIMEOUT_SEC: u64 = 30;
const TX_FEE_BUFFER: u64 = 1_500;

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
    let non_token: Vec<_> = utxos.into_iter().filter(|u| u.token_data.is_none()).collect();
    let total: u64 = non_token.iter().map(|u| u.value).sum();
    println!("source balance:          {total} sats ({} utxos)", non_token.len());
    if non_token.is_empty() {
        return Err("source wallet has no spendable UTXOs".into());
    }
    let need = amount_sats + TX_FEE_BUFFER;
    if total < need {
        return Err(format!("insufficient funds: have {total}, need {need}").into());
    }

    let to_pkh = parse_p2pkh_cashaddr(to_address, prefix)?;

    let mut outputs = Vec::with_capacity(2);
    outputs.push(Output {
        value: amount_sats,
        locking_script: p2pkh_locking_script(&to_pkh).to_vec(),
        token: None,
    });
    let change = total - amount_sats - TX_FEE_BUFFER;
    if change >= 546 {
        outputs.push(Output {
            value: change,
            locking_script: p2pkh_locking_script(&wallet.pkh).to_vec(),
            token: None,
        });
        println!("change:                  {change} sats back to source");
    } else {
        println!("change:                  {change} (below dust — folded into fee)");
    }

    let mut inputs = Vec::with_capacity(non_token.len());
    for u in &non_token {
        let mut txid_be = [0u8; 32];
        txid_be.copy_from_slice(&hex::decode(&u.tx_hash)?);
        inputs.push(Input {
            prev: TxOutpoint { txid_be, vout: u.tx_pos },
            unlock_script: Vec::new(),
            sequence: DEFAULT_SEQUENCE,
        });
    }
    let mut tx = Tx::new(inputs, outputs);

    let locking = p2pkh_locking_script(&wallet.pkh).to_vec();
    for (i, u) in non_token.iter().enumerate() {
        let preimage = p2pkh_sighash_preimage(&tx, i, &locking, u.value);
        let digest = double_sha256(&preimage);
        let sig = sign_ecdsa(&wallet.private_key, &digest)?;
        let mut sig_with_sighash = Vec::with_capacity(sig.len() + 1);
        sig_with_sighash.extend_from_slice(&sig);
        sig_with_sighash.push(SIGHASH_BIT);
        let mut unlock = Vec::with_capacity(100);
        push_data(&mut unlock, &sig_with_sighash);
        push_data(&mut unlock, &wallet.public_key);
        tx.inputs[i].unlock_script = unlock;
    }

    let raw = encode_tx(&tx);
    println!("\ntx hex ({} bytes):\n{}", raw.len(), hex::encode(&raw));

    if broadcast {
        let txid = electrum.broadcast_raw(&raw)?;
        println!("\nbroadcast ok: {txid}");
    } else {
        println!("\n(dry-run — pass --broadcast to send)");
    }
    Ok(())
}

/// Decode a P2PKH CashAddr (chipnet or mainnet). Hand-rolled minimal decoder —
/// extracts the 20-byte payload, ignores everything else.
fn parse_p2pkh_cashaddr(addr: &str, expected: AddressPrefix) -> Result<[u8; 20], String> {
    let (prefix, body) = addr.split_once(':').ok_or_else(|| format!("missing prefix in {addr}"))?;
    if prefix != expected.as_str() {
        return Err(format!("wrong prefix {prefix} (expected {})", expected.as_str()));
    }
    let alphabet = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut data5 = Vec::with_capacity(body.len());
    for c in body.chars() {
        let pos = alphabet.iter().position(|&b| b == c as u8)
            .ok_or_else(|| format!("invalid char {c:?} in address"))?;
        data5.push(pos as u8);
    }
    // Strip the 8-char (40-bit) checksum suffix.
    if data5.len() < 8 {
        return Err("address too short".to_string());
    }
    data5.truncate(data5.len() - 8);
    let payload8 = convert_bits(&data5, 5, 8, false);
    if payload8.len() < 21 {
        return Err(format!("payload too short ({} bytes)", payload8.len()));
    }
    let version = payload8[0];
    // P2PKH: type 0, hash-size 0 (20 bytes) → version byte 0x00.
    if version != 0x00 {
        return Err(format!("not a P2PKH address (version byte 0x{version:02x})"));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&payload8[1..21]);
    Ok(out)
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * from_bits as usize / to_bits as usize + 1);
    let max = (1u32 << to_bits) - 1;
    for &v in data {
        acc = (acc << from_bits) | v as u32;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad && bits > 0 {
        out.push(((acc << (to_bits - bits)) & max) as u8);
    }
    out
}

// `AddressPrefix::as_str` is `pub(crate)` in ticker-core; mirror it locally.
trait AddrPrefixExt {
    fn as_str(&self) -> &'static str;
}
impl AddrPrefixExt for AddressPrefix {
    fn as_str(&self) -> &'static str {
        match self {
            AddressPrefix::Mainnet => "bitcoincash",
            AddressPrefix::Chipnet => "bchtest",
        }
    }
}
