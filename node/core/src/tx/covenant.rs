//! Compiled covenant bytes and the derivations around them.
//!
//! The hex files are emitted by `cashc --hex` from `contracts/*.cash` (cashc 0.14.0) and are the
//! exact bytes the VM test suite exercised. cashc pushes constructor arguments ahead of the body,
//! so for `contract Oracle(bytes tickerLock)`:
//!
//! ```text
//!   redeem      = push(tickerLock) ‖ ORACLE_BODY                  (580 B, the same for every deployment)
//!   oracle_lock = OP_HASH256 <sha256d(redeem)> OP_EQUAL           (P2SH-32, 35 B)
//!   ticker_lock = TICKER_BODY                                     (P2S, 55 B)
//! ```
//!
//! Function arguments are pushed in reverse declaration order, then the function index, then the
//! redeem script. The notary table is not part of the script: its hash160 lives in the head's
//! commitment and the table itself is an argument of every spend.
//!
//! The v26 scripts stay embedded for two jobs: spending a v26 head into the v27 lock (migration)
//! and recycling the v26 Tickers that are still alive afterwards.

use crate::crypto::hash160;
use crate::tx::script::{p2sh32_locking_script, push_data};
use crate::TABLE_ENTRY_LEN;

const ORACLE_BODY_HEX: &str = include_str!("../../../../contracts/artifacts/Oracle.body.hex");
const TICKER_BODY_HEX: &str = include_str!("../../../../contracts/artifacts/Ticker.body.hex");
const ORACLE26_BODY_HEX: &str = include_str!("../../../../contracts/artifacts/v26/Oracle.body.hex");
const TICKER26_BODY_HEX: &str = include_str!("../../../../contracts/artifacts/v26/Ticker.body.hex");

fn body(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text.trim()).expect("compiled covenant body is valid hex")
}

pub fn oracle_body() -> Vec<u8> {
    body(ORACLE_BODY_HEX)
}

pub fn ticker_lock() -> Vec<u8> {
    body(TICKER_BODY_HEX)
}

fn redeem_for(ticker: &[u8], oracle_body_bytes: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(640);
    push_data(&mut r, ticker);
    r.extend_from_slice(oracle_body_bytes);
    r
}

pub fn oracle_redeem() -> Vec<u8> {
    redeem_for(&ticker_lock(), &oracle_body())
}

/// The head's locking bytecode. Every v27 deployment shares it; deployments differ by category.
pub fn oracle_lock() -> [u8; 35] {
    p2sh32_locking_script(&oracle_redeem())
}

/// The previous generation's scripts.
pub mod legacy {
    use super::*;
    pub fn ticker26_lock() -> Vec<u8> {
        body(TICKER26_BODY_HEX)
    }
    pub fn oracle26_redeem() -> Vec<u8> {
        redeem_for(&ticker26_lock(), &body(ORACLE26_BODY_HEX))
    }
    pub fn oracle26_lock() -> [u8; 35] {
        p2sh32_locking_script(&oracle26_redeem())
    }
}

/// hash160 of a notary table, as the head commitment stores it.
pub fn table_hash(table: &[u8]) -> [u8; 20] {
    hash160(table)
}

pub fn table_rows(table: &[u8]) -> usize {
    table.len() / TABLE_ENTRY_LEN
}

/// `(pubkey, source)` of table row `row`, if the table has it.
pub fn table_entry(table: &[u8], row: u8) -> Option<([u8; 33], u8)> {
    let start = row as usize * TABLE_ENTRY_LEN;
    let entry = table.get(start..start + TABLE_ENTRY_LEN)?;
    Some((entry[..33].try_into().unwrap(), entry[33]))
}

/// Electrum scripthash of a locking bytecode: sha256, reversed, hex.
pub fn electrum_scripthash(lock: &[u8]) -> String {
    let mut h = crate::crypto::sha256(lock);
    h.reverse();
    hex::encode(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../contracts/test/v27-vectors.json")).unwrap()
    }

    #[test]
    fn body_sizes_match_cashc() {
        assert_eq!(oracle_body().len(), 518);
        assert_eq!(ticker_lock().len(), 55);
        assert_eq!(oracle_redeem().len(), 574);
        assert_eq!(legacy::ticker26_lock().len(), 57);
        assert_eq!(legacy::oracle26_redeem().len(), 564);
    }

    /// The cashscript SDK (`contracts/test/v27.suite.mjs --vectors`) produced these exact bytes.
    #[test]
    fn redeem_lock_and_table_hash_match_sdk_vectors() {
        let v = vectors();
        assert_eq!(hex::encode(oracle_redeem()), v["oracle_redeem"].as_str().unwrap());
        assert_eq!(hex::encode(oracle_lock()), v["oracle_lock"].as_str().unwrap());
        assert_eq!(hex::encode(ticker_lock()), v["ticker_lock"].as_str().unwrap());
        assert_eq!(hex::encode(legacy::oracle26_redeem()), v["oracle26_redeem"].as_str().unwrap());
        assert_eq!(hex::encode(legacy::oracle26_lock()), v["oracle26_lock"].as_str().unwrap());
        assert_eq!(hex::encode(legacy::ticker26_lock()), v["ticker26_lock"].as_str().unwrap());
        let table = hex::decode(v["table"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(table_hash(&table)), v["table_hash"].as_str().unwrap());
        assert_eq!(table_rows(&table), 13);
        let (_, source) = table_entry(&table, 3).unwrap();
        assert_eq!(source, 16);
        assert!(table_entry(&table, 13).is_none());
    }
}
