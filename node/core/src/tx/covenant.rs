//! Compiled covenant bytes and the derivations around them.
//!
//! The hex files are emitted by `cashc --hex` from `contracts/*.cash` (cashc 0.14.0) and are
//! the exact bytes the VM test suite exercised. cashc pushes constructor arguments in reverse
//! declaration order ahead of the body, so for `contract Oracle(bytes table, bytes tickerLock)`:
//!
//! ```text
//!   redeem      = push(tickerLock) ‖ push(table) ‖ ORACLE_BODY
//!   oracle_lock = OP_HASH256 <sha256d(redeem)> OP_EQUAL         (P2SH-32, 35 B)
//!   ticker_lock = TICKER_BODY                                   (P2S, 31 B)
//! ```
//!
//! and function arguments are likewise pushed in reverse order, followed by the redeem script.

use crate::tx::script::{p2sh32_locking_script, push_data};

const ORACLE_BODY_HEX: &str = include_str!("../../../../contracts/artifacts/Oracle.body.hex");
const TICKER_BODY_HEX: &str = include_str!("../../../../contracts/artifacts/Ticker.body.hex");

/// Bytes per notary table entry: compressed pubkey (33) ‖ source id (1).
pub const TABLE_ENTRY_LEN: usize = 34;
pub const TABLE_LEN: usize = TABLE_ENTRY_LEN * crate::ROWS;

pub fn oracle_body() -> Vec<u8> {
    hex::decode(ORACLE_BODY_HEX.trim()).expect("compiled Oracle body is valid hex")
}

pub fn ticker_lock() -> Vec<u8> {
    hex::decode(TICKER_BODY_HEX.trim()).expect("compiled Ticker body is valid hex")
}

pub fn oracle_redeem_for_table(table: &[u8]) -> Vec<u8> {
    assert_eq!(table.len(), TABLE_LEN, "table must be {TABLE_LEN} bytes");
    let mut r = Vec::with_capacity(900);
    push_data(&mut r, &ticker_lock());
    push_data(&mut r, table);
    r.extend_from_slice(&oracle_body());
    r
}

pub fn oracle_lock_for_table(table: &[u8]) -> [u8; 35] {
    p2sh32_locking_script(&oracle_redeem_for_table(table))
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

    #[test]
    fn body_sizes_match_cashc() {
        assert_eq!(oracle_body().len(), 373);
        assert_eq!(ticker_lock().len(), 31);
    }

    /// Cross-check against the cashscript SDK (`contracts/test`): a table of 442 × 0x11
    /// yields an 850-byte redeem that starts with the Ticker lock push, and this exact
    /// P2SH-32 locking bytecode.
    #[test]
    fn redeem_and_lock_match_sdk_vectors() {
        let table = vec![0x11u8; TABLE_LEN];
        let redeem = oracle_redeem_for_table(&table);
        assert_eq!(redeem.len(), 850);
        assert_eq!(redeem[0], 0x1f);
        assert_eq!(&redeem[1..32], &ticker_lock()[..]);
        assert_eq!(&redeem[32..35], &[0x4d, 0xba, 0x01]);
        let lock = oracle_lock_for_table(&table);
        assert_eq!(hex::encode(lock), SDK_ORACLE_LOCK_FOR_0X11_TABLE);
        assert_eq!(hex::encode(ticker_lock()), SDK_TICKER_LOCK);
    }

    const SDK_ORACLE_LOCK_FOR_0X11_TABLE: &str = include_str!("../../../../contracts/test/oracle-lock-0x11.hex");
    const SDK_TICKER_LOCK: &str = "76009c63c076cd78c78876d178ce8876cc7cc69c7767519d029000b2755168";
}
