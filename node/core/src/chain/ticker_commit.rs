//! Ticker NFT commit (19 B in v24, version `0x80`).
//!
//! v22 → v24 (P01): widened `seq` and `last_ts` from u32 to u40 LE, mirroring
//! the Oracle commit widening. The Ticker covenant body is unchanged — it just
//! preserves whatever bytes the Oracle mints.
//!
//! | Offset | Size | Field      | Type    |
//! |--------|------|------------|---------|
//! | 0      | 1    | version    | `0x80`  |
//! | 1..6   | 5    | seq        | u40 LE  |
//! | 6..11  | 5    | last_ts    | u40 LE  |
//! | 11..19 | 8    | median_usd | u64 LE  |
//!
//! Minted in pairs (`TICKER_HEAD_COUNT = 2`) by every `Oracle.update`.
//! `Ticker.consume` re-emits the commitment verbatim — consumers cannot
//! mutate it.

use super::consts::{TICKER_COMMIT_LEN, TICKER_VERSION_BYTE};
use super::oracle_commit::OracleState;
use super::u40_to_le;

/// Encode a Ticker commit. Reads only `seq`, `last_ts`, `median_usd` from `OracleState`.
pub fn encode_ticker_commit(s: &OracleState) -> [u8; TICKER_COMMIT_LEN] {
    let mut out = [0u8; TICKER_COMMIT_LEN];
    out[0] = TICKER_VERSION_BYTE;
    out[1..6].copy_from_slice(&u40_to_le(s.seq));
    out[6..11].copy_from_slice(&u40_to_le(s.last_ts));
    out[11..19].copy_from_slice(&s.median_usd.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        let s = OracleState {
            seq: 1,
            last_ts: 0x6500_0000,
            median_usd: 0x1234_5678_9abc_def0,
        };
        let expected: [u8; 19] = [
            0x80, // version
            0x01, 0x00, 0x00, 0x00, 0x00, // seq=1 LE u40
            0x00, 0x00, 0x00, 0x65, 0x00, // last_ts LE u40
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // median_usd LE
        ];
        assert_eq!(encode_ticker_commit(&s), expected);
    }
}
