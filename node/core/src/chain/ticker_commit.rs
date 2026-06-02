//! Ticker NFT commit (17 B, version `0x80`).
//!
//! Layout:
//!
//! | Offset | Size | Field      | Type    |
//! |--------|------|------------|---------|
//! | 0      | 1    | version    | `0x80`  |
//! | 1..5   | 4    | seq        | u32 LE  |
//! | 5..9   | 4    | last_ts    | u32 LE  |
//! | 9..17  | 8    | median_usd | u64 LE  |
//!
//! Minted in pairs (`TICKER_HEAD_COUNT = 2`) by every `Oracle.update`.
//! `Ticker.consume` re-emits the commitment verbatim — consumers cannot
//! mutate it.

use super::consts::{TICKER_COMMIT_LEN, TICKER_VERSION_BYTE};
use super::oracle_commit::OracleState;

/// Encode a Ticker commit. Reads only `seq`, `last_ts`, `median_usd` from `OracleState`.
pub fn encode_ticker_commit(s: &OracleState) -> [u8; TICKER_COMMIT_LEN] {
    let mut out = [0u8; TICKER_COMMIT_LEN];
    out[0] = TICKER_VERSION_BYTE;
    out[1..5].copy_from_slice(&s.seq.to_le_bytes());
    out[5..9].copy_from_slice(&s.last_ts.to_le_bytes());
    out[9..17].copy_from_slice(&s.median_usd.to_le_bytes());
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
        let expected: [u8; 17] = [
            0x80, // version
            0x01, 0x00, 0x00, 0x00, // seq=1 LE
            0x00, 0x00, 0x00, 0x65, // last_ts LE
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // median_usd LE
        ];
        assert_eq!(encode_ticker_commit(&s), expected);
    }
}
