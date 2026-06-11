//! Oracle NFT commit (18 B in v24, no version byte, no activeCount).
//!
//! v22 → v24 (P01): widened `seq` and `last_ts` from u32 to u40 LE to close
//! F-OC12 Y2038 PERMANENTLY. Layout:
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0..5   | 5    | seq          | u40 LE    |
//! | 5..10  | 5    | last_ts      | u40 LE    |
//! | 10..18 | 8    | median_usd   | u64 LE    |
//!
//! Rewritten in full each cycle by `Oracle.update`. The covenant enforces
//! `seq = prev_seq + 1`, `last_ts - prev_last_ts >= 60`, `last_ts > prev_last_ts`
//! (P01 F05 restore), and both fields < `U40_CAP` (P01 Strategy-A bound).

use super::consts::ORACLE_COMMIT_LEN;
use super::{u40_from_le, u40_to_le};

/// Decoded view of an Oracle commit. `seq` and `last_ts` are u40 in wire form;
/// kept as u64 here since Rust has no u40 (the high 24 bits are always zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleState {
    pub seq: u64,
    pub last_ts: u64,
    pub median_usd: u64,
}

/// Encode an Oracle commit to its 18-byte wire form.
pub fn encode_oracle_commit(s: &OracleState) -> [u8; ORACLE_COMMIT_LEN] {
    let mut out = [0u8; ORACLE_COMMIT_LEN];
    out[0..5].copy_from_slice(&u40_to_le(s.seq));
    out[5..10].copy_from_slice(&u40_to_le(s.last_ts));
    out[10..18].copy_from_slice(&s.median_usd.to_le_bytes());
    out
}

/// Decode error for an Oracle commit.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OracleCommitError {
    #[error("Oracle commit must be {ORACLE_COMMIT_LEN} B, got {0}")]
    WrongLength(usize),
}

/// Decode an 18-byte Oracle commit.
pub fn decode_oracle_commit(bytes: &[u8]) -> Result<OracleState, OracleCommitError> {
    if bytes.len() != ORACLE_COMMIT_LEN {
        return Err(OracleCommitError::WrongLength(bytes.len()));
    }
    Ok(OracleState {
        seq: u40_from_le(bytes[0..5].try_into().unwrap()),
        last_ts: u40_from_le(bytes[5..10].try_into().unwrap()),
        median_usd: u64::from_le_bytes(bytes[10..18].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> OracleState {
        OracleState {
            seq: 2153,
            last_ts: 1_780_000_000,
            median_usd: 350_000_000,
        }
    }

    #[test]
    fn roundtrip() {
        let s = fixture();
        assert_eq!(decode_oracle_commit(&encode_oracle_commit(&s)).unwrap(), s);
    }

    #[test]
    fn known_vector() {
        let s = OracleState {
            seq: 1,
            last_ts: 0x6500_0000,
            median_usd: 0x1234_5678_9abc_def0,
        };
        let expected: [u8; 18] = [
            0x01, 0x00, 0x00, 0x00, 0x00, // seq=1 LE u40
            0x00, 0x00, 0x00, 0x65, 0x00, // last_ts=0x65000000 LE u40
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // median_usd LE
        ];
        assert_eq!(encode_oracle_commit(&s), expected);
    }

    /// v24 P01 — F-OC12 Y2038 closure: a year-36812 timestamp roundtrips
    /// cleanly through u40 encode/decode.
    #[test]
    fn year_36812_timestamp_roundtrips() {
        let s = OracleState {
            seq: 1,
            last_ts: 0x6F_FFFF_FFFF, // ~36812 AD, below U40_CAP
            median_usd: 1,
        };
        let bytes = encode_oracle_commit(&s);
        let decoded = decode_oracle_commit(&bytes).unwrap();
        assert_eq!(decoded.last_ts, 0x6F_FFFF_FFFF);
    }

    #[test]
    fn rejects_wrong_length() {
        let bytes = encode_oracle_commit(&fixture());
        assert!(matches!(
            decode_oracle_commit(&bytes[..17]),
            Err(OracleCommitError::WrongLength(17))
        ));
    }
}
