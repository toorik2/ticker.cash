//! Oracle NFT commit (18 B in v20, no version byte).
//!
//! v19 → v20: dropped the `0x65` version byte. Oracle self-replicates via
//! static concat that's provably 18 B by construction; identity is enforced
//! by category + length-by-format. All field offsets shift -1.
//!
//! Layout:
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0..4   | 4    | seq          | u32 LE    |
//! | 4..8   | 4    | last_ts      | u32 LE    |
//! | 8..16  | 8    | median_usd   | u64 LE    |
//! | 16..18 | 2    | active_count | u16 LE    |
//!
//! Rewritten in full each cycle by `Oracle.update`. The covenant enforces
//! `seq = prev_seq + 1` and `last_ts - prev_last_ts >= 60`.

use super::consts::ORACLE_COMMIT_LEN;

/// Decoded view of an Oracle commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleState {
    pub seq: u32,
    pub last_ts: u32,
    pub median_usd: u64,
    pub active_count: u16,
}

/// Encode an Oracle commit to its 18-byte wire form.
pub fn encode_oracle_commit(s: &OracleState) -> [u8; ORACLE_COMMIT_LEN] {
    let mut out = [0u8; ORACLE_COMMIT_LEN];
    out[0..4].copy_from_slice(&s.seq.to_le_bytes());
    out[4..8].copy_from_slice(&s.last_ts.to_le_bytes());
    out[8..16].copy_from_slice(&s.median_usd.to_le_bytes());
    out[16..18].copy_from_slice(&s.active_count.to_le_bytes());
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
        seq: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        last_ts: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        median_usd: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        active_count: u16::from_le_bytes(bytes[16..18].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> OracleState {
        OracleState {
            seq: 2153,
            last_ts: 1_780_000_000,
            median_usd: 350_000_000, // $3.50 × 1e8
            active_count: 10,
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
            active_count: 7,
        };
        let expected: [u8; 18] = [
            0x01, 0x00, 0x00, 0x00, // seq=1 LE
            0x00, 0x00, 0x00, 0x65, // last_ts=0x65000000 LE
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // median_usd LE
            0x07, 0x00, // active_count=7 LE
        ];
        assert_eq!(encode_oracle_commit(&s), expected);
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
