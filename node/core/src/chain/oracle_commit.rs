//! Oracle NFT commit (16 B in v22, no version byte, no activeCount).
//!
//! v20 → v22 (T2): dropped the `activeCount` field. It was dead state since
//! v15 — `oldActive*5/10 ≤ 6 < 7` so `thr = max(…, 7) = 7` unconditionally.
//!
//! Layout:
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0..4   | 4    | seq          | u32 LE    |
//! | 4..8   | 4    | last_ts      | u32 LE    |
//! | 8..16  | 8    | median_usd   | u64 LE    |
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
}

/// Encode an Oracle commit to its 16-byte wire form.
pub fn encode_oracle_commit(s: &OracleState) -> [u8; ORACLE_COMMIT_LEN] {
    let mut out = [0u8; ORACLE_COMMIT_LEN];
    out[0..4].copy_from_slice(&s.seq.to_le_bytes());
    out[4..8].copy_from_slice(&s.last_ts.to_le_bytes());
    out[8..16].copy_from_slice(&s.median_usd.to_le_bytes());
    out
}

/// Decode error for an Oracle commit.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OracleCommitError {
    #[error("Oracle commit must be {ORACLE_COMMIT_LEN} B, got {0}")]
    WrongLength(usize),
}

/// Decode a 16-byte Oracle commit.
pub fn decode_oracle_commit(bytes: &[u8]) -> Result<OracleState, OracleCommitError> {
    if bytes.len() != ORACLE_COMMIT_LEN {
        return Err(OracleCommitError::WrongLength(bytes.len()));
    }
    Ok(OracleState {
        seq: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        last_ts: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        median_usd: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
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
        let expected: [u8; 16] = [
            0x01, 0x00, 0x00, 0x00, // seq=1 LE
            0x00, 0x00, 0x00, 0x65, // last_ts=0x65000000 LE
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // median_usd LE
        ];
        assert_eq!(encode_oracle_commit(&s), expected);
    }

    #[test]
    fn rejects_wrong_length() {
        let bytes = encode_oracle_commit(&fixture());
        assert!(matches!(
            decode_oracle_commit(&bytes[..15]),
            Err(OracleCommitError::WrongLength(15))
        ));
    }
}
