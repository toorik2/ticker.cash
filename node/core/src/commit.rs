//! Commitments. The head NFT carries 33 bytes; every Ticker carries the first 13 of them.
//!
//! ```text
//!   snapshot (13 B)  seq u32 LE ‖ price u64 LE ‖ k u8
//!   head     (33 B)  snapshot ‖ tableHash (hash160 of the notary table)
//! ```
//!
//! `seq` is the Unix minute (floor(unix_time / 60)) the notaries observed in; `price` is USD per
//! BCH in 1e-8 units; `k` is how many table rows signed. A u32 minute runs to the year 6053 before
//! the script sign bit; a u64 price covers $184 billion per BCH; `k` is at most 127.

pub const SNAPSHOT_LEN: usize = 13;
pub const HEAD_COMMIT_LEN: usize = 33;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub seq: u32,
    pub price: u64,
    pub k: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadCommit {
    pub snapshot: Snapshot,
    pub table_hash: [u8; 20],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommitError {
    #[error("commitment is {got} bytes, expected {want}")]
    Length { got: usize, want: usize },
    #[error("seq has the script sign bit set")]
    SeqSignBit,
    #[error("price has the script sign bit set")]
    PriceSignBit,
    #[error("k has the script sign bit set")]
    KSignBit,
}

impl Snapshot {
    pub fn encode(&self) -> [u8; SNAPSHOT_LEN] {
        let mut out = [0u8; SNAPSHOT_LEN];
        out[..4].copy_from_slice(&self.seq.to_le_bytes());
        out[4..12].copy_from_slice(&self.price.to_le_bytes());
        out[12] = self.k;
        out
    }

    /// Decode a snapshot read from chain. Rejects values the covenant's `int()` would read as
    /// negative, which no honest update can produce.
    pub fn decode(bytes: &[u8]) -> Result<Self, CommitError> {
        if bytes.len() != SNAPSHOT_LEN {
            return Err(CommitError::Length { got: bytes.len(), want: SNAPSHOT_LEN });
        }
        let seq = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let price = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let k = bytes[12];
        if seq & 0x8000_0000 != 0 {
            return Err(CommitError::SeqSignBit);
        }
        if price & 0x8000_0000_0000_0000 != 0 {
            return Err(CommitError::PriceSignBit);
        }
        if k & 0x80 != 0 {
            return Err(CommitError::KSignBit);
        }
        Ok(Snapshot { seq, price, k })
    }

    /// Unix time of the start of the observed minute.
    pub fn minute_start_unix(&self) -> u64 {
        self.seq as u64 * 60
    }

    /// Earliest median-time-past at which a Ticker with this snapshot may be recycled.
    pub fn recyclable_at(&self) -> u64 {
        self.minute_start_unix() + crate::TICKER_LIFE_SECS
    }
}

impl HeadCommit {
    pub fn encode(&self) -> [u8; HEAD_COMMIT_LEN] {
        let mut out = [0u8; HEAD_COMMIT_LEN];
        out[..SNAPSHOT_LEN].copy_from_slice(&self.snapshot.encode());
        out[SNAPSHOT_LEN..].copy_from_slice(&self.table_hash);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CommitError> {
        if bytes.len() != HEAD_COMMIT_LEN {
            return Err(CommitError::Length { got: bytes.len(), want: HEAD_COMMIT_LEN });
        }
        let snapshot = Snapshot::decode(&bytes[..SNAPSHOT_LEN])?;
        let table_hash: [u8; 20] = bytes[SNAPSHOT_LEN..].try_into().unwrap();
        Ok(HeadCommit { snapshot, table_hash })
    }
}

/// The current Unix minute.
pub fn current_minute() -> u32 {
    (now_unix() / 60) as u32
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_matches_vm_suite_layout() {
        let s = Snapshot { seq: 29_870_001, price: 29_000_000_000, k: 13 };
        let b = s.encode();
        assert_eq!(&b[..4], &29_870_001u32.to_le_bytes());
        assert_eq!(&b[4..12], &29_000_000_000u64.to_le_bytes());
        assert_eq!(b[12], 13);
        assert_eq!(Snapshot::decode(&b).unwrap(), s);
        let h = HeadCommit { snapshot: s, table_hash: [7u8; 20] };
        let hb = h.encode();
        assert_eq!(hb.len(), 33);
        assert_eq!(&hb[..13], &b);
        assert_eq!(&hb[13..], &[7u8; 20]);
        assert_eq!(HeadCommit::decode(&hb).unwrap(), h);
    }

    #[test]
    fn rejects_wrong_length_and_sign_bits() {
        assert_eq!(Snapshot::decode(&[0u8; 12]).unwrap_err(), CommitError::Length { got: 12, want: 13 });
        assert_eq!(HeadCommit::decode(&[0u8; 12]).unwrap_err(), CommitError::Length { got: 12, want: 33 });
        let mut b = Snapshot { seq: 1, price: 1, k: 1 }.encode();
        b[3] |= 0x80;
        assert_eq!(Snapshot::decode(&b).unwrap_err(), CommitError::SeqSignBit);
        let mut b = Snapshot { seq: 1, price: 1, k: 1 }.encode();
        b[11] |= 0x80;
        assert_eq!(Snapshot::decode(&b).unwrap_err(), CommitError::PriceSignBit);
        let mut b = Snapshot { seq: 1, price: 1, k: 1 }.encode();
        b[12] = 0x80;
        assert_eq!(Snapshot::decode(&b).unwrap_err(), CommitError::KSignBit);
    }

    #[test]
    fn current_minute_is_plausible() {
        let m = current_minute();
        assert!(m > 29_000_000 && m < 40_000_000, "minute {m}");
    }
}
