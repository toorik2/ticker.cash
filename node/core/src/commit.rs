//! Commitments. The head NFT carries 37 bytes; every Ticker carries the first 17 of them.
//!
//! ```text
//!   snapshot (17 B)  timestamp u32 LE ‖ messageSequence u32 LE ‖ dataSequence u32 LE ‖ price u32 LE ‖ k u8
//!   head     (37 B)  snapshot ‖ tableHash (hash160 of the notary table)
//! ```
//!
//! The first 16 bytes are a General Protocols price-oracle message: the timestamp is the start of
//! the Unix minute the rows observed in, both sequences are the oracle's update counter (the
//! covenant advances it by exactly one per update), the price is US cents per BCH. `k` is how many
//! rows signed. Any reader of that format reads a Ticker as a price message; the signature is
//! consensus.
//!
//! The v26 layout (`seq u32 ‖ price u64 ‖ k ‖ tableHash`) is kept as `legacy` for one purpose each:
//! migrating a v26 head and recycling v26 Tickers.

pub const SNAPSHOT_LEN: usize = 17;
pub const HEAD_COMMIT_LEN: usize = 37;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Start of the observed Unix minute, seconds.
    pub ts: u32,
    /// The update counter (dataSequence; messageSequence is written equal to it).
    pub seq: u32,
    /// US cents per BCH.
    pub price: u32,
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
}

impl Snapshot {
    pub fn encode(&self) -> [u8; SNAPSHOT_LEN] {
        let mut out = [0u8; SNAPSHOT_LEN];
        out[..4].copy_from_slice(&self.ts.to_le_bytes());
        out[4..8].copy_from_slice(&self.seq.to_le_bytes());
        out[8..12].copy_from_slice(&self.seq.to_le_bytes());
        out[12..16].copy_from_slice(&self.price.to_le_bytes());
        out[16] = self.k;
        out
    }

    /// Decode a snapshot read from chain. The counter is taken from the dataSequence field
    /// (bytes 8..12), which is the one the covenant advances; a head fresh from migration carries
    /// v26 bytes in the other fields and is decoded all the same.
    pub fn decode(bytes: &[u8]) -> Result<Self, CommitError> {
        if bytes.len() != SNAPSHOT_LEN {
            return Err(CommitError::Length { got: bytes.len(), want: SNAPSHOT_LEN });
        }
        Ok(Snapshot {
            ts: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            seq: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            price: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            k: bytes[16],
        })
    }

    /// True when the two sequence fields agree, as every covenant-written snapshot has them.
    pub fn is_canonical(bytes: &[u8]) -> bool {
        bytes.len() == SNAPSHOT_LEN && bytes[4..8] == bytes[8..12]
    }

    /// Earliest median-time-past at which a Ticker with this snapshot may be recycled.
    pub fn recyclable_at(&self) -> u64 {
        self.ts as u64 + crate::TICKER_LIFE_SECS
    }

    /// The price as a decimal string, e.g. `272.52`.
    pub fn price_usd(&self) -> String {
        format!("{}.{:02}", self.price / 100, self.price % 100)
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
        Ok(HeadCommit { snapshot: Snapshot::decode(&bytes[..SNAPSHOT_LEN])?, table_hash: bytes[SNAPSHOT_LEN..].try_into().unwrap() })
    }
}

/// The v26 layouts, decoded only to migrate a head or recycle a Ticker.
pub mod legacy {
    use super::CommitError;

    pub const SNAPSHOT_LEN: usize = 13;
    pub const HEAD_COMMIT_LEN: usize = 33;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Snapshot26 {
        pub seq: u32,
        pub price: u64,
        pub k: u8,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HeadCommit26 {
        pub snapshot: Snapshot26,
        pub table_hash: [u8; 20],
    }

    impl Snapshot26 {
        pub fn encode(&self) -> [u8; SNAPSHOT_LEN] {
            let mut out = [0u8; SNAPSHOT_LEN];
            out[..4].copy_from_slice(&self.seq.to_le_bytes());
            out[4..12].copy_from_slice(&self.price.to_le_bytes());
            out[12] = self.k;
            out
        }
        pub fn decode(bytes: &[u8]) -> Result<Self, CommitError> {
            if bytes.len() != SNAPSHOT_LEN {
                return Err(CommitError::Length { got: bytes.len(), want: SNAPSHOT_LEN });
            }
            Ok(Snapshot26 { seq: u32::from_le_bytes(bytes[..4].try_into().unwrap()), price: u64::from_le_bytes(bytes[4..12].try_into().unwrap()), k: bytes[12] })
        }
        pub fn recyclable_at(&self) -> u64 {
            self.seq as u64 * 60 + crate::LEGACY_TICKER_LIFE_SECS
        }
    }

    impl HeadCommit26 {
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
            Ok(HeadCommit26 { snapshot: Snapshot26::decode(&bytes[..SNAPSHOT_LEN])?, table_hash: bytes[SNAPSHOT_LEN..].try_into().unwrap() })
        }
    }
}

/// The current Unix minute.
pub fn current_minute() -> u32 {
    (now_unix() / 60) as u32
}

/// Start of the current Unix minute, in seconds: what a notary signs as the timestamp.
pub fn current_minute_start() -> u32 {
    current_minute() * 60
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Exchange price in 1e-8 USD to US cents, rounded half up.
pub fn cents_from_1e8(price_1e8: u64) -> u32 {
    ((price_1e8 + 500_000) / 1_000_000) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_matches_vm_suite_layout() {
        let s = Snapshot { ts: 1_792_200_060, seq: 1001, price: 29_000, k: 13 };
        let b = s.encode();
        assert_eq!(&b[..4], &1_792_200_060u32.to_le_bytes());
        assert_eq!(&b[4..8], &1001u32.to_le_bytes());
        assert_eq!(&b[8..12], &1001u32.to_le_bytes());
        assert_eq!(&b[12..16], &29_000u32.to_le_bytes());
        assert_eq!(b[16], 13);
        assert_eq!(Snapshot::decode(&b).unwrap(), s);
        assert!(Snapshot::is_canonical(&b));
        let h = HeadCommit { snapshot: s, table_hash: [7u8; 20] };
        let hb = h.encode();
        assert_eq!(hb.len(), 37);
        assert_eq!(HeadCommit::decode(&hb).unwrap(), h);
        assert_eq!(s.price_usd(), "290.00");
        assert_eq!(s.recyclable_at(), 1_792_200_060 + 86_400);
    }

    /// A head straight out of the migration: v26 state (seq ‖ price8 ‖ k) ‖ 4 filler ‖ tableHash.
    #[test]
    fn migrated_head_decodes_with_the_counter_from_bytes_8_to_12() {
        let v26 = legacy::HeadCommit26 { snapshot: legacy::Snapshot26 { seq: 29_882_228, price: 27_257_000_000, k: 13 }, table_hash: [9u8; 20] };
        let mut migrated = Vec::new();
        migrated.extend_from_slice(&v26.snapshot.encode());
        migrated.extend_from_slice(&[0u8; 4]);
        migrated.extend_from_slice(&v26.table_hash);
        let h = HeadCommit::decode(&migrated).unwrap();
        assert_eq!(h.snapshot.ts, 29_882_228);
        assert_eq!(h.snapshot.seq, (27_257_000_000u64 >> 32) as u32);
        assert_eq!(h.snapshot.seq, 6);
        assert_eq!(h.table_hash, [9u8; 20]);
        assert!(!Snapshot::is_canonical(&migrated[..17]));
    }

    #[test]
    fn legacy_roundtrip_and_recycle_time() {
        let s = legacy::Snapshot26 { seq: 29_882_228, price: 27_257_000_000, k: 13 };
        assert_eq!(legacy::Snapshot26::decode(&s.encode()).unwrap(), s);
        assert_eq!(s.recyclable_at(), 29_882_228 * 60 + 3_600);
        assert_eq!(Snapshot::decode(&[0u8; 13]).unwrap_err(), CommitError::Length { got: 13, want: 17 });
    }

    #[test]
    fn cents_rounding() {
        assert_eq!(cents_from_1e8(27_257_000_000), 27_257);
        assert_eq!(cents_from_1e8(27_257_499_999), 27_257);
        assert_eq!(cents_from_1e8(27_257_500_000), 27_258);
        assert_eq!(cents_from_1e8(1), 0);
    }

    #[test]
    fn current_minute_is_plausible() {
        let m = current_minute();
        assert!(m > 29_000_000 && m < 40_000_000, "minute {m}");
        assert_eq!(current_minute_start() % 60, 0);
    }
}
