//! The 12-byte commitment carried by the head NFT and by every Ticker NFT.
//!
//! ```text
//!   seq   u32 LE   Unix minute (floor(unix_time / 60)) the notaries observed in
//!   price u64 LE   USD per BCH in 1e-8 units
//! ```
//!
//! `Oracle.cash` pins the head's output commitment to `seq ‖ median` and every Ticker's to the
//! same bytes, so one codec serves both. A u32 minute runs to the year 6053 before the script
//! sign bit; a u64 price covers $184 billion per BCH.

pub const COMMIT_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commit {
    pub seq: u32,
    pub price: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommitError {
    #[error("commitment is {0} bytes, expected 12")]
    Length(usize),
    #[error("seq has the script sign bit set")]
    SeqSignBit,
    #[error("price has the script sign bit set")]
    PriceSignBit,
}

impl Commit {
    pub fn encode(&self) -> [u8; COMMIT_LEN] {
        let mut out = [0u8; COMMIT_LEN];
        out[..4].copy_from_slice(&self.seq.to_le_bytes());
        out[4..].copy_from_slice(&self.price.to_le_bytes());
        out
    }

    /// Decode a commitment read from chain. Rejects values the covenant's `int()` would read as
    /// negative, which no honest update can produce.
    pub fn decode(bytes: &[u8]) -> Result<Self, CommitError> {
        if bytes.len() != COMMIT_LEN {
            return Err(CommitError::Length(bytes.len()));
        }
        let seq = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let price = u64::from_le_bytes(bytes[4..].try_into().unwrap());
        if seq & 0x8000_0000 != 0 {
            return Err(CommitError::SeqSignBit);
        }
        if price & 0x8000_0000_0000_0000 != 0 {
            return Err(CommitError::PriceSignBit);
        }
        Ok(Commit { seq, price })
    }

    /// Unix time of the start of the observed minute.
    pub fn minute_start_unix(&self) -> u64 {
        self.seq as u64 * 60
    }
}

/// The current Unix minute.
pub fn current_minute() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 60) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_matches_vm_suite_layout() {
        // the VM suite encodes seq u32 LE then price u64 LE
        let c = Commit { seq: 29_870_001, price: 29_000_000_000 };
        let b = c.encode();
        assert_eq!(&b[..4], &29_870_001u32.to_le_bytes());
        assert_eq!(&b[4..], &29_000_000_000u64.to_le_bytes());
        assert_eq!(Commit::decode(&b).unwrap(), c);
    }

    #[test]
    fn rejects_wrong_length_and_sign_bits() {
        assert_eq!(Commit::decode(&[0u8; 13]).unwrap_err(), CommitError::Length(13));
        let mut b = Commit { seq: 1, price: 1 }.encode();
        b[3] |= 0x80;
        assert_eq!(Commit::decode(&b).unwrap_err(), CommitError::SeqSignBit);
        let mut b = Commit { seq: 1, price: 1 }.encode();
        b[11] |= 0x80;
        assert_eq!(Commit::decode(&b).unwrap_err(), CommitError::PriceSignBit);
    }

    #[test]
    fn current_minute_is_plausible() {
        let m = current_minute();
        assert!(m > 29_000_000 && m < 40_000_000, "minute {m}");
    }
}
