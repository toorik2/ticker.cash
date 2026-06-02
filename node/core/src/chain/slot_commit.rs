//! PublisherSlot NFT commit (36 B in v19, no version byte).
//!
//! v18 → v19: dropped the `0x75` version byte. Slot identity is enforced by
//! length + token-category gates in PublisherSlot.cash; the byte was
//! redundant. All field offsets shift -1.
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0..20  | 20   | pkh          | bytes20   |
//! | 20..28 | 8    | price        | u64 LE    |
//! | 28..32 | 4    | timestamp    | u32 LE    |
//! | 32..36 | 4    | cycle_seq    | u32 LE    |
//!
//! `pkh` is **pinned at genesis** and never rewritten; only
//! `(price, timestamp, cycle_seq)` mutate via `PublisherSlot.attest`.

use super::consts::SLOT_COMMIT_LEN;

/// Decoded view of a PublisherSlot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotCommit {
    pub pkh: [u8; 20],
    pub price: u64,
    pub timestamp: u32,
    pub cycle_seq: u32,
}

/// Encode a slot commit to its 36-byte wire form.
pub fn encode_slot_commit(c: &SlotCommit) -> [u8; SLOT_COMMIT_LEN] {
    let mut out = [0u8; SLOT_COMMIT_LEN];
    out[0..20].copy_from_slice(&c.pkh);
    out[20..28].copy_from_slice(&c.price.to_le_bytes());
    out[28..32].copy_from_slice(&c.timestamp.to_le_bytes());
    out[32..36].copy_from_slice(&c.cycle_seq.to_le_bytes());
    out
}

/// Decode a 36-byte slot commit. Returns `None` for wrong length.
pub fn decode_slot_commit(bytes: &[u8]) -> Option<SlotCommit> {
    if bytes.len() != SLOT_COMMIT_LEN {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&bytes[0..20]);
    Some(SlotCommit {
        pkh,
        price: u64::from_le_bytes(bytes[20..28].try_into().ok()?),
        timestamp: u32::from_le_bytes(bytes[28..32].try_into().ok()?),
        cycle_seq: u32::from_le_bytes(bytes[32..36].try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SlotCommit {
        SlotCommit {
            pkh: [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
                0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
            ],
            price: 0x_0000_0000_0123_4567,
            timestamp: 1_700_000_000,
            cycle_seq: 42,
        }
    }

    #[test]
    fn encode_length() {
        let bytes = encode_slot_commit(&fixture());
        assert_eq!(bytes.len(), SLOT_COMMIT_LEN);
        assert_eq!(bytes.len(), 36);
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let c = fixture();
        let bytes = encode_slot_commit(&c);
        let decoded = decode_slot_commit(&bytes).expect("valid commit decodes");
        assert_eq!(c, decoded);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let bytes = encode_slot_commit(&fixture());
        assert_eq!(decode_slot_commit(&bytes[..35]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_slot_commit(&longer), None);
    }

    #[test]
    fn known_vector_byte_for_byte() {
        // Hand-computed expected bytes for the fixture (no version byte):
        //   pkh        = 11..44                    → 20 bytes
        //   price      = 0x01234567               → 67 45 23 01 00 00 00 00
        //   timestamp  = 1_700_000_000 = 0x6553F100 → 00 F1 53 65
        //   cycle_seq  = 42 = 0x2A                 → 2A 00 00 00
        let expected: [u8; 36] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xf1, 0x53, 0x65, 0x2a, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encode_slot_commit(&fixture()), expected);
    }
}
