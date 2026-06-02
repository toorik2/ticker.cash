//! PublisherSlot NFT commit (16 B in v22, no version byte, no pkh).
//!
//! v19 → v22: dropped the `publisherPkh` field. pkh now lives in the slot's
//! locking_bytecode as a script literal (specialized per source). All field
//! offsets shift.
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0..8   | 8    | price        | u64 LE    |
//! | 8..12  | 4    | timestamp    | u32 LE    |
//! | 12..16 | 4    | cycle_seq    | u32 LE    |
//!
//! Publisher identity is derived from the slot UTXO's address (= specialized
//! P2S LB), not from commit. Daemon look-up: address → source_id via manifest.

use super::consts::SLOT_COMMIT_LEN;

/// Decoded view of a PublisherSlot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotCommit {
    pub price: u64,
    pub timestamp: u32,
    pub cycle_seq: u32,
}

/// Encode a slot commit to its 16-byte wire form.
pub fn encode_slot_commit(c: &SlotCommit) -> [u8; SLOT_COMMIT_LEN] {
    let mut out = [0u8; SLOT_COMMIT_LEN];
    out[0..8].copy_from_slice(&c.price.to_le_bytes());
    out[8..12].copy_from_slice(&c.timestamp.to_le_bytes());
    out[12..16].copy_from_slice(&c.cycle_seq.to_le_bytes());
    out
}

/// Decode a 16-byte slot commit. Returns `None` for wrong length.
pub fn decode_slot_commit(bytes: &[u8]) -> Option<SlotCommit> {
    if bytes.len() != SLOT_COMMIT_LEN {
        return None;
    }
    Some(SlotCommit {
        price: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
        timestamp: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
        cycle_seq: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SlotCommit {
        SlotCommit {
            price: 0x_0000_0000_0123_4567,
            timestamp: 1_700_000_000,
            cycle_seq: 42,
        }
    }

    #[test]
    fn encode_length() {
        let bytes = encode_slot_commit(&fixture());
        assert_eq!(bytes.len(), SLOT_COMMIT_LEN);
        assert_eq!(bytes.len(), 16);
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
        assert_eq!(decode_slot_commit(&bytes[..15]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_slot_commit(&longer), None);
    }

    #[test]
    fn known_vector_byte_for_byte() {
        // Hand-computed expected bytes for fixture (no pkh, no version):
        //   price      = 0x01234567 → 67 45 23 01 00 00 00 00
        //   timestamp  = 1_700_000_000 = 0x6553F100 → 00 F1 53 65
        //   cycle_seq  = 42 = 0x2A     → 2A 00 00 00
        let expected: [u8; 16] = [
            0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xf1, 0x53, 0x65, 0x2a, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encode_slot_commit(&fixture()), expected);
    }
}
