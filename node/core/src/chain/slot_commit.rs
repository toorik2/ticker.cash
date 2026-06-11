//! PublisherSlot NFT commit (18 B in v24, no version byte, no pkh).
//!
//! v22 → v24 (P01): widened `timestamp` and `cycle_seq` from u32 to u40 LE
//! to close F03 / F04 / Y2038 at the slot layer. Layout:
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0..8   | 8    | price        | u64 LE    |
//! | 8..13  | 5    | timestamp    | u40 LE    |
//! | 13..18 | 5    | cycle_seq    | u40 LE    |
//!
//! Publisher identity is derived from the slot UTXO's address (= specialized
//! P2S LB), not from commit. Daemon look-up: address → source_id via manifest.

use super::consts::SLOT_COMMIT_LEN;
use super::{u40_from_le, u40_to_le};

/// Decoded view of a PublisherSlot commit. `timestamp` and `cycle_seq` are
/// u40 in wire form; kept as u64 here (high 24 bits always zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotCommit {
    pub price: u64,
    pub timestamp: u64,
    pub cycle_seq: u64,
}

/// Encode a slot commit to its 18-byte wire form.
pub fn encode_slot_commit(c: &SlotCommit) -> [u8; SLOT_COMMIT_LEN] {
    let mut out = [0u8; SLOT_COMMIT_LEN];
    out[0..8].copy_from_slice(&c.price.to_le_bytes());
    out[8..13].copy_from_slice(&u40_to_le(c.timestamp));
    out[13..18].copy_from_slice(&u40_to_le(c.cycle_seq));
    out
}

/// Decode an 18-byte slot commit. Returns `None` for wrong length.
pub fn decode_slot_commit(bytes: &[u8]) -> Option<SlotCommit> {
    if bytes.len() != SLOT_COMMIT_LEN {
        return None;
    }
    Some(SlotCommit {
        price: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
        timestamp: u40_from_le(bytes[8..13].try_into().ok()?),
        cycle_seq: u40_from_le(bytes[13..18].try_into().ok()?),
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
        assert_eq!(bytes.len(), 18);
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
        assert_eq!(decode_slot_commit(&bytes[..17]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_slot_commit(&longer), None);
    }

    #[test]
    fn known_vector_byte_for_byte() {
        // Hand-computed expected bytes for fixture (no pkh, no version):
        //   price      = 0x01234567 → 67 45 23 01 00 00 00 00
        //   timestamp  = 1_700_000_000 = 0x6553F100 → 00 F1 53 65 00 (u40 LE)
        //   cycle_seq  = 42 = 0x2A     → 2A 00 00 00 00 (u40 LE)
        let expected: [u8; 18] = [
            0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0xf1, 0x53, 0x65, 0x00,
            0x2a, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encode_slot_commit(&fixture()), expected);
    }
}
