//! PublisherSlot NFT commit (39 B, version `0x75`).
//!
//! v15→v16 keeps the commit layout AND version byte unchanged (Oracle.cash
//! hard-codes `0x75`; bumping would require an Oracle re-compile).
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0      | 1    | version      | `0x75`    |
//! | 1..3   | 2    | source_id    | u16 LE    |
//! | 3..23  | 20   | pkh          | bytes20   |
//! | 23..31 | 8    | price        | u64 LE    |
//! | 31..35 | 4    | timestamp    | u32 LE — MSB-clear by covenant gate |
//! | 35..39 | 4    | cycle_seq    | u32 LE — MSB-clear by covenant gate |
//!
//! `source_id` and `pkh` are **pinned at genesis** and never rewritten;
//! only `(price, timestamp, cycle_seq)` mutate via `PublisherSlot.attest`.
//! v16 covenant enforces MSB-clear on `timestamp` and `cycle_seq` to close
//! the sign-magnitude self-DoS class.

use super::consts::{SLOT_COMMIT_LEN, SLOT_VERSION_BYTE};

/// Decoded view of a PublisherSlot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotCommit {
    pub source_id: u16,
    pub pkh: [u8; 20],
    pub price: u64,
    pub timestamp: u32,
    pub cycle_seq: u32,
}

/// Encode a slot commit to its 39-byte wire form.
pub fn encode_slot_commit(c: &SlotCommit) -> [u8; SLOT_COMMIT_LEN] {
    let mut out = [0u8; SLOT_COMMIT_LEN];
    out[0] = SLOT_VERSION_BYTE;
    out[1..3].copy_from_slice(&c.source_id.to_le_bytes());
    out[3..23].copy_from_slice(&c.pkh);
    out[23..31].copy_from_slice(&c.price.to_le_bytes());
    out[31..35].copy_from_slice(&c.timestamp.to_le_bytes());
    out[35..39].copy_from_slice(&c.cycle_seq.to_le_bytes());
    out
}

/// Decode a 39-byte slot commit. Returns `None` for wrong length or version.
pub fn decode_slot_commit(bytes: &[u8]) -> Option<SlotCommit> {
    if bytes.len() != SLOT_COMMIT_LEN || bytes[0] != SLOT_VERSION_BYTE {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&bytes[3..23]);
    Some(SlotCommit {
        source_id: u16::from_le_bytes(bytes[1..3].try_into().ok()?),
        pkh,
        price: u64::from_le_bytes(bytes[23..31].try_into().ok()?),
        timestamp: u32::from_le_bytes(bytes[31..35].try_into().ok()?),
        cycle_seq: u32::from_le_bytes(bytes[35..39].try_into().ok()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> SlotCommit {
        SlotCommit {
            source_id: 1,
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
    fn encode_length_and_version() {
        let bytes = encode_slot_commit(&fixture());
        assert_eq!(bytes.len(), SLOT_COMMIT_LEN);
        assert_eq!(bytes[0], 0x75);
    }

    /// Wrong-version commits (anything other than 0x75) must NOT decode.
    #[test]
    fn rejects_wrong_prefix() {
        let mut bytes = encode_slot_commit(&fixture());
        bytes[0] = 0x73;
        assert_eq!(decode_slot_commit(&bytes), None);
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let c = fixture();
        let bytes = encode_slot_commit(&c);
        let decoded = decode_slot_commit(&bytes).expect("valid commit decodes");
        assert_eq!(c, decoded);
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut bytes = encode_slot_commit(&fixture());
        bytes[0] = 0x71;
        assert_eq!(decode_slot_commit(&bytes), None);
    }

    #[test]
    fn decode_rejects_wrong_length() {
        let bytes = encode_slot_commit(&fixture());
        assert_eq!(decode_slot_commit(&bytes[..38]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_slot_commit(&longer), None);
    }

    #[test]
    fn known_vector_byte_for_byte() {
        // Hand-computed expected bytes for the fixture (prefix 0x75):
        //   version 0x75
        //   source_id  = 1            → 01 00
        //   pkh        = 11..44        → 20 bytes
        //   price      = 0x01234567   → 67 45 23 01 00 00 00 00
        //   timestamp  = 1_700_000_000 = 0x6553F100 → 00 F1 53 65
        //   cycle_seq  = 42 = 0x2A     → 2A 00 00 00
        let expected: [u8; 39] = [
            0x75, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x67, 0x45, 0x23, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf1, 0x53, 0x65, 0x2a, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encode_slot_commit(&fixture()), expected);
    }
}
