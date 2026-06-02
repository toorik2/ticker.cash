//! PublisherSlot NFT commit (37 B in v17, version `0x75`).
//!
//! v16 → v17: dropped `source_id(u16 LE)` field (was at bytes 1..3).
//! Source identification now comes from the slot's P2SH-32 address, which is
//! per-source in v16+ (each source has its own redeem with its own cnHash baked
//! in). Commit-side sourceId was redundant; daemons derive sourceId from
//! address lookup against the manifest.
//!
//! | Offset | Size | Field        | Type      |
//! |--------|------|--------------|-----------|
//! | 0      | 1    | version      | `0x75`    |
//! | 1..21  | 20   | pkh          | bytes20   |
//! | 21..29 | 8    | price        | u64 LE    |
//! | 29..33 | 4    | timestamp    | u32 LE — MSB-clear by covenant gate |
//! | 33..37 | 4    | cycle_seq    | u32 LE — MSB-clear by covenant gate |
//!
//! `pkh` is **pinned at genesis** and never rewritten; only
//! `(price, timestamp, cycle_seq)` mutate via `PublisherSlot.attest`.

use super::consts::{SLOT_COMMIT_LEN, SLOT_VERSION_BYTE};

/// Decoded view of a PublisherSlot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotCommit {
    pub pkh: [u8; 20],
    pub price: u64,
    pub timestamp: u32,
    pub cycle_seq: u32,
}

/// Encode a slot commit to its 37-byte wire form.
pub fn encode_slot_commit(c: &SlotCommit) -> [u8; SLOT_COMMIT_LEN] {
    let mut out = [0u8; SLOT_COMMIT_LEN];
    out[0] = SLOT_VERSION_BYTE;
    out[1..21].copy_from_slice(&c.pkh);
    out[21..29].copy_from_slice(&c.price.to_le_bytes());
    out[29..33].copy_from_slice(&c.timestamp.to_le_bytes());
    out[33..37].copy_from_slice(&c.cycle_seq.to_le_bytes());
    out
}

/// Decode a 37-byte slot commit. Returns `None` for wrong length or version.
pub fn decode_slot_commit(bytes: &[u8]) -> Option<SlotCommit> {
    if bytes.len() != SLOT_COMMIT_LEN || bytes[0] != SLOT_VERSION_BYTE {
        return None;
    }
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&bytes[1..21]);
    Some(SlotCommit {
        pkh,
        price: u64::from_le_bytes(bytes[21..29].try_into().ok()?),
        timestamp: u32::from_le_bytes(bytes[29..33].try_into().ok()?),
        cycle_seq: u32::from_le_bytes(bytes[33..37].try_into().ok()?),
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
    fn encode_length_and_version() {
        let bytes = encode_slot_commit(&fixture());
        assert_eq!(bytes.len(), SLOT_COMMIT_LEN);
        assert_eq!(bytes.len(), 37);
        assert_eq!(bytes[0], 0x75);
    }

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
        assert_eq!(decode_slot_commit(&bytes[..36]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_slot_commit(&longer), None);
    }

    #[test]
    fn known_vector_byte_for_byte() {
        // Hand-computed expected bytes for the fixture (prefix 0x75, no sourceId):
        //   version 0x75
        //   pkh        = 11..44        → 20 bytes
        //   price      = 0x01234567   → 67 45 23 01 00 00 00 00
        //   timestamp  = 1_700_000_000 = 0x6553F100 → 00 F1 53 65
        //   cycle_seq  = 42 = 0x2A     → 2A 00 00 00
        let expected: [u8; 37] = [
            0x75, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x67, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xf1, 0x53, 0x65, 0x2a, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encode_slot_commit(&fixture()), expected);
    }
}
