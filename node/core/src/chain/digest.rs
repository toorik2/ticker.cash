//! Publisher signing digest.
//!
//! `checkDataSig` payload — SHA-256 over a fixed field concatenation, signed
//! with secp256k1 ECDSA-DER.
//!
//! The covenant recomputes the digest from on-chain bytes and verifies the
//! signature against the publisher pubkey. Any field-order, endianness, or
//! size deviation makes the signature unverifiable.
//!
//! v16 → v17: dropped `source_id` from the payload (was the first field).
//! v17 publisher signs over the cnHash directly (rather than hash160 of a
//! pushed serverName arg, which was redundant since cnHash is pinned by the
//! P2SH-32 address).

use sha2::{Digest, Sha256};

/// Publisher signing digest (v17).
///
/// `sha256(u64LE(price) || u32LE(timestamp) || pkh20 || u32LE(cycle_seq) || cn_hash20)`
///
/// Note: source_id dropped in v17 (was redundant since per-source addressing in v16+
/// implies sourceId from the slot's address).
pub fn publisher_sig_digest(
    price: u64,
    timestamp: u32,
    pkh20: &[u8; 20],
    cycle_seq: u32,
    cn_hash20: &[u8; 20],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(price.to_le_bytes());
    h.update(timestamp.to_le_bytes());
    h.update(pkh20);
    h.update(cycle_seq.to_le_bytes());
    h.update(cn_hash20);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_digest_matches_manual_sha256() {
        let price: u64 = 99_999_999;
        let timestamp: u32 = 1_700_000_030;
        let pkh20: [u8; 20] = [0xab; 20];
        let cycle_seq: u32 = 43;
        let cn_hash20: [u8; 20] = [0xcd; 20];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&price.to_le_bytes());
        preimage.extend_from_slice(&timestamp.to_le_bytes());
        preimage.extend_from_slice(&pkh20);
        preimage.extend_from_slice(&cycle_seq.to_le_bytes());
        preimage.extend_from_slice(&cn_hash20);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            publisher_sig_digest(price, timestamp, &pkh20, cycle_seq, &cn_hash20),
            expected
        );
    }
}
