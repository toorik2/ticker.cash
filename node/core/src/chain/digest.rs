//! Publisher signing digest.
//!
//! `checkDataSig` payload — SHA-256 over a fixed field concatenation, signed
//! with secp256k1 ECDSA-DER.
//!
//! The covenant recomputes the digest from on-chain bytes and verifies the
//! signature against the publisher pubkey. Any field-order, endianness, or
//! size deviation makes the signature unverifiable.
//!
//! v16 → v17: dropped `source_id` from the payload.
//! v22 → v24 (P01): widened `timestamp` and `cycle_seq` from u32 to u40 LE
//! to match the covenant's widened commit layouts.

use sha2::{Digest, Sha256};

use super::u40_to_le;

/// Publisher signing digest (v24).
///
/// `sha256(u64LE(price) || u40LE(timestamp) || pkh20 || u40LE(cycle_seq) || cn_hash20)`
pub fn publisher_sig_digest(
    price: u64,
    timestamp: u64,
    pkh20: &[u8; 20],
    cycle_seq: u64,
    cn_hash20: &[u8; 20],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(price.to_le_bytes());
    h.update(u40_to_le(timestamp));
    h.update(pkh20);
    h.update(u40_to_le(cycle_seq));
    h.update(cn_hash20);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publisher_digest_matches_manual_sha256() {
        let price: u64 = 99_999_999;
        let timestamp: u64 = 1_700_000_030;
        let pkh20: [u8; 20] = [0xab; 20];
        let cycle_seq: u64 = 43;
        let cn_hash20: [u8; 20] = [0xcd; 20];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&price.to_le_bytes());
        preimage.extend_from_slice(&u40_to_le(timestamp));
        preimage.extend_from_slice(&pkh20);
        preimage.extend_from_slice(&u40_to_le(cycle_seq));
        preimage.extend_from_slice(&cn_hash20);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            publisher_sig_digest(price, timestamp, &pkh20, cycle_seq, &cn_hash20),
            expected
        );
    }
}
