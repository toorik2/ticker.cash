//! Schnorr signing digests for the notary and the publisher.
//!
//! Both are `checkDataSig` payloads — SHA-256 over a fixed field concatenation,
//! signed with secp256k1 Schnorr. Mirrors `daemon/src/helpers.ts:112-152`.
//!
//! The covenant recomputes each digest from on-chain bytes and verifies the
//! corresponding Schnorr signature against the notary or publisher pubkey.
//! Any field-order, endianness, or size deviation makes the signature unverifiable.

use sha2::{Digest, Sha256};

/// Notary signing digest.
///
/// `sha256(server_name || u16LE(source_id) || u64LE(price) || u32LE(timestamp) || u32LE(cycle_seq) || pkh20)`
///
/// `pkh20` binds the notary's signature to one publisher identity — without it a single
/// notary sig could be replayed across an attacker's self-generated keypairs and forge quorum.
pub fn notary_sig_digest(
    server_name: &str,
    source_id: u16,
    price: u64,
    timestamp: u32,
    cycle_seq: u32,
    pkh20: &[u8; 20],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(server_name.as_bytes());
    h.update(source_id.to_le_bytes());
    h.update(price.to_le_bytes());
    h.update(timestamp.to_le_bytes());
    h.update(cycle_seq.to_le_bytes());
    h.update(pkh20);
    h.finalize().into()
}

/// Publisher signing digest.
///
/// `sha256(u16LE(source_id) || u64LE(price) || u32LE(timestamp) || pkh20 || u32LE(cycle_seq) || cn_hash20)`
///
/// `cn_hash20` is `hash160(server_name)` — the covenant slices it against the per-source
/// CN hash committed at slot-covenant construction time.
pub fn publisher_sig_digest(
    source_id: u16,
    price: u64,
    timestamp: u32,
    pkh20: &[u8; 20],
    cycle_seq: u32,
    cn_hash20: &[u8; 20],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(source_id.to_le_bytes());
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

    /// Sanity test: independently compose the preimage and SHA-256 it, compare
    /// against the streaming digest. Catches accidental field reordering.
    #[test]
    fn notary_digest_matches_manual_sha256() {
        let server_name = "api.kraken.com";
        let source_id: u16 = 1;
        let price: u64 = 35_000_000;
        let timestamp: u32 = 1_700_000_000;
        let cycle_seq: u32 = 42;
        let pkh20: [u8; 20] = [0x11; 20];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(server_name.as_bytes());
        preimage.extend_from_slice(&source_id.to_le_bytes());
        preimage.extend_from_slice(&price.to_le_bytes());
        preimage.extend_from_slice(&timestamp.to_le_bytes());
        preimage.extend_from_slice(&cycle_seq.to_le_bytes());
        preimage.extend_from_slice(&pkh20);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            notary_sig_digest(server_name, source_id, price, timestamp, cycle_seq, &pkh20),
            expected
        );
    }

    #[test]
    fn publisher_digest_matches_manual_sha256() {
        let source_id: u16 = 3;
        let price: u64 = 99_999_999;
        let timestamp: u32 = 1_700_000_030;
        let pkh20: [u8; 20] = [0xab; 20];
        let cycle_seq: u32 = 43;
        let cn_hash20: [u8; 20] = [0xcd; 20];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&source_id.to_le_bytes());
        preimage.extend_from_slice(&price.to_le_bytes());
        preimage.extend_from_slice(&timestamp.to_le_bytes());
        preimage.extend_from_slice(&pkh20);
        preimage.extend_from_slice(&cycle_seq.to_le_bytes());
        preimage.extend_from_slice(&cn_hash20);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(
            publisher_sig_digest(source_id, price, timestamp, &pkh20, cycle_seq, &cn_hash20),
            expected
        );
    }

    /// Different field order MUST produce a different digest (smoke test against
    /// accidental cross-wiring of notary↔publisher digests).
    #[test]
    fn notary_and_publisher_digests_diverge() {
        let pkh20 = [0u8; 20];
        let cn = [0u8; 20];
        let a = notary_sig_digest("x", 1, 2, 3, 4, &pkh20);
        let b = publisher_sig_digest(1, 2, 3, &pkh20, 4, &cn);
        assert_ne!(a, b);
    }
}
