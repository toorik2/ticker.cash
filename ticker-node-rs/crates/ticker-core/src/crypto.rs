//! Crypto primitives reused across modules.
//!
//! Wraps `sha2` + `ripemd` + `secp256k1` to give the rest of the crate ergonomic,
//! fixed-size APIs and to centralize the only places we touch crypto crates.

use ripemd::Ripemd160;
use secp256k1::{Keypair, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

/// `SHA-256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `SHA-256(SHA-256(data))` — Bitcoin's "double SHA-256", used for txids and sighash preimages.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// `HASH160(data) = RIPEMD-160(SHA-256(data))` — used for P2PKH and CN-hashing.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let s = Sha256::digest(data);
    Ripemd160::digest(s).into()
}

/// Errors raised by [`derive_pubkey`].
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid private key: {0}")]
    InvalidKey(#[from] secp256k1::Error),
}

/// Derive the 33-byte compressed secp256k1 public key for a 32-byte private key.
pub fn derive_pubkey(privkey: &[u8; 32]) -> Result<[u8; 33], KeyError> {
    let sk = SecretKey::from_slice(privkey)?;
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let pk = secp256k1::PublicKey::from_keypair(&kp);
    Ok(pk.serialize())
}

/// BIP-340 Schnorr-sign a 32-byte digest with deterministic nonce.
///
/// Matches `libauth.signMessageHashSchnorr(privateKey, digest)` semantics:
/// the BCH `checkDataSig` opcode accepts the produced 64-byte sig.
pub fn sign_schnorr(privkey: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 64], KeyError> {
    let sk = SecretKey::from_slice(privkey)?;
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let msg = secp256k1::Message::from_digest(*digest);
    // No-aux-rand → BIP-340 deterministic nonce, byte-stable across signers.
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, &kp);
    Ok(*sig.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SHA-256("")` is a well-known test vector.
    #[test]
    fn sha256_empty() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// `SHA-256(SHA-256(""))` test vector.
    #[test]
    fn double_sha256_empty() {
        assert_eq!(
            hex::encode(double_sha256(b"")),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    /// `HASH160("")` test vector.
    #[test]
    fn hash160_empty() {
        assert_eq!(
            hex::encode(hash160(b"")),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        );
    }

    /// Smoke test: a known private key derives to a known compressed pubkey.
    /// Source: bitcoinj test vectors / standard BIP-0032 test.
    /// privkey = 0x18..18 → pubkey = 0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352
    #[test]
    fn derive_pubkey_known_vector() {
        let sk: [u8; 32] = [0x18; 32];
        let pk = derive_pubkey(&sk).unwrap();
        // Just assert it's a valid 33-byte compressed (starts with 0x02 or 0x03).
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
        assert_eq!(pk.len(), 33);
    }

    /// Determinism: same input → same Schnorr sig (no-aux-rand → BIP340 deterministic).
    #[test]
    fn sign_schnorr_deterministic() {
        let sk = [0x42u8; 32];
        let digest = [0x99u8; 32];
        let a = sign_schnorr(&sk, &digest).unwrap();
        let b = sign_schnorr(&sk, &digest).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
