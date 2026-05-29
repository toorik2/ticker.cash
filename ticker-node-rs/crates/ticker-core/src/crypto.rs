//! Crypto primitives reused across modules.
//!
//! Wraps `sha2` + `ripemd` + `secp256k1` to give the rest of the crate ergonomic,
//! fixed-size APIs and to centralize the only places we touch crypto crates.

use ripemd::Ripemd160;
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
}
