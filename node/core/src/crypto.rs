//! Hashing, secp256k1 keys and BCH Schnorr signatures (CHIP-2019-05).
//!
//! Why our own Schnorr: Bitcoin Cash's Schnorr scheme predates BIP-340 and differs from it in
//! two places, so no off-the-shelf crate produces a signature `OP_CHECKDATASIG` accepts:
//!
//!   * the nonce point `R` must have a y-coordinate that is a quadratic residue (Jacobi
//!     symbol +1), where BIP-340 requires an even y;
//!   * the challenge is `e = sha256(R.x ‖ P ‖ m)` with the **33-byte compressed** public key,
//!     where BIP-340 hashes an x-only key with tagged hashing.
//!
//! The signature is `R.x ‖ s` (64 bytes). `OP_CHECKDATASIG` hashes the message with sha256
//! itself, so `m` here is `sha256(message)`; transaction signatures use the sighash digest.
//! Nonces are deterministic (RFC 6979, HMAC-SHA256, extra data `"Schnorr+SHA256  "`, the
//! convention of the BCH reference implementation). Cross-checked against libauth vectors in
//! `tests` (contracts/test/schnorr-vectors.json).

use hmac::{Hmac, Mac};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar, U256};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// `SHA-256(data)`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `SHA-256(SHA-256(data))` — txids, sighash digests, P2SH-32 script hashes.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// `RIPEMD-160(SHA-256(data))` — P2PKH hashes.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("private key is zero or not below the curve order")]
    InvalidPrivateKey,
    #[error("public key is not a valid compressed secp256k1 point")]
    InvalidPublicKey,
    #[error("signature is malformed")]
    InvalidSignature,
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Option<Scalar> {
    let s = Scalar::from_repr(FieldBytes::clone_from_slice(bytes));
    if bool::from(s.is_some()) {
        Some(s.unwrap())
    } else {
        None
    }
}

fn secret_scalar(privkey: &[u8; 32]) -> Result<Scalar, KeyError> {
    match scalar_from_bytes(privkey) {
        Some(d) if !bool::from(d.is_zero()) => Ok(d),
        _ => Err(KeyError::InvalidPrivateKey),
    }
}

fn point_from_compressed(pubkey: &[u8; 33]) -> Result<AffinePoint, KeyError> {
    let ep = EncodedPoint::from_bytes(pubkey).map_err(|_| KeyError::InvalidPublicKey)?;
    let p = AffinePoint::from_encoded_point(&ep);
    if bool::from(p.is_some()) {
        Ok(p.unwrap())
    } else {
        Err(KeyError::InvalidPublicKey)
    }
}

/// 33-byte compressed public key for a 32-byte private key.
pub fn derive_pubkey(privkey: &[u8; 32]) -> Result<[u8; 33], KeyError> {
    let d = secret_scalar(privkey)?;
    let p = (ProjectivePoint::GENERATOR * d).to_affine();
    let ep = p.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(ep.as_bytes());
    Ok(out)
}

/// True when `y` is a quadratic residue mod p (Jacobi symbol +1). For secp256k1's
/// p ≡ 3 (mod 4) that is exactly "a square root exists".
fn y_is_quadratic_residue(point: &AffinePoint) -> bool {
    let ep = point.to_encoded_point(false);
    let y = ep.y().expect("uncompressed encoding carries y");
    let fe = FieldElement::from_bytes(y);
    if !bool::from(fe.is_some()) {
        return false;
    }
    bool::from(fe.unwrap().sqrt().is_some())
}

/// RFC 6979 nonce (HMAC-SHA256) with the BCH Schnorr extra data.
fn rfc6979_nonce(privkey: &[u8; 32], msg32: &[u8; 32]) -> Scalar {
    type HmacSha256 = Hmac<Sha256>;
    const EXTRA: &[u8; 16] = b"Schnorr+SHA256  ";
    let mac = |key: &[u8], parts: &[&[u8]]| -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    };
    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];
    k = mac(&k, &[&v, &[0x00], privkey, msg32, EXTRA]);
    v = mac(&k, &[&v]);
    k = mac(&k, &[&v, &[0x01], privkey, msg32, EXTRA]);
    v = mac(&k, &[&v]);
    loop {
        v = mac(&k, &[&v]);
        if let Some(cand) = scalar_from_bytes(&v) {
            if !bool::from(cand.is_zero()) {
                return cand;
            }
        }
        k = mac(&k, &[&v, &[0x00]]);
        v = mac(&k, &[&v]);
    }
}

fn challenge(r: &[u8; 32], pubkey: &[u8; 33], msg32: &[u8; 32]) -> Scalar {
    let mut pre = Vec::with_capacity(32 + 33 + 32);
    pre.extend_from_slice(r);
    pre.extend_from_slice(pubkey);
    pre.extend_from_slice(msg32);
    let h = sha256(&pre);
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::clone_from_slice(&h))
}

/// BCH Schnorr signature (64 bytes, `R.x ‖ s`) over a 32-byte digest.
pub fn schnorr_sign(privkey: &[u8; 32], msg32: &[u8; 32]) -> Result<[u8; 64], KeyError> {
    let d = secret_scalar(privkey)?;
    let pubkey = derive_pubkey(privkey)?;
    let mut k = rfc6979_nonce(privkey, msg32);
    let r_point = (ProjectivePoint::GENERATOR * k).to_affine();
    if !y_is_quadratic_residue(&r_point) {
        k = -k;
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(r_point.x().as_slice());
    let e = challenge(&r, &pubkey, msg32);
    let s = k + e * d;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(s.to_repr().as_slice());
    Ok(sig)
}

/// Verify a BCH Schnorr signature over a 32-byte digest. Returns `Ok(false)` for a
/// well-formed but invalid signature, `Err` for malformed inputs.
pub fn schnorr_verify(sig: &[u8; 64], pubkey: &[u8; 33], msg32: &[u8; 32]) -> Result<bool, KeyError> {
    let p = point_from_compressed(pubkey)?;
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);
    let s = scalar_from_bytes(&s_bytes).ok_or(KeyError::InvalidSignature)?;
    let e = challenge(&r, pubkey, msg32);
    let rp = ProjectivePoint::GENERATOR * s - ProjectivePoint::from(p) * e;
    if bool::from(rp.is_identity()) {
        return Ok(false);
    }
    let ra = rp.to_affine();
    if !y_is_quadratic_residue(&ra) {
        return Ok(false);
    }
    Ok(ra.x().as_slice() == r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_vector() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash160_empty_vector() {
        assert_eq!(hex::encode(hash160(b"")), "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb");
    }

    /// Generator-derived pubkey for privkey = 1 is the well-known G.
    #[test]
    fn pubkey_of_one_is_generator() {
        let mut sk = [0u8; 32];
        sk[31] = 1;
        assert_eq!(
            hex::encode(derive_pubkey(&sk).unwrap()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn zero_key_rejected() {
        assert_eq!(derive_pubkey(&[0u8; 32]).unwrap_err(), KeyError::InvalidPrivateKey);
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let sk = [0x42u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let m = sha256(b"hello v25");
        let sig = schnorr_sign(&sk, &m).unwrap();
        assert!(schnorr_verify(&sig, &pk, &m).unwrap());
        let mut bad = sig;
        bad[40] ^= 1;
        assert!(!schnorr_verify(&bad, &pk, &m).unwrap());
        let other = sha256(b"hello v26");
        assert!(!schnorr_verify(&sig, &pk, &other).unwrap());
        // deterministic
        assert_eq!(sig, schnorr_sign(&sk, &m).unwrap());
    }

    /// libauth (`signMessageHashSchnorr`) vectors: our verifier must accept them, and our
    /// signer must produce signatures libauth's verifier accepts (checked in the JS suite);
    /// here we additionally assert byte-identical signatures, which holds when the RFC 6979
    /// extra data matches the reference implementation.
    #[test]
    fn libauth_vectors_verify() {
        let raw = include_str!("../../../contracts/test/schnorr-vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        assert!(vectors.len() >= 4);
        for v in vectors {
            let sk: [u8; 32] = hex::decode(v["priv"].as_str().unwrap()).unwrap().try_into().unwrap();
            let pk: [u8; 33] = hex::decode(v["pub"].as_str().unwrap()).unwrap().try_into().unwrap();
            let h: [u8; 32] = hex::decode(v["hash"].as_str().unwrap()).unwrap().try_into().unwrap();
            let sig: [u8; 64] = hex::decode(v["sig"].as_str().unwrap()).unwrap().try_into().unwrap();
            assert_eq!(derive_pubkey(&sk).unwrap(), pk);
            assert!(schnorr_verify(&sig, &pk, &h).unwrap(), "libauth signature must verify");
            let ours = schnorr_sign(&sk, &h).unwrap();
            assert!(schnorr_verify(&ours, &pk, &h).unwrap());
            assert_eq!(ours, sig, "deterministic nonce should match libauth's RFC 6979 variant");
        }
    }
}
