//! P2SH-32 locking-bytecode derivation.
//!
//! Format: `OP_HASH256 <32 B script hash> OP_EQUAL` (35 bytes total).
//! On the wire: `aa 20 <32 B> 87`.
//!
//! The script hash is **double-SHA-256** of the redeem script
//! (consistent with `OP_HASH256` semantics; reference at https://github.com/bitjson/p2sh32).

use crate::crypto::double_sha256;

/// P2SH-32 locking-bytecode length in bytes.
pub const P2SH32_LEN: usize = 35;

const OP_HASH256: u8 = 0xaa;
const PUSH_32_BYTES: u8 = 0x20;
const OP_EQUAL: u8 = 0x87;

/// Derive the P2SH-32 locking bytecode for a redeem script.
///
/// `aa 20 <double_sha256(redeem_script)> 87`
pub fn p2sh32_locking_bytecode(redeem_script: &[u8]) -> [u8; P2SH32_LEN] {
    let hash = double_sha256(redeem_script);
    let mut out = [0u8; P2SH32_LEN];
    out[0] = OP_HASH256;
    out[1] = PUSH_32_BYTES;
    out[2..34].copy_from_slice(&hash);
    out[34] = OP_EQUAL;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locking_bytecode_shape() {
        let lb = p2sh32_locking_bytecode(b"sample redeem");
        assert_eq!(lb[0], 0xaa);
        assert_eq!(lb[1], 0x20);
        assert_eq!(lb[34], 0x87);
        assert_eq!(lb.len(), 35);
    }

    #[test]
    fn determinism() {
        let a = p2sh32_locking_bytecode(b"abc");
        let b = p2sh32_locking_bytecode(b"abc");
        let c = p2sh32_locking_bytecode(b"abd");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
