//! Notary statements: the 47-byte message a notary signs, and the signed object that travels
//! from notary to builder.
//!
//! ```text
//!   message = 0x4e ‖ category(32, VM byte order) ‖ row(1) ‖ source(1) ‖ seq(4 LE) ‖ price(8 LE)
//!   sig     = BCH Schnorr over sha256(message)           (OP_CHECKDATASIG hashes the message)
//! ```
//!
//! The covenant rebuilds the message from its own token category, the row byte, the source
//! byte stored in that row's table entry, the sequence, and the supplied price; nothing but the
//! price and the signature are carried in the transaction.

use crate::crypto::{schnorr_sign, schnorr_verify, sha256, KeyError};
use crate::STATEMENT_TAG;
use serde::{Deserialize, Serialize};

pub const MESSAGE_LEN: usize = 1 + 32 + 1 + 1 + 4 + 8;

/// Build the statement message. `category_vm` is the category in VM byte order, i.e. the
/// display id reversed (what `tx.inputs[i].tokenCategory.slice(0, 32)` yields on chain).
pub fn message(category_vm: &[u8; 32], row: u8, source: u8, seq: u32, price: u64) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[0] = STATEMENT_TAG;
    m[1..33].copy_from_slice(category_vm);
    m[33] = row;
    m[34] = source;
    m[35..39].copy_from_slice(&seq.to_le_bytes());
    m[39..47].copy_from_slice(&price.to_le_bytes());
    m
}

/// Display-order category hex (as explorers and Fulcrum print it) to VM byte order.
pub fn category_vm_from_display_hex(display_hex: &str) -> Option<[u8; 32]> {
    let mut b: [u8; 32] = hex::decode(display_hex).ok()?.try_into().ok()?;
    b.reverse();
    Some(b)
}

/// A signed statement, as served by a notary over HTTP and as consumed by a builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub row: u8,
    pub source: u8,
    pub seq: u32,
    pub price: u64,
    /// 64-byte Schnorr signature, hex.
    pub sig: String,
}

impl Statement {
    pub fn sign(privkey: &[u8; 32], category_vm: &[u8; 32], row: u8, source: u8, seq: u32, price: u64) -> Result<Self, KeyError> {
        let m = message(category_vm, row, source, seq, price);
        let sig = schnorr_sign(privkey, &sha256(&m))?;
        Ok(Statement { row, source, seq, price, sig: hex::encode(sig) })
    }

    pub fn sig_bytes(&self) -> Option<[u8; 64]> {
        hex::decode(&self.sig).ok()?.try_into().ok()
    }

    /// Verify against the notary pubkey the table holds for `self.row`.
    pub fn verify(&self, category_vm: &[u8; 32], pubkey: &[u8; 33]) -> bool {
        let Some(sig) = self.sig_bytes() else { return false };
        let m = message(category_vm, self.row, self.source, self.seq, self.price);
        schnorr_verify(&sig, pubkey, &sha256(&m)).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_pubkey;

    #[test]
    fn message_layout() {
        let cat = [0xabu8; 32];
        let m = message(&cat, 3, 4, 0x0102_0304, 0x0a0b_0c0d_0e0f_1011);
        assert_eq!(m.len(), 47);
        assert_eq!(m[0], 0x4e);
        assert_eq!(&m[1..33], &cat);
        assert_eq!(m[33], 3);
        assert_eq!(m[34], 4);
        assert_eq!(&m[35..39], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&m[39..47], &[0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a]);
    }

    #[test]
    fn sign_verify_and_binding() {
        let sk = [7u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let cat = [1u8; 32];
        let st = Statement::sign(&sk, &cat, 2, 3, 29_870_000, 27_715_000_000).unwrap();
        assert!(st.verify(&cat, &pk));
        // another deployment, row, source, minute or price: all refused
        let mut other = [1u8; 32];
        other[0] = 2;
        assert!(!st.verify(&other, &pk));
        let mut t = st.clone();
        t.row = 3;
        assert!(!t.verify(&cat, &pk));
        let mut t = st.clone();
        t.source = 9;
        assert!(!t.verify(&cat, &pk));
        let mut t = st.clone();
        t.seq += 1;
        assert!(!t.verify(&cat, &pk));
        let mut t = st.clone();
        t.price += 1;
        assert!(!t.verify(&cat, &pk));
    }

    #[test]
    fn category_display_to_vm_reverses() {
        let d = "00".repeat(31) + "ff";
        let vm = category_vm_from_display_hex(&d).unwrap();
        assert_eq!(vm[0], 0xff);
        assert_eq!(vm[31], 0x00);
    }
}
