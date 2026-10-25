//! Notary statements and rotation approvals: the two messages a table key ever signs.
//!
//! ```text
//!   statement = 0x4e ‖ category(32, VM byte order) ‖ source(1) ‖ seq(4 LE) ‖ price(8 LE)     (46 B)
//!   approval  = 0x52 ‖ category(32) ‖ oldTableHash(20) ‖ nextLockingBytecode ‖ nextCommitment[13..]
//!   sig       = BCH Schnorr over sha256(message)            (OP_CHECKDATASIG hashes the message)
//! ```
//!
//! A statement names the exchange (source id), not a table position: a notary is a key and a
//! source, and the table may be rotated around it. The covenant rebuilds the message from its own
//! token category, the source byte stored in the row's table entry, the sequence and the supplied
//! price; only the price and the signature travel in the transaction.

use crate::crypto::{schnorr_sign, schnorr_verify, sha256, KeyError};
use crate::{APPROVAL_TAG, STATEMENT_TAG};
use serde::{Deserialize, Serialize};

pub const MESSAGE_LEN: usize = 1 + 32 + 1 + 4 + 8;

/// Build the statement message. `category_vm` is the category in VM byte order, i.e. the display
/// id reversed (what `tx.inputs[0].tokenCategory.split(32)[0]` yields on chain).
pub fn message(category_vm: &[u8; 32], source: u8, seq: u32, price: u64) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[0] = STATEMENT_TAG;
    m[1..33].copy_from_slice(category_vm);
    m[33] = source;
    m[34..38].copy_from_slice(&seq.to_le_bytes());
    m[38..46].copy_from_slice(&price.to_le_bytes());
    m
}

/// The rotation approval message.
pub fn approval_message(category_vm: &[u8; 32], old_table_hash: &[u8; 20], next_lock: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(1 + 32 + 20 + next_lock.len() + tail.len());
    m.push(APPROVAL_TAG);
    m.extend_from_slice(category_vm);
    m.extend_from_slice(old_table_hash);
    m.extend_from_slice(next_lock);
    m.extend_from_slice(tail);
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
    pub source: u8,
    pub seq: u32,
    pub price: u64,
    /// 64-byte Schnorr signature, hex.
    pub sig: String,
}

impl Statement {
    pub fn sign(privkey: &[u8; 32], category_vm: &[u8; 32], source: u8, seq: u32, price: u64) -> Result<Self, KeyError> {
        let m = message(category_vm, source, seq, price);
        let sig = schnorr_sign(privkey, &sha256(&m))?;
        Ok(Statement { source, seq, price, sig: hex::encode(sig) })
    }

    pub fn sig_bytes(&self) -> Option<[u8; 64]> {
        hex::decode(&self.sig).ok()?.try_into().ok()
    }

    /// Verify against a table row's pubkey.
    pub fn verify(&self, category_vm: &[u8; 32], pubkey: &[u8; 33]) -> bool {
        let Some(sig) = self.sig_bytes() else { return false };
        let m = message(category_vm, self.source, self.seq, self.price);
        schnorr_verify(&sig, pubkey, &sha256(&m)).unwrap_or(false)
    }
}

/// A row's approval of a rotation, produced offline by `ticker-notary sign-rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    /// 33-byte compressed pubkey, hex: identifies the row without naming its index.
    pub pubkey: String,
    pub old_table_hash: String,
    pub next_lock: String,
    pub tail: String,
    /// 64-byte Schnorr signature, hex.
    pub sig: String,
}

impl Approval {
    pub fn sign(privkey: &[u8; 32], pubkey: &[u8; 33], category_vm: &[u8; 32], old_table_hash: &[u8; 20], next_lock: &[u8], tail: &[u8]) -> Result<Self, KeyError> {
        let m = approval_message(category_vm, old_table_hash, next_lock, tail);
        let sig = schnorr_sign(privkey, &sha256(&m))?;
        Ok(Approval { pubkey: hex::encode(pubkey), old_table_hash: hex::encode(old_table_hash), next_lock: hex::encode(next_lock), tail: hex::encode(tail), sig: hex::encode(sig) })
    }

    pub fn sig_bytes(&self) -> Option<[u8; 64]> {
        hex::decode(&self.sig).ok()?.try_into().ok()
    }

    pub fn pubkey_bytes(&self) -> Option<[u8; 33]> {
        hex::decode(&self.pubkey).ok()?.try_into().ok()
    }

    /// Verify against the claimed pubkey and the rotation it is meant for.
    pub fn verify(&self, category_vm: &[u8; 32], old_table_hash: &[u8; 20], next_lock: &[u8], tail: &[u8]) -> bool {
        let (Some(sig), Some(pk)) = (self.sig_bytes(), self.pubkey_bytes()) else { return false };
        if hex::decode(&self.old_table_hash).ok().as_deref() != Some(&old_table_hash[..])
            || hex::decode(&self.next_lock).ok().as_deref() != Some(next_lock)
            || hex::decode(&self.tail).ok().as_deref() != Some(tail)
        {
            return false;
        }
        let m = approval_message(category_vm, old_table_hash, next_lock, tail);
        schnorr_verify(&sig, &pk, &sha256(&m)).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_pubkey;

    #[test]
    fn message_layout() {
        let cat = [0xabu8; 32];
        let m = message(&cat, 4, 0x0102_0304, 0x0a0b_0c0d_0e0f_1011);
        assert_eq!(m.len(), 46);
        assert_eq!(m[0], 0x4e);
        assert_eq!(&m[1..33], &cat);
        assert_eq!(m[33], 4);
        assert_eq!(&m[34..38], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&m[38..46], &[0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a]);
    }

    #[test]
    fn sign_verify_and_binding() {
        let sk = [7u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let cat = [1u8; 32];
        let st = Statement::sign(&sk, &cat, 3, 29_870_000, 27_715_000_000).unwrap();
        assert!(st.verify(&cat, &pk));
        let mut other = [1u8; 32];
        other[0] = 2;
        assert!(!st.verify(&other, &pk));
        for (field, mutate) in [("source", 0u8), ("seq", 1), ("price", 2)] {
            let mut t = st.clone();
            match mutate {
                0 => t.source = 9,
                1 => t.seq += 1,
                _ => t.price += 1,
            }
            assert!(!t.verify(&cat, &pk), "{field} must be bound");
        }
    }

    #[test]
    fn approval_binds_every_field() {
        let sk = [9u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let cat = [5u8; 32];
        let old = [3u8; 20];
        let lock = [0xaa, 0x20, 0x01, 0x87];
        let tail = [4u8; 20];
        let a = Approval::sign(&sk, &pk, &cat, &old, &lock, &tail).unwrap();
        assert!(a.verify(&cat, &old, &lock, &tail));
        assert!(!a.verify(&cat, &[0u8; 20], &lock, &tail));
        assert!(!a.verify(&cat, &old, &[0x76], &tail));
        assert!(!a.verify(&cat, &old, &lock, &[]));
        let mut other = cat;
        other[0] ^= 1;
        assert!(!a.verify(&other, &old, &lock, &tail));
    }

    #[test]
    fn category_display_to_vm_reverses() {
        let d = "00".repeat(31) + "ff";
        let vm = category_vm_from_display_hex(&d).unwrap();
        assert_eq!(vm[0], 0xff);
        assert_eq!(vm[31], 0x00);
    }
}
