//! Notary statements and rotation approvals: the two messages a table key ever signs.
//!
//! ```text
//!   statement = 0x4e ‖ source(1) ‖ timestamp(4 LE) ‖ price(4 LE, cents)                                 (10 B)
//!   approval  = 0x52 ‖ category(32) ‖ oldTableHash(20) ‖ nextLockingBytecode ‖ nextCommitment[17..]
//!   sig       = BCH Schnorr over sha256(message)            (OP_CHECKDATASIG hashes the message)
//! ```
//!
//! A statement names the exchange (source id) and nothing else: not a table position, and not a
//! deployment. It is a public fact, "this exchange said this price at this minute", signed by a
//! key, and any head whose table lists that key may consume it. That is what lets anyone
//! instantiate an oracle over public notaries. The timestamp is the start of the observed minute;
//! the price is US cents per BCH. The covenant rebuilds the message from the source byte stored in
//! the row's table entry, the timestamp and the supplied price; only the price and the signature
//! travel in the transaction. Approvals, by contrast, bind the category: governance is per instance.

use crate::crypto::{schnorr_sign, schnorr_verify, sha256, KeyError};
use crate::{APPROVAL_TAG, STATEMENT_TAG};
use serde::{Deserialize, Serialize};

pub const MESSAGE_LEN: usize = 1 + 1 + 4 + 4;

/// Build the statement message.
pub fn message(source: u8, ts: u32, price: u32) -> [u8; MESSAGE_LEN] {
    let mut m = [0u8; MESSAGE_LEN];
    m[0] = STATEMENT_TAG;
    m[1] = source;
    m[2..6].copy_from_slice(&ts.to_le_bytes());
    m[6..10].copy_from_slice(&price.to_le_bytes());
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
    /// Start of the observed Unix minute, seconds.
    pub ts: u32,
    /// US cents per BCH.
    pub price: u32,
    /// 64-byte Schnorr signature, hex.
    pub sig: String,
}

impl Statement {
    pub fn sign(privkey: &[u8; 32], source: u8, ts: u32, price: u32) -> Result<Self, KeyError> {
        let m = message(source, ts, price);
        let sig = schnorr_sign(privkey, &sha256(&m))?;
        Ok(Statement { source, ts, price, sig: hex::encode(sig) })
    }

    /// The Unix minute this statement is for.
    pub fn minute(&self) -> u32 {
        self.ts / 60
    }

    pub fn sig_bytes(&self) -> Option<[u8; 64]> {
        hex::decode(&self.sig).ok()?.try_into().ok()
    }

    /// Verify against a table row's pubkey.
    pub fn verify(&self, pubkey: &[u8; 33]) -> bool {
        let Some(sig) = self.sig_bytes() else { return false };
        let m = message(self.source, self.ts, self.price);
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
        let m = message(4, 0x0102_0304, 0x0e0f_1011);
        assert_eq!(m.len(), 10);
        assert_eq!(m[0], 0x4e);
        assert_eq!(m[1], 4);
        assert_eq!(&m[2..6], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&m[6..10], &[0x11, 0x10, 0x0f, 0x0e]);
    }

    #[test]
    fn sign_verify_and_binding() {
        let sk = [7u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let st = Statement::sign(&sk, 3, 1_792_200_000, 27_715).unwrap();
        assert!(st.verify(&pk));
        for (field, mutate) in [("source", 0u8), ("ts", 1), ("price", 2)] {
            let mut t = st.clone();
            match mutate {
                0 => t.source = 9,
                1 => t.ts += 60,
                _ => t.price += 1,
            }
            assert!(!t.verify(&pk), "{field} must be bound");
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
