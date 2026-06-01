//! Redeem-script construction for each ticker.cash covenant.
//!
//! CashScript constructor arg push order: declared args are **reversed** before
//! being emitted as pushes. The redeem script is:
//!
//! ```text
//!   push(arg_{N-1}) || push(arg_{N-2}) || ... || push(arg_0) || artifact_bytecode
//! ```
//!
//! Declared order:
//!
//!   Oracle:         [tickerLockingBytecode, slotCategoryReversed]
//!   PublisherSlot:  [cnHash, oracleCategoryReversed]                ← v16
//!   Ticker:         []
//!
//! v15 PublisherSlot took (packedSourceCNHashes:bytes260, oracleCategoryReversed,
//! oracleLockingBytecode) — three args producing one 625 B redeem shared by all
//! 13 slots. v16 takes one 20 B per-slot cnHash + oracleCategoryReversed and
//! drops the LB pin; each of the 13 slots compiles to a distinct 262 B redeem.
//! See /tmp/slot-experiments/v16-design.md for the full rationale.
//!
//! Each push uses minimal-push encoding (`tx::script::push_data`).

use super::artifacts::{
    oracle_bytecode, publisher_slot_bytecode, ticker_bytecode, ArtifactError,
};
use crate::tx::script::push_data;

/// Errors that can occur while building a redeem script.
#[derive(Debug, thiserror::Error)]
pub enum RedeemScriptError {
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    #[error("constructor arg `{name}` has wrong length: expected {expected}, got {got}")]
    WrongArgLength {
        name: &'static str,
        expected: usize,
        got: usize,
    },
}

/// Build the Oracle covenant's redeem script.
///
/// Args:
///   * `ticker_locking_bytecode`   — 35 B P2SH-32 locking script of the Ticker covenant.
///   * `slot_category_reversed`    — 32 B PublisherSlot category in little-endian wire order.
pub fn redeem_oracle(
    ticker_locking_bytecode: &[u8; 35],
    slot_category_reversed: &[u8; 32],
) -> Result<Vec<u8>, RedeemScriptError> {
    let bytecode = oracle_bytecode()?;
    let mut s = Vec::with_capacity(bytecode.len() + 80);
    // Reverse declaration order: arg[1] pushed first, arg[0] last.
    push_data(&mut s, slot_category_reversed);
    push_data(&mut s, ticker_locking_bytecode);
    s.extend_from_slice(bytecode);
    Ok(s)
}

/// Build a v16 PublisherSlot covenant redeem script for ONE source.
///
/// v16 bakes a single per-source cnHash into the redeem (rather than the
/// 260-byte packed table v15 used). Each of the 13 sources therefore has a
/// distinct redeem and a distinct P2SH-32 address.
///
/// Args:
///   * `cn_hash`                   — 20 B `hash160(canonicalCN)` for THIS source.
///   * `oracle_category_reversed`  — 32 B Oracle category in little-endian wire order.
pub fn redeem_publisher_slot(
    cn_hash: &[u8; 20],
    oracle_category_reversed: &[u8; 32],
) -> Result<Vec<u8>, RedeemScriptError> {
    let bytecode = publisher_slot_bytecode()?;
    let mut s = Vec::with_capacity(bytecode.len() + 60);
    // Reverse declaration order.
    push_data(&mut s, oracle_category_reversed);
    push_data(&mut s, cn_hash);
    s.extend_from_slice(bytecode);
    Ok(s)
}

/// Build the Ticker covenant's redeem script. Zero constructor args, so this
/// is just the bytecode.
pub fn redeem_ticker() -> Result<Vec<u8>, RedeemScriptError> {
    Ok(ticker_bytecode()?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::sources::{source_cn_hash, SOURCES};
    use crate::covenant::locking::p2sh32_locking_bytecode;

    /// Ticker has no constructor args, so its redeem is deterministic — pin
    /// to ensure the artifact hasn't drifted.
    #[test]
    fn ticker_redeem_matches_v15_bytecode() {
        let redeem = redeem_ticker().unwrap();
        let lb = p2sh32_locking_bytecode(&redeem);
        let v15_hex = "aa208e80af66f9834d331fea34bc88d0c71e0f89b156389bb30e51f1a37d0f87a85b87";
        assert_eq!(hex::encode(lb), v15_hex);
    }

    /// v16 PublisherSlot redeem is now ~262 B (was 625 B in v15). Per-source
    /// redeems differ only in their cnHash push. Verify the shape.
    #[test]
    fn publisher_slot_redeem_v16_shape() {
        let cn_hash = [0x42u8; 20];
        let oracle_cat = [0xeeu8; 32];
        let redeem = redeem_publisher_slot(&cn_hash, &oracle_cat).unwrap();
        // Push order is REVERSED declaration order: oracleCat (arg 1) pushed
        // first, cnHash (arg 0) pushed second, then body.
        // Layout: push(32) + 32B oracleCat + push(20) + 20B cnHash + body
        let body = publisher_slot_bytecode().unwrap();
        assert_eq!(redeem.len(), 1 + 32 + 1 + 20 + body.len());
        assert_eq!(redeem[0], 0x20); // push 32 — oracleCat first
        assert_eq!(redeem[33], 0x14); // push 20 — cnHash second
    }

    /// Two different sources must produce two different redeems / addresses
    /// — the load-bearing v16 property.
    #[test]
    fn per_source_redeems_differ() {
        let oracle_cat = [0xeeu8; 32];
        // Compute cnHashes for the first two configured sources.
        let cn_a = source_cn_hash(&SOURCES[0]);
        let cn_b = source_cn_hash(&SOURCES[1]);
        assert_ne!(cn_a, cn_b, "fixture: first two sources must have distinct cn names");
        let r_a = redeem_publisher_slot(&cn_a, &oracle_cat).unwrap();
        let r_b = redeem_publisher_slot(&cn_b, &oracle_cat).unwrap();
        assert_ne!(r_a, r_b, "v16 per-source redeems must differ");
        let lb_a = p2sh32_locking_bytecode(&r_a);
        let lb_b = p2sh32_locking_bytecode(&r_b);
        assert_ne!(lb_a, lb_b, "v16 per-source P2SH-32 LBs must differ");
    }
}
