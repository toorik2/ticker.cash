//! Redeem-script construction for each v13 covenant.
//!
//! CashScript constructor arg push order: declared args are **reversed** before
//! being emitted as pushes. The redeem script is:
//!
//! ```text
//!   push(arg_{N-1}) || push(arg_{N-2}) || ... || push(arg_0) || artifact_bytecode
//! ```
//!
//! Declared order (v13):
//!
//!   Oracle:         [tickerLockingBytecode, slotCategoryReversed]
//!   PublisherSlot:  [packedSourceCNHashes, oracleCategoryReversed, oracleLockingBytecode]
//!   Ticker:         []
//!
//! v12 PublisherSlot had 7 leading `notary0..notary6` pubkey args; v13 drops
//! them (the notary tier is removed, see PR13a / Phase B).
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

/// Build the v13 PublisherSlot covenant's redeem script.
///
/// Args:
///   * `packed_cn_hashes`          — 260 B (`13 × hash160(canonicalCN)`).
///   * `oracle_category_reversed`  — 32 B Oracle category in little-endian wire order.
///   * `oracle_locking_bytecode`   — 35 B P2SH-32 locking script of the Oracle covenant.
///
/// v12 took a 4th `notary_pubkeys: &[[u8; 33]; 7]` arg — dropped in v13 because
/// the notary tier is gone.
pub fn redeem_publisher_slot(
    packed_cn_hashes: &[u8; 260],
    oracle_category_reversed: &[u8; 32],
    oracle_locking_bytecode: &[u8; 35],
) -> Result<Vec<u8>, RedeemScriptError> {
    let bytecode = publisher_slot_bytecode()?;
    let mut s = Vec::with_capacity(bytecode.len() + 270 + 35 + 35);
    // Reverse declaration order.
    push_data(&mut s, oracle_locking_bytecode);
    push_data(&mut s, oracle_category_reversed);
    push_data(&mut s, packed_cn_hashes);
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
    use crate::chain::sources::packed_cn_hashes;
    use crate::covenant::locking::p2sh32_locking_bytecode;

    /// Live chipnet ground truth: every value here is dumped from the running
    /// production deployment (`.ticker/deploy-state.json` + seed.hex on
    /// ticker.cash-vps). If these tests ever break we've either changed a
    /// covenant source file, changed the P2SH-32 derivation, or changed the
    /// constructor-arg push order — any of which would invalidate a
    /// wire-compatible rebuild.

    /// `tickerLockingBytecodeHex` (Ticker has no constructor args).
    #[test]
    fn ticker_redeem_matches_live_chipnet_locking() {
        let redeem = redeem_ticker().unwrap();
        let lb = p2sh32_locking_bytecode(&redeem);
        let live_hex = "aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87";
        assert_eq!(hex::encode(lb), live_hex);
    }

    fn live_ticker_locking_bytecode() -> [u8; 35] {
        let h = hex::decode("aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87")
            .unwrap();
        h.try_into().unwrap()
    }

    fn live_oracle_locking_bytecode() -> [u8; 35] {
        let h = hex::decode("aa2090c9064dc6fee8d55da81e07ab6b0bdd55e67bae8d38376368d9973957a8f8fd87")
            .unwrap();
        h.try_into().unwrap()
    }

    fn reverse_hex_32(hex_str: &str) -> [u8; 32] {
        let mut b: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
        b.reverse();
        b
    }

    /// `oracleLockingBytecodeHex`. Constructor: [tickerLockingBytecode, slotCategoryReversed].
    ///
    /// IGNORED for v13: this test pins against the v12 chipnet deploy. Once the v13
    /// genesis ceremony lands (PR13d Week 4), update the live hex below and re-enable.
    #[test]
    #[ignore = "live-chipnet pin awaits v13 genesis deploy"]
    fn oracle_redeem_matches_live_chipnet_locking() {
        let ticker_lb = live_ticker_locking_bytecode();
        // slotCategory on chain: 846b2ca944750af011fa41bb87f9fda1244090a63be2cc3286223551343020f7
        let slot_cat_reversed = reverse_hex_32(
            "846b2ca944750af011fa41bb87f9fda1244090a63be2cc3286223551343020f7",
        );
        let redeem = redeem_oracle(&ticker_lb, &slot_cat_reversed).unwrap();
        let lb = p2sh32_locking_bytecode(&redeem);
        let live_hex = "aa2090c9064dc6fee8d55da81e07ab6b0bdd55e67bae8d38376368d9973957a8f8fd87";
        assert_eq!(hex::encode(lb), live_hex);
    }

    /// v13 `slotLockingBytecodeHex`. Constructor:
    /// [packedSourceCNHashes, oracleCategoryReversed, oracleLockingBytecode].
    ///
    /// IGNORED for v13: this test pins against a live chipnet deploy that
    /// doesn't exist yet. Re-enable + update the live hex after the v13
    /// genesis ceremony (PR13d Week 4).
    #[test]
    #[ignore = "live-chipnet pin awaits v13 genesis deploy"]
    fn publisher_slot_redeem_matches_live_chipnet_locking() {
        let cn_hashes = packed_cn_hashes();
        let oracle_cat_reversed = reverse_hex_32(
            "9880c31334f9f708e9e0a3cf956442290ae1a463bd806fd416a5ed10b40f0d17",
        );
        let oracle_lb = live_oracle_locking_bytecode();
        let redeem = redeem_publisher_slot(&cn_hashes, &oracle_cat_reversed, &oracle_lb).unwrap();
        let lb = p2sh32_locking_bytecode(&redeem);
        // TODO(PR13d): replace with v13 deploy locking bytecode.
        let live_hex = "<v13 deploy address pending>";
        assert_eq!(hex::encode(lb), live_hex);
    }
}
