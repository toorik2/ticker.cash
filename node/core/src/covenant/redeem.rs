//! Redeem-script construction for each v12 covenant.
//!
//! CashScript constructor arg push order: declared args are **reversed** before
//! being emitted as pushes. The redeem script is:
//!
//! ```text
//!   push(arg_{N-1}) || push(arg_{N-2}) || ... || push(arg_0) || artifact_bytecode
//! ```
//!
//! Declared order (matching `daemon/scripts/deploy.ts`):
//!
//!   Oracle:         [tickerLockingBytecode, slotCategoryReversed]
//!   PublisherSlot:  [notary0..notary6, packedSourceCNHashes, oracleCategoryReversed, oracleLockingBytecode]
//!   Ticker:         []
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

/// Build the PublisherSlot covenant's redeem script.
///
/// Args:
///   * `notary_pubkeys`            — 7 × 33 B compressed pubkeys (OR-list).
///   * `packed_cn_hashes`          — 260 B (`13 × hash160(canonicalCN)`).
///   * `oracle_category_reversed`  — 32 B Oracle category in little-endian wire order.
///   * `oracle_locking_bytecode`   — 35 B P2SH-32 locking script of the Oracle covenant.
pub fn redeem_publisher_slot(
    notary_pubkeys: &[[u8; 33]; 7],
    packed_cn_hashes: &[u8; 260],
    oracle_category_reversed: &[u8; 32],
    oracle_locking_bytecode: &[u8; 35],
) -> Result<Vec<u8>, RedeemScriptError> {
    let bytecode = publisher_slot_bytecode()?;
    let mut s = Vec::with_capacity(bytecode.len() + 7 * 35 + 270 + 35 + 35);
    // Reverse declaration order.
    push_data(&mut s, oracle_locking_bytecode);
    push_data(&mut s, oracle_category_reversed);
    push_data(&mut s, packed_cn_hashes);
    for pk in notary_pubkeys.iter().rev() {
        push_data(&mut s, pk);
    }
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

    /// Live notary pubkeys, dumped from `.ticker/seed.hex` derivation on VPS.
    fn live_notary_pubkeys() -> [[u8; 33]; 7] {
        const HEX: [&str; 7] = [
            "0261cddf9b5d64bc2a588de8e36402e9fb99d95fcf1e69f4f63f1b386ea1a6f6ba",
            "03c69d09352fdf6e7aa855dcb7958ff0447017087eaef31202e4099981626ec90b",
            "03228ed5c8efe76933aadd86c0483046263492a5635f95570b5bb2d0b5600a55ce",
            "030ee2d60a5fdede626f7c83f6199e672f7ca8f290bf9f411f5c85dd4d9bdb6ec8",
            "03619e9fdfe9c2a0b6e353a520078fd938e953a02df3a289017af8281357b85f12",
            "02c3912220a6af45a83f017a0b9717d103bf153641205aa38e617b24a3641e54b0",
            "02cf85d91dbddc61a32d7f4ea4b67b5e16ed7bd2c3f128a18b178eb8b44edda84d",
        ];
        let mut out = [[0u8; 33]; 7];
        for (i, h) in HEX.iter().enumerate() {
            out[i].copy_from_slice(&hex::decode(h).unwrap());
        }
        out
    }

    /// `slotLockingBytecodeHex`. Constructor:
    /// [notary0..notary6, packedSourceCNHashes, oracleCategoryReversed, oracleLockingBytecode].
    ///
    /// IGNORED for v13: this test pins against the v12 chipnet deploy and v12's
    /// 4-arg redeem_publisher_slot signature (with notary pubkeys). Both change in v13:
    /// the constructor drops notaries (PR13b Week 2) and the deploy changes (PR13d Week 4).
    /// Re-enable after both land.
    #[test]
    #[ignore = "v12 signature + live-chipnet pin; awaits v13 PR13b + PR13d"]
    fn publisher_slot_redeem_matches_live_chipnet_locking() {
        let notaries = live_notary_pubkeys();
        let cn_hashes = packed_cn_hashes();
        // oracleCategory on chain: 9880c31334f9f708e9e0a3cf956442290ae1a463bd806fd416a5ed10b40f0d17
        let oracle_cat_reversed = reverse_hex_32(
            "9880c31334f9f708e9e0a3cf956442290ae1a463bd806fd416a5ed10b40f0d17",
        );
        let oracle_lb = live_oracle_locking_bytecode();
        let redeem = redeem_publisher_slot(&notaries, &cn_hashes, &oracle_cat_reversed, &oracle_lb)
            .unwrap();
        let lb = p2sh32_locking_bytecode(&redeem);
        let live_hex = "aa20ec8e0bc24f6934cb31518714a15c5c31424514bb9bcde5578e20da8d231a14db87";
        assert_eq!(hex::encode(lb), live_hex);
    }
}
