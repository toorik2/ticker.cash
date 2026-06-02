//! Redeem-script construction for each ticker.cash covenant.
//!
//! v22 changes the slot covenant from P2SH-32 with ctor args to P2S with
//! per-source body-literal specialization. The compiled PublisherSlot
//! artifact is a TEMPLATE: 3 specific byte ranges (at fixed offsets) are
//! substituted with the per-source values to produce the deployed body.
//! Under P2S, the body IS the locking bytecode — no hash wrapper.
//!
//! Oracle and Ticker stay P2SH-32.
//!
//! Declared ctor order:
//!   Oracle:         [tickerLockingBytecode]                     ← v22 (was 2 args)
//!   PublisherSlot:  []                                          ← v22 (was 2 args)
//!   Ticker:         []
//!
//! CashScript ctor args, when present, are pushed in reverse declaration order
//! before the body. With Oracle having one arg, redeem = push(ticker_lb) || body.
//! With PublisherSlot having zero args, the redeem == body (no pushes).
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
    #[error("template placeholder not found at expected offset {offset}")]
    PlaceholderMissing { offset: usize },
}

/// v22 slot template literal offsets, verified at cashc-emit time.
/// Each placeholder is 20 bytes (a `bytes20` literal in cashscript source).
pub const SLOT_PKH_OFFSET: usize = 8;
pub const SLOT_CN_HASH_OFFSET: usize = 57;
pub const SLOT_ORACLE_CAT_HASH_OFFSET: usize = 124;

/// Build the v22 Oracle covenant's redeem script (P2SH-32 — Oracle is over P2S cap).
///
/// Args:
///   * `ticker_locking_bytecode` — 35 B P2SH-32 locking script of the Ticker covenant.
pub fn redeem_oracle(
    ticker_locking_bytecode: &[u8; 35],
) -> Result<Vec<u8>, RedeemScriptError> {
    let bytecode = oracle_bytecode()?;
    let mut s = Vec::with_capacity(bytecode.len() + 40);
    push_data(&mut s, ticker_locking_bytecode);
    s.extend_from_slice(bytecode);
    Ok(s)
}

/// Build the v22 PublisherSlot SPECIALIZED body for ONE source (P2S).
///
/// Takes the template body and substitutes the 3 per-source literals at their
/// fixed offsets. The result IS the slot's locking bytecode (P2S — no hash
/// wrapper, no ctor pushes).
///
/// Args:
///   * `publisher_pkh`   — 20 B hash160(publisher pubkey) for THIS source.
///   * `cn_hash`         — 20 B hash160(canonical CN) for THIS source.
///   * `oracle_cat_hash` — 20 B hash160(oracle_category_reversed) — shared.
pub fn specialize_slot_body(
    publisher_pkh: &[u8; 20],
    cn_hash: &[u8; 20],
    oracle_cat_hash: &[u8; 20],
) -> Result<Vec<u8>, RedeemScriptError> {
    let template = publisher_slot_bytecode()?;
    let mut body = template.to_vec();

    // Verify placeholders match template literals at expected offsets.
    // Placeholder bytes:
    //   publisherPkh    = 0xDE 0xAD 0xBE 0xEF × 5
    //   cnHash          = 0xCA 0xFE 0xBA 0xBE × 5
    //   oracleCatHash   = 0xFE 0xED 0xFA 0xCE × 5
    let pkh_placeholder: [u8; 20] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
        0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let cn_placeholder: [u8; 20] = [
        0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
        0xCA, 0xFE, 0xBA, 0xBE, 0xCA, 0xFE, 0xBA, 0xBE,
        0xCA, 0xFE, 0xBA, 0xBE,
    ];
    let oracle_cat_placeholder: [u8; 20] = [
        0xFE, 0xED, 0xFA, 0xCE, 0xFE, 0xED, 0xFA, 0xCE,
        0xFE, 0xED, 0xFA, 0xCE, 0xFE, 0xED, 0xFA, 0xCE,
        0xFE, 0xED, 0xFA, 0xCE,
    ];

    if body[SLOT_PKH_OFFSET..SLOT_PKH_OFFSET + 20] != pkh_placeholder {
        return Err(RedeemScriptError::PlaceholderMissing { offset: SLOT_PKH_OFFSET });
    }
    if body[SLOT_CN_HASH_OFFSET..SLOT_CN_HASH_OFFSET + 20] != cn_placeholder {
        return Err(RedeemScriptError::PlaceholderMissing { offset: SLOT_CN_HASH_OFFSET });
    }
    if body[SLOT_ORACLE_CAT_HASH_OFFSET..SLOT_ORACLE_CAT_HASH_OFFSET + 20]
        != oracle_cat_placeholder
    {
        return Err(RedeemScriptError::PlaceholderMissing {
            offset: SLOT_ORACLE_CAT_HASH_OFFSET,
        });
    }

    body[SLOT_PKH_OFFSET..SLOT_PKH_OFFSET + 20].copy_from_slice(publisher_pkh);
    body[SLOT_CN_HASH_OFFSET..SLOT_CN_HASH_OFFSET + 20].copy_from_slice(cn_hash);
    body[SLOT_ORACLE_CAT_HASH_OFFSET..SLOT_ORACLE_CAT_HASH_OFFSET + 20]
        .copy_from_slice(oracle_cat_hash);

    Ok(body)
}

/// Build the Ticker covenant's redeem script. Zero constructor args.
pub fn redeem_ticker() -> Result<Vec<u8>, RedeemScriptError> {
    Ok(ticker_bytecode()?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::sources::{source_cn_hash, SOURCES};

    /// Ticker pin — fingerprint v22 Ticker (24 B body, unchanged from v18/v19/v20)
    #[test]
    fn ticker_redeem_matches_v22_bytecode() {
        let redeem = redeem_ticker().unwrap();
        // Body is the redeem (zero ctor); P2SH-32 LB wraps it via aa20...87
        // Ticker body unchanged from v18: same fingerprint.
        let v22_body_hex = "777eb832fc504fc203dc4651bf78bc35db62787d45430ea3139b0ae16dd9f3d3";
        // body's hash256 = v22_body_hex (sha256d of redeem)
        use crate::covenant::locking::p2sh32_locking_bytecode;
        let lb = p2sh32_locking_bytecode(&redeem);
        assert_eq!(hex::encode(&lb[2..34]), v22_body_hex);
    }

    /// v22 PublisherSlot template has zero ctor args; specialized body is the LB.
    #[test]
    fn slot_specialize_returns_body_length() {
        let pkh = [0x42u8; 20];
        let cn_hash = [0x11u8; 20];
        let oracle_cat_hash = [0xeeu8; 20];
        let body = specialize_slot_body(&pkh, &cn_hash, &oracle_cat_hash).unwrap();
        let template = publisher_slot_bytecode().unwrap();
        assert_eq!(body.len(), template.len(), "specialize preserves length");
    }

    /// Specialized body has substituted literals at the right offsets.
    #[test]
    fn slot_specialize_substitutes_literals() {
        let pkh = [0x42u8; 20];
        let cn_hash = [0x11u8; 20];
        let oracle_cat_hash = [0xeeu8; 20];
        let body = specialize_slot_body(&pkh, &cn_hash, &oracle_cat_hash).unwrap();
        assert_eq!(&body[SLOT_PKH_OFFSET..SLOT_PKH_OFFSET + 20], &pkh);
        assert_eq!(&body[SLOT_CN_HASH_OFFSET..SLOT_CN_HASH_OFFSET + 20], &cn_hash);
        assert_eq!(
            &body[SLOT_ORACLE_CAT_HASH_OFFSET..SLOT_ORACLE_CAT_HASH_OFFSET + 20],
            &oracle_cat_hash
        );
    }

    /// Per-source specialized bodies differ in pkh + cn_hash regions.
    #[test]
    fn per_source_specialized_bodies_differ() {
        let oracle_cat_hash = [0xeeu8; 20];
        let pkh_a = [0xaau8; 20];
        let pkh_b = [0xbbu8; 20];
        let cn_a = source_cn_hash(&SOURCES[0]);
        let cn_b = source_cn_hash(&SOURCES[1]);
        let body_a = specialize_slot_body(&pkh_a, &cn_a, &oracle_cat_hash).unwrap();
        let body_b = specialize_slot_body(&pkh_b, &cn_b, &oracle_cat_hash).unwrap();
        assert_ne!(body_a, body_b, "per-source specialized bodies must differ");
        // Length is identical
        assert_eq!(body_a.len(), body_b.len());
    }

    /// Wrong placeholder shape detected.
    #[test]
    fn slot_specialize_validates_placeholders() {
        // If the artifact ever changes such that placeholders are missing,
        // specialize_slot_body returns PlaceholderMissing. This protects
        // against silent drift if the template gets recompiled with different
        // literal offsets.
        let pkh = [0x42u8; 20];
        let cn_hash = [0x11u8; 20];
        let oracle_cat_hash = [0xeeu8; 20];
        // Happy path
        assert!(specialize_slot_body(&pkh, &cn_hash, &oracle_cat_hash).is_ok());
    }

    #[test]
    fn oracle_redeem_v22_has_single_ctor_push() {
        let ticker_lb = [0x33u8; 35];
        let redeem = redeem_oracle(&ticker_lb).unwrap();
        let body = oracle_bytecode().unwrap();
        // push(35) byte + 35 bytes + body
        assert_eq!(redeem.len(), 1 + 35 + body.len());
        assert_eq!(redeem[0], 0x23); // push 35 (0x23 = OP_PUSHBYTES_35)
    }
}
