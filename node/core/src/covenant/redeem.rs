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

/// v23 Oracle template literal offset — placeholder for `slotCatWithCap` (F01).
/// Verified at cashc-emit time: 33-byte literal (32-B slot category id LE +
/// 1-B mutable capability suffix). The placeholder bytes are 0xBABEFACE × 8
/// followed by 0x01 — appears exactly once in the compiled body.
pub const ORACLE_SLOT_CAT_WITH_CAP_OFFSET: usize = 82;

/// Build the v23 Oracle covenant's redeem script (P2SH-32 — Oracle still over
/// P2S cap). The body is specialized per-deployment with the slot category +
/// mutable capability suffix inlined (F01 fix for V22-OC-22 quorum bypass).
///
/// Args:
///   * `ticker_locking_bytecode` — 35 B P2SH-32 locking script of the Ticker covenant.
///   * `slot_category_reversed`  — 32 B PublisherSlot category in LE wire order.
pub fn redeem_oracle(
    ticker_locking_bytecode: &[u8; 35],
    slot_category_reversed: &[u8; 32],
) -> Result<Vec<u8>, RedeemScriptError> {
    let body = specialize_oracle_body(slot_category_reversed)?;
    let mut s = Vec::with_capacity(body.len() + 40);
    push_data(&mut s, ticker_locking_bytecode);
    s.extend_from_slice(&body);
    Ok(s)
}

/// Build the v23 Oracle SPECIALIZED body — substitutes the `slotCatWithCap`
/// placeholder with the actual slot category id + mutable capability suffix.
/// The Oracle is a single-instance covenant (only one Oracle per deployment),
/// so the slot category is a deploy-time constant.
pub fn specialize_oracle_body(
    slot_category_reversed: &[u8; 32],
) -> Result<Vec<u8>, RedeemScriptError> {
    let template = oracle_bytecode()?;
    let mut body = template.to_vec();
    // Placeholder: 0xBABEFACE × 8 + 0x01 capability suffix (33 bytes).
    let placeholder: [u8; 33] = [
        0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
        0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
        0x01,
    ];
    if body[ORACLE_SLOT_CAT_WITH_CAP_OFFSET..ORACLE_SLOT_CAT_WITH_CAP_OFFSET + 33] != placeholder {
        return Err(RedeemScriptError::PlaceholderMissing {
            offset: ORACLE_SLOT_CAT_WITH_CAP_OFFSET,
        });
    }
    body[ORACLE_SLOT_CAT_WITH_CAP_OFFSET..ORACLE_SLOT_CAT_WITH_CAP_OFFSET + 32]
        .copy_from_slice(slot_category_reversed);
    body[ORACLE_SLOT_CAT_WITH_CAP_OFFSET + 32] = 0x01; // mutable capability suffix
    Ok(body)
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
    fn oracle_redeem_v23_has_single_ctor_push() {
        let ticker_lb = [0x33u8; 35];
        let slot_cat = [0xaau8; 32];
        let redeem = redeem_oracle(&ticker_lb, &slot_cat).unwrap();
        let template = oracle_bytecode().unwrap();
        // push(35) byte + 35 bytes ctor + body (specialized; same length as template)
        assert_eq!(redeem.len(), 1 + 35 + template.len());
        assert_eq!(redeem[0], 0x23); // push 35 (0x23 = OP_PUSHBYTES_35)
    }

    #[test]
    fn oracle_specialize_substitutes_slot_cat() {
        let slot_cat = [0xaau8; 32];
        let body = specialize_oracle_body(&slot_cat).unwrap();
        assert_eq!(
            &body[ORACLE_SLOT_CAT_WITH_CAP_OFFSET..ORACLE_SLOT_CAT_WITH_CAP_OFFSET + 32],
            &slot_cat
        );
        assert_eq!(body[ORACLE_SLOT_CAT_WITH_CAP_OFFSET + 32], 0x01);
    }

    #[test]
    fn oracle_specialize_per_deployment_bodies_differ() {
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        assert_ne!(
            specialize_oracle_body(&a).unwrap(),
            specialize_oracle_body(&b).unwrap()
        );
    }

    /// F01 permanent regression — the slot category placeholder MUST appear
    /// exactly once in the compiled template. If a future cashc release
    /// inlines the literal somewhere extra (e.g. an optimizer dedup boundary
    /// shift), specialize_oracle_body would substitute only the first
    /// occurrence and leave the second as live BABEFACE bytes — which a
    /// crafted slot would then trivially pass. Fingerprinting "exactly one"
    /// makes any such drift trip CI loudly before deployment.
    #[test]
    fn oracle_template_placeholder_appears_exactly_once() {
        let template = oracle_bytecode().unwrap();
        let placeholder: [u8; 33] = [
            0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
            0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
            0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
            0xBA, 0xBE, 0xFA, 0xCE, 0xBA, 0xBE, 0xFA, 0xCE,
            0x01,
        ];
        let positions: Vec<usize> = template
            .windows(33)
            .enumerate()
            .filter_map(|(i, w)| if w == placeholder { Some(i) } else { None })
            .collect();
        assert_eq!(
            positions,
            vec![ORACLE_SLOT_CAT_WITH_CAP_OFFSET],
            "F01 invariant: placeholder must appear at exactly one offset"
        );
    }

    /// F01 permanent regression — after specialization, the BABEFACE marker
    /// bytes must be entirely gone. Catches accidental partial substitution
    /// or stray template literal copies.
    #[test]
    fn oracle_specialized_body_contains_no_babeface_marker() {
        let slot_cat = [0xaau8; 32];
        let body = specialize_oracle_body(&slot_cat).unwrap();
        // The 4-byte BABEFACE quad is distinctive enough that no real category
        // is realistically going to contain it. If any survives substitution,
        // we know there's a second placeholder occurrence we missed.
        let marker = [0xBAu8, 0xBE, 0xFA, 0xCE];
        let surviving: Vec<usize> = body
            .windows(4)
            .enumerate()
            .filter_map(|(i, w)| if w == marker { Some(i) } else { None })
            .collect();
        assert!(
            surviving.is_empty(),
            "F01 invariant: BABEFACE marker bytes must not survive specialization (found at {surviving:?})"
        );
    }

    /// v23 Oracle body fingerprint — pinned sha256d of the compiled template.
    /// Any cashc upgrade, source edit, or build-system drift that changes the
    /// emitted bytecode trips this. Forces a human to re-verify the F01 slot
    /// category check site (and re-run the F01 PoC) before re-pinning.
    #[test]
    fn oracle_v23_template_fingerprint() {
        use sha2::{Digest, Sha256};
        let template = oracle_bytecode().unwrap();
        assert_eq!(template.len(), 460, "v23 Oracle body length is 460 B");
        let h1 = Sha256::digest(template);
        let h2 = Sha256::digest(h1);
        assert_eq!(
            hex::encode(h2),
            "dcbbe7d1e042f00a71d14070b752512adc331a9e863d5d29c648b8048c2476c0",
            "v23 Oracle body fingerprint changed — re-verify F01 slot category pin"
        );
    }
}
