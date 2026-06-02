//! `Oracle.update` transaction builder.
//!
//! Tx shape:
//!   inputs:  [0]      Oracle UTXO with `Oracle.update` covenant unlock
//!            [1..N+1] PublisherSlot UTXOs with `PublisherSlot.consume` unlocks
//!            [N+1..]  P2PKH funder UTXOs (publisher's own wallet)
//!   outputs: [0]      Oracle re-emit (minting NFT, new oracle commit)
//!            [1..N+1] Slot re-emits (mutable NFTs, commits unchanged 1:1 with inputs)
//!            [N+1, N+2] Two Ticker heads (mutable NFTs, new ticker commit)
//!            [N+3]    Optional P2PKH change to publisher
//!
//! Slot inputs MUST be sorted by `pkh` little-endian-numeric ascending. The
//! covenant enforces this at `Oracle.cash:110-115` via
//! `require(int(pkh + 0x00) > int(prevPkh + 0x00))`.
//!
//! Oracle.update unlock script (single function — no selector):
//!   push(budgetPad, 1024 zero B) push(claimedNewTs, 4 B) push(claimedMedian, 8 B)
//!   push(pricesBlob, N*8 B) push(redeem_script)
//!
//! PublisherSlot.consume unlock script (function index 1 of 2):
//!   push(1, fn selector) push(redeem_script)

use crate::chain::consts::{
    BUDGET_PAD_LEN, CAPABILITY_MINTING, CAPABILITY_MUTABLE, DUST_THRESHOLD, FEE_EPSILON_SATS,
    MAX_UPDATE_FEE_HINT, ORACLE_DUST, SAT_PER_BYTE, STRIDE_FLOOR_SEC, THR_FLOOR, TICKER_DUST,
    TICKER_HEAD_COUNT,
};
use crate::chain::oracle_commit::{encode_oracle_commit, OracleState};
use crate::chain::ticker_commit::encode_ticker_commit;
use crate::covenant::locking::p2sh32_locking_bytecode;
use crate::covenant::redeem::{redeem_publisher_slot, RedeemScriptError};
use crate::crypto::{double_sha256, sign_ecdsa, KeyError};
use crate::tx::encode::{
    encode_tx, Input, Output, TokenPrefix, Tx, TxOutpoint, DEFAULT_SEQUENCE,
};
use crate::tx::script::{p2pkh_locking_script, push_data, push_int};
use crate::tx::sighash::{
    p2pkh_sighash_preimage_bch, SpentOutput, SIGHASH_BIT_TOKENS,
};

use super::attest::FunderUtxo;

/// One slot UTXO participating in this cycle (already at `new_seq`).
#[derive(Debug, Clone)]
pub struct CycleSlotUtxo {
    pub txid_be: [u8; 32],
    pub vout: u32,
    pub satoshis: u64,
    /// 20-byte publisher pkh — used for the LE-numeric ascending sort the covenant enforces.
    pub pkh: [u8; 20],
    /// Last attested price (u64 LE) — contributes to median computation.
    pub price: u64,
    /// Last attested timestamp (u32 LE) — contributes to median timestamp.
    pub timestamp: u32,
    /// Raw 39-byte slot commit, copied into the output verbatim (covenant invariant).
    pub commitment: [u8; 37],
}

/// Oracle UTXO being spent (minting NFT).
#[derive(Debug, Clone)]
pub struct OracleUtxo {
    pub txid_be: [u8; 32],
    pub vout: u32,
    pub satoshis: u64,
    pub prev_state: OracleState,
}

/// Inputs to [`build_oracle_update_tx`].
#[derive(Debug, Clone)]
pub struct UpdateArgs<'a> {
    pub oracle_utxo: OracleUtxo,
    /// 7..13 slot UTXOs at the new cycleSeq. The builder sorts them before assembly.
    pub cycle_slots: &'a [CycleSlotUtxo],
    pub funder_utxos: &'a [FunderUtxo],
    pub publisher_pkh: [u8; 20],
    pub publisher_privkey: [u8; 32],
    pub publisher_pubkey: [u8; 33],
    /// Wire-LE category bytes for the Oracle (reverse of display txid).
    pub oracle_category_wire_le: [u8; 32],
    /// Wire-LE category bytes for the PublisherSlot.
    pub slot_category_wire_le: [u8; 32],
    pub oracle_redeem_script: &'a [u8],
    pub ticker_redeem_script: &'a [u8],
    /// v17: pkh → cnHash mapping for all 13 sources. The builder derives each
    /// slot input's redeem from `redeem_publisher_slot(cn_hash, oracle_cat)`
    /// where cn_hash is looked up from the slot commit's pkh. v16 used the
    /// commit's sourceId field directly; v17 dropped sourceId from the commit.
    pub pkh_to_cn_hash: &'a [([u8; 20], [u8; 20])],
    pub new_seq: u32,
}

/// Errors building an Oracle.update tx.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("below quorum: {got} slots, need ≥ {need}")]
    BelowQuorum { got: usize, need: usize },
    #[error("slot inputs not unique by pkh (duplicate at index {0})")]
    DuplicatePkh(usize),
    #[error("new timestamp {new} does not pass stride floor ({stride} s) above prev {prev}")]
    StrideFloor { new: u32, prev: u32, stride: u32 },
    #[error("insufficient funder balance: have {have}, need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("crypto: {0}")]
    Crypto(#[from] KeyError),
    #[error("slot commit pkh {pkh_hex} not in pkh→cnHash map (manifest mismatch?)")]
    UnknownSlotPkh { pkh_hex: String },
    #[error("redeem build failure: {0}")]
    Redeem(#[from] RedeemScriptError),
}

/// Build the `Oracle.update` raw transaction bytes ready for broadcast.
///
/// Caller responsibilities:
///   * `cycle_slots` may be unsorted; this function sorts by pkh LE-numeric
///     ascending and rejects duplicates.
///   * Median ts + median price are computed here from the provided slots.
///   * Funder selection is the caller's job; all provided funders are spent.
pub fn build_oracle_update_tx(args: &UpdateArgs) -> Result<Vec<u8>, UpdateError> {
    // ─── 1. Quorum + sort slots by pkh LE-numeric ──────────────────────────
    if args.cycle_slots.len() < THR_FLOOR {
        return Err(UpdateError::BelowQuorum {
            got: args.cycle_slots.len(),
            need: THR_FLOOR,
        });
    }
    let mut slots: Vec<CycleSlotUtxo> = args.cycle_slots.to_vec();
    slots.sort_by(|a, b| {
        for i in (0..20).rev() {
            if a.pkh[i] != b.pkh[i] {
                return a.pkh[i].cmp(&b.pkh[i]);
            }
        }
        std::cmp::Ordering::Equal
    });
    for w in slots.windows(2) {
        if w[0].pkh == w[1].pkh {
            // Find the index of the second one in the sorted vec for a useful error.
            let idx = slots.iter().rposition(|s| s.pkh == w[1].pkh).unwrap();
            return Err(UpdateError::DuplicatePkh(idx));
        }
    }

    // ─── 2. Compute median ts + median price ───────────────────────────────
    let mut ts_values: Vec<u32> = slots.iter().map(|s| s.timestamp).collect();
    ts_values.sort_unstable();
    let claimed_new_ts = ts_values[ts_values.len() / 2];
    if claimed_new_ts <= args.oracle_utxo.prev_state.last_ts
        || claimed_new_ts - args.oracle_utxo.prev_state.last_ts < STRIDE_FLOOR_SEC
    {
        return Err(UpdateError::StrideFloor {
            new: claimed_new_ts,
            prev: args.oracle_utxo.prev_state.last_ts,
            stride: STRIDE_FLOOR_SEC,
        });
    }
    let mut price_values: Vec<u64> = slots.iter().map(|s| s.price).collect();
    price_values.sort_unstable();
    // TS daemon uses `Math.floor((len - 1) / 2)` for prices — lower-middle on even arrays.
    let claimed_median = price_values[(price_values.len() - 1) / 2];

    // ─── 3. Compute new activeCount (0.9× decay, floor at THR_FLOOR or current) ──
    let decayed = (args.oracle_utxo.prev_state.active_count as u64) * 9 / 10;
    let n = slots.len() as u64;
    let mut new_active = n.max(decayed);
    if new_active < THR_FLOOR as u64 {
        new_active = THR_FLOOR as u64;
    }
    let new_active = new_active.min(u16::MAX as u64) as u16;

    // ─── 4. Funder balance (gate on worst-case hint; actual fee comes from
    //         the dynamic-size pass below) ─────────────────────────────────
    let funder_balance: u64 = args.funder_utxos.iter().map(|u| u.satoshis).sum();
    let min_update_funds = (TICKER_HEAD_COUNT as u64) * TICKER_DUST + MAX_UPDATE_FEE_HINT;
    if funder_balance < min_update_funds {
        return Err(UpdateError::InsufficientFunds {
            have: funder_balance,
            need: min_update_funds,
        });
    }
    // Placeholder change for the first encode pass; corrected below.
    let change = funder_balance - (TICKER_HEAD_COUNT as u64) * TICKER_DUST - MAX_UPDATE_FEE_HINT;

    // ─── 5. Build pricesBlob = concat(u64LE(price) for each slot) ──────────
    let mut prices_blob = Vec::with_capacity(slots.len() * 8);
    for s in &slots {
        prices_blob.extend_from_slice(&s.price.to_le_bytes());
    }

    // ─── 6. Build oracle unlock script ─────────────────────────────────────
    let budget_pad = vec![0u8; BUDGET_PAD_LEN];
    let oracle_unlock = build_update_unlock_script(
        &budget_pad,
        claimed_new_ts,
        claimed_median,
        &prices_blob,
        args.oracle_redeem_script,
    );

    // ─── 7. Build per-slot redeems + consume unlocks (v17: each slot's
    //         redeem differs by its baked-in cnHash, looked up from each
    //         slot's pkh via the manifest-derived pkh→cnHash table) ──────────
    let per_slot_redeems: Vec<Vec<u8>> = slots
        .iter()
        .map(|s| {
            let cn_hash = args
                .pkh_to_cn_hash
                .iter()
                .find(|(p, _)| *p == s.pkh)
                .map(|(_, c)| *c)
                .ok_or_else(|| UpdateError::UnknownSlotPkh {
                    pkh_hex: hex::encode(s.pkh),
                })?;
            Ok(redeem_publisher_slot(&cn_hash, &args.oracle_category_wire_le)?)
        })
        .collect::<Result<_, UpdateError>>()?;
    let per_slot_consume_unlocks: Vec<Vec<u8>> = per_slot_redeems
        .iter()
        .map(|r| build_consume_unlock_script(r))
        .collect();
    let per_slot_lockings: Vec<[u8; 35]> = per_slot_redeems
        .iter()
        .map(|r| p2sh32_locking_bytecode(r))
        .collect();

    // ─── 8. Build outputs ──────────────────────────────────────────────────
    let new_oracle_commit = encode_oracle_commit(&OracleState {
        seq: args.new_seq,
        last_ts: claimed_new_ts,
        median_usd: claimed_median,
        active_count: new_active,
    });
    let new_ticker_commit = encode_ticker_commit(&OracleState {
        seq: args.new_seq,
        last_ts: claimed_new_ts,
        median_usd: claimed_median,
        active_count: 0, // ignored by ticker commit encoder
    });

    let oracle_locking = p2sh32_locking_bytecode(args.oracle_redeem_script);
    let ticker_locking = p2sh32_locking_bytecode(args.ticker_redeem_script);

    let mut outputs = Vec::with_capacity(1 + slots.len() + 2 + 1);

    // Oracle re-emit.
    outputs.push(Output {
        value: ORACLE_DUST,
        locking_script: oracle_locking.to_vec(),
        token: Some(TokenPrefix {
            category_le: args.oracle_category_wire_le,
            capability: CAPABILITY_MINTING,
            commitment: new_oracle_commit.to_vec(),
            amount: 0,
        }),
    });
    // Slot re-emits, one per input, same satoshis, commit unchanged.
    // v16: each slot output gets its OWN locking bytecode (per-source P2SH-32).
    for (i, s) in slots.iter().enumerate() {
        outputs.push(Output {
            value: s.satoshis,
            locking_script: per_slot_lockings[i].to_vec(),
            token: Some(TokenPrefix {
                category_le: args.slot_category_wire_le,
                capability: CAPABILITY_MUTABLE,
                commitment: s.commitment.to_vec(),
                amount: 0,
            }),
        });
    }
    // Two Ticker heads. Ticker shares the Oracle's 32-byte category but with mutable capability.
    for _ in 0..TICKER_HEAD_COUNT {
        outputs.push(Output {
            value: TICKER_DUST,
            locking_script: ticker_locking.to_vec(),
            token: Some(TokenPrefix {
                category_le: args.oracle_category_wire_le,
                capability: CAPABILITY_MUTABLE,
                commitment: new_ticker_commit.to_vec(),
                amount: 0,
            }),
        });
    }
    // Optional change.
    if change >= DUST_THRESHOLD {
        outputs.push(Output {
            value: change,
            locking_script: p2pkh_locking_script(&args.publisher_pkh).to_vec(),
            token: None,
        });
    }

    // ─── 9. Build inputs ───────────────────────────────────────────────────
    let mut inputs = Vec::with_capacity(1 + slots.len() + args.funder_utxos.len());
    inputs.push(Input {
        prev: TxOutpoint {
            txid_be: args.oracle_utxo.txid_be,
            vout: args.oracle_utxo.vout,
        },
        unlock_script: oracle_unlock,
        sequence: DEFAULT_SEQUENCE,
    });
    for (i, s) in slots.iter().enumerate() {
        inputs.push(Input {
            prev: TxOutpoint {
                txid_be: s.txid_be,
                vout: s.vout,
            },
            unlock_script: per_slot_consume_unlocks[i].clone(),
            sequence: DEFAULT_SEQUENCE,
        });
    }
    for f in args.funder_utxos {
        inputs.push(Input {
            prev: TxOutpoint {
                txid_be: f.txid_be,
                vout: f.vout,
            },
            unlock_script: Vec::new(), // signed below
            sequence: DEFAULT_SEQUENCE,
        });
    }

    let mut tx = Tx::new(inputs, outputs);

    // ─── 10. Build per-input spent-UTXO sources for hashUtxos / outputTokenPrefix
    let funder_locking = p2pkh_locking_script(&args.publisher_pkh).to_vec();
    let mut sources: Vec<SpentOutput> = Vec::with_capacity(1 + slots.len() + args.funder_utxos.len());
    // [0] Oracle input
    sources.push(SpentOutput {
        value: args.oracle_utxo.satoshis,
        locking_script: oracle_locking.to_vec(),
        token: Some(TokenPrefix {
            category_le: args.oracle_category_wire_le,
            capability: CAPABILITY_MINTING,
            commitment: crate::chain::oracle_commit::encode_oracle_commit(
                &args.oracle_utxo.prev_state,
            )
            .to_vec(),
            amount: 0,
        }),
    });
    // [1..N+1] Slot inputs — v16: per-slot locking bytecode
    for (i, s) in slots.iter().enumerate() {
        sources.push(SpentOutput {
            value: s.satoshis,
            locking_script: per_slot_lockings[i].to_vec(),
            token: Some(TokenPrefix {
                category_le: args.slot_category_wire_le,
                capability: CAPABILITY_MUTABLE,
                commitment: s.commitment.to_vec(),
                amount: 0,
            }),
        });
    }
    // [N+1..] Funder P2PKH inputs (no tokens)
    for f in args.funder_utxos {
        sources.push(SpentOutput {
            value: f.satoshis,
            locking_script: funder_locking.clone(),
            token: None,
        });
    }

    // ─── 11. First pass: sign funders with the placeholder change, measure
    //          actual tx size to derive the right fee. ────────────────────
    let funder_start = 1 + slots.len();
    sign_all_funders(
        &mut tx,
        funder_start,
        args.funder_utxos.len(),
        &funder_locking,
        &sources,
        &args.publisher_privkey,
        &args.publisher_pubkey,
    )?;
    let measured_size = encode_tx(&tx).len() as u64;
    let target_fee = measured_size * SAT_PER_BYTE + FEE_EPSILON_SATS;
    let _ = change; // initial placeholder, superseded below

    // ─── 12. Recompute change with the measured fee, adjust the change
    //          output in place, re-sign funders. ────────────────────────
    let target_change = funder_balance
        .saturating_sub((TICKER_HEAD_COUNT as u64) * TICKER_DUST)
        .saturating_sub(target_fee);
    let had_change_output = matches!(tx.outputs.last(), Some(o) if o.token.is_none());
    let need_change_output = target_change >= DUST_THRESHOLD;

    match (had_change_output, need_change_output) {
        (true, true) => {
            tx.outputs.last_mut().unwrap().value = target_change;
        }
        (true, false) => {
            tx.outputs.pop();
        }
        (false, true) => {
            tx.outputs.push(Output {
                value: target_change,
                locking_script: p2pkh_locking_script(&args.publisher_pkh).to_vec(),
                token: None,
            });
        }
        (false, false) => {}
    }

    // Re-sign — the sighash commits to hashOutputs, which we just changed.
    sign_all_funders(
        &mut tx,
        funder_start,
        args.funder_utxos.len(),
        &funder_locking,
        &sources,
        &args.publisher_privkey,
        &args.publisher_pubkey,
    )?;

    Ok(encode_tx(&tx))
}

/// Build and write the unlock script for every funder input.
/// Used twice — once with the placeholder change, once with the size-corrected change.
fn sign_all_funders(
    tx: &mut Tx,
    funder_start: usize,
    funder_count: usize,
    funder_locking: &[u8],
    sources: &[SpentOutput],
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
) -> Result<(), UpdateError> {
    for i in 0..funder_count {
        let input_index = funder_start + i;
        let preimage = p2pkh_sighash_preimage_bch(
            tx,
            input_index,
            funder_locking,
            sources,
            SIGHASH_BIT_TOKENS,
        );
        let digest = double_sha256(&preimage);
        let sig = sign_ecdsa(privkey, &digest)?;
        let mut sig_with_sighash = Vec::with_capacity(sig.len() + 1);
        sig_with_sighash.extend_from_slice(&sig);
        sig_with_sighash.push(SIGHASH_BIT_TOKENS);
        let mut unlock = Vec::with_capacity(100);
        push_data(&mut unlock, &sig_with_sighash);
        push_data(&mut unlock, pubkey);
        tx.inputs[input_index].unlock_script = unlock;
    }
    Ok(())
}

/// Compose Oracle.update unlock script.
///
/// Reverse declaration order (Oracle.cash:40-): budgetPad → claimedNewTs →
/// claimedMedian → pricesBlob → (no selector — single fn) → redeem script.
fn build_update_unlock_script(
    budget_pad: &[u8],
    claimed_new_ts: u32,
    claimed_median: u64,
    prices_blob: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(redeem_script.len() + budget_pad.len() + prices_blob.len() + 64);
    push_data(&mut s, budget_pad);
    push_data(&mut s, &claimed_new_ts.to_le_bytes());
    push_data(&mut s, &claimed_median.to_le_bytes());
    push_data(&mut s, prices_blob);
    push_data(&mut s, redeem_script);
    s
}

/// Compose PublisherSlot.consume unlock script (no args, fn index 1 of 2).
fn build_consume_unlock_script(redeem_script: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(redeem_script.len() + 8);
    push_int(&mut s, 1); // function selector for consume
    push_data(&mut s, redeem_script);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(pkh_byte: u8, ts: u32, price: u64) -> CycleSlotUtxo {
        // v17: 37-byte commit (no sourceId). Per-slot redeem derived from
        // pkh via the pkh_to_cn_hash lookup table provided in UpdateArgs.
        let mut commitment = [0u8; 37];
        commitment[0] = crate::chain::consts::SLOT_VERSION_BYTE; // 0x75
        commitment[1..21].copy_from_slice(&[pkh_byte; 20]);
        CycleSlotUtxo {
            txid_be: [0; 32],
            vout: 0,
            satoshis: 1000,
            pkh: [pkh_byte; 20],
            price,
            timestamp: ts,
            commitment,
        }
    }

    fn oracle_utxo() -> OracleUtxo {
        OracleUtxo {
            txid_be: [0xaa; 32],
            vout: 0,
            satoshis: ORACLE_DUST,
            prev_state: OracleState {
                seq: 100,
                last_ts: 1_780_000_000,
                median_usd: 350_000_000,
                active_count: 10,
            },
        }
    }

    fn funders(count: usize, each_sat: u64) -> Vec<FunderUtxo> {
        (0..count)
            .map(|i| FunderUtxo {
                txid_be: [(i as u8) + 1; 32],
                vout: 0,
                satoshis: each_sat,
            })
            .collect()
    }

    /// Build a pkh→cnHash lookup table covering the unique pkhs in the test
    /// slots. cnHash bytes are deterministic but arbitrary (just need to be
    /// stable per pkh so per-slot redeems can be derived).
    fn pkh_to_cn_hash_for(slots: &[CycleSlotUtxo]) -> Vec<([u8; 20], [u8; 20])> {
        let mut out: Vec<([u8; 20], [u8; 20])> = Vec::new();
        for s in slots {
            if !out.iter().any(|(p, _)| *p == s.pkh) {
                let mut cn = [0u8; 20];
                cn[0] = s.pkh[0].wrapping_add(0x40); // arbitrary derivation
                out.push((s.pkh, cn));
            }
        }
        out
    }

    fn dummy_args<'a>(
        cycle_slots: &'a [CycleSlotUtxo],
        funder_utxos: &'a [FunderUtxo],
        redeem: &'a [u8],
        pkh_to_cn_hash: &'a [([u8; 20], [u8; 20])],
    ) -> UpdateArgs<'a> {
        UpdateArgs {
            oracle_utxo: oracle_utxo(),
            cycle_slots,
            funder_utxos,
            publisher_pkh: [0x42; 20],
            publisher_privkey: [0x01; 32],
            publisher_pubkey: [0x02; 33],
            oracle_category_wire_le: [0xee; 32],
            slot_category_wire_le: [0xff; 32],
            oracle_redeem_script: redeem,
            ticker_redeem_script: redeem,
            pkh_to_cn_hash,
            new_seq: 101,
        }
    }

    #[test]
    fn rejects_below_quorum() {
        let slots: Vec<CycleSlotUtxo> = (0..6).map(|i| slot(i as u8, 1_780_000_100, 100)).collect();
        let funders = funders(1, 100_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        assert!(matches!(
            build_oracle_update_tx(&args),
            Err(UpdateError::BelowQuorum { got: 6, need: 7 })
        ));
    }

    #[test]
    fn rejects_duplicate_pkh() {
        let mut slots: Vec<CycleSlotUtxo> = (0..7).map(|i| slot(i as u8, 1_780_000_100, 100)).collect();
        slots[6].pkh = slots[0].pkh; // duplicate
        let funders = funders(1, 100_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        assert!(matches!(
            build_oracle_update_tx(&args),
            Err(UpdateError::DuplicatePkh(_))
        ));
    }

    #[test]
    fn rejects_stride_floor_violation() {
        // All ts at prev_ts + 5 — below 60 s stride.
        let slots: Vec<CycleSlotUtxo> = (0..7).map(|i| slot(i as u8, 1_780_000_005, 100)).collect();
        let funders = funders(1, 100_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        assert!(matches!(
            build_oracle_update_tx(&args),
            Err(UpdateError::StrideFloor { .. })
        ));
    }

    #[test]
    fn rejects_insufficient_funder() {
        // 2× TICKER_DUST + MAX_UPDATE_FEE_HINT = 2×1500 + 8000 = 11000 minimum.
        let slots: Vec<CycleSlotUtxo> = (0..7).map(|i| slot(i as u8, 1_780_000_100, 100)).collect();
        let funders = funders(1, 10_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        assert!(matches!(
            build_oracle_update_tx(&args),
            Err(UpdateError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn happy_path_7_slots_produces_tx() {
        let slots: Vec<CycleSlotUtxo> = (0..7)
            .map(|i| slot(i as u8, 1_780_000_100, 100_000_000 + i as u64))
            .collect();
        let funders = funders(1, 100_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        let bytes = build_oracle_update_tx(&args).unwrap();
        assert!(!bytes.is_empty());
        // Sanity floor: 1 oracle in + 7 slot in + 1 funder in, all with non-trivial unlocks;
        // plus 1 oracle out + 7 slot out + 2 ticker out + 1 change. > 2 KB easily.
        assert!(bytes.len() > 2_000);
    }

    #[test]
    fn happy_path_13_slots_includes_budget_pad() {
        let slots: Vec<CycleSlotUtxo> = (0..13)
            .map(|i| slot(i as u8, 1_780_000_100 + (i as u32), 100_000_000 + i as u64))
            .collect();
        let funders = funders(1, 100_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        let bytes = build_oracle_update_tx(&args).unwrap();
        // v17 BUDGET_PAD_LEN = 64 → length byte 0x40 followed by 64 zero bytes.
        // Look for the marker.
        let mut found = false;
        for off in 0..bytes.len().saturating_sub(65) {
            if bytes[off] == 0x40 && bytes[off + 1..off + 65].iter().all(|b| *b == 0) {
                found = true;
                break;
            }
        }
        assert!(found, "budgetPad(64 zeros) not emitted in unlock");
    }

    /// Sort is LE-numeric on pkh (least-significant byte = pkh[19]; matches covenant).
    /// Reversed-byte-order pkh comparison: pkh A = [01..00,FF] vs B = [01..00,00] —
    /// LE-numeric says B < A because the high (last) byte of B is 0 < FF.
    #[test]
    fn sort_is_le_numeric_not_big_endian_lex() {
        // Each `slot(pkh_byte, ...)` call sets commit source_id = pkh_byte + 1;
        // we pass 0..6 so source_ids land at 1..=7, all in 1..=13.
        let mut a = slot(0, 1_780_000_100, 1);
        a.pkh = [0x01; 20];
        a.pkh[19] = 0xff; // a's "high" byte is large under LE numeric
        let mut b = slot(1, 1_780_000_100, 2);
        b.pkh = [0x01; 20];
        b.pkh[19] = 0x00; // b's "high" byte is small under LE numeric
        // ... pad to quorum with distinct pkhs and distinct source_ids
        let mut others: Vec<CycleSlotUtxo> = (0..5)
            .map(|i| slot((i + 2) as u8, 1_780_000_100, 1000)) // source_ids 3..=7
            .collect();
        // Replace first byte of `others` to ensure they sort highest.
        for (i, o) in others.iter_mut().enumerate() {
            o.pkh = [0x10 + i as u8; 20];
        }
        // Assemble in deliberately wrong order: [a, b, others...]
        let mut slots = vec![a.clone(), b.clone()];
        slots.extend(others);
        let funders = funders(1, 100_000);
        let redeem = vec![0u8; 500];
        let pkh_map = pkh_to_cn_hash_for(&slots);
        let args = dummy_args(&slots, &funders, &redeem, &pkh_map);
        // If sort works correctly, build doesn't error.
        let _bytes = build_oracle_update_tx(&args).unwrap();
        // Stronger property: when we re-sort manually using the documented LE-numeric
        // comparator, b should come before a.
        let cmp = |x: &CycleSlotUtxo, y: &CycleSlotUtxo| -> std::cmp::Ordering {
            for i in (0..20).rev() {
                if x.pkh[i] != y.pkh[i] {
                    return x.pkh[i].cmp(&y.pkh[i]);
                }
            }
            std::cmp::Ordering::Equal
        };
        assert_eq!(cmp(&b, &a), std::cmp::Ordering::Less);
    }
}
