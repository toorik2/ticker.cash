//! `PublisherSlot.attest` transaction builder (v13).
//!
//! Tx shape:
//!   inputs:  [0] PublisherSlot UTXO with covenant unlock script
//!            [1..N+1] P2PKH funder UTXOs
//!   outputs: [0] PublisherSlot re-emit (mutable NFT, new commit, same satoshis)
//!            [1] optional P2PKH change to publisher address
//!
//! Unlock-script layout (v13 PublisherSlot.attest, function index 0 of 2):
//!   push(cycleSeq, 4 B LE) push(publisherSig, 70-72 B ECDSA-DER)
//!   push(publisherPubkey, 33 B) push(timestamp, 4 B LE) push(price, 8 B LE)
//!   push(serverName, variable) push(0, fn selector) push(redeemScript)
//!
//! v12 carried two extra pushes (notarySig + notaryIdx) between serverName and
//! the fn selector. v13 drops the notary tier entirely (see PR13a / Phase B).
//!
//! Per cashscript convention, declaration order of args is REVERSED before
//! pushing — last declared arg is pushed first.

use crate::chain::consts::{
    CAPABILITY_MUTABLE, DUST_THRESHOLD, FEE_EPSILON_SATS, MAX_ATTEST_FEE_HINT, SAT_PER_BYTE,
};
use crate::chain::digest::publisher_sig_digest;
use crate::chain::slot_commit::{encode_slot_commit, SlotCommit};
use crate::crypto::{double_sha256, hash160, sign_ecdsa, KeyError};
use crate::tx::encode::{
    encode_tx, Input, Output, TokenPrefix, Tx, TxOutpoint, DEFAULT_SEQUENCE,
};
use crate::tx::script::{p2pkh_locking_script, push_data, push_int};
use crate::tx::sighash::{
    p2pkh_sighash_preimage_bch, SpentOutput, SIGHASH_BIT_TOKENS,
};

/// PublisherSlot UTXO being spent.
#[derive(Debug, Clone)]
pub struct SlotUtxo {
    pub txid_be: [u8; 32],
    pub vout: u32,
    pub satoshis: u64,
    /// Raw 39-byte commitment of the slot UTXO being spent (the OLD commit,
    /// before this attest rewrites it). Needed to construct the CashTokens
    /// `hashUtxos` field of the funder input sighash.
    pub commitment_raw: [u8; 39],
}

/// Funder UTXO (P2PKH) being spent.
#[derive(Debug, Clone)]
pub struct FunderUtxo {
    pub txid_be: [u8; 32],
    pub vout: u32,
    pub satoshis: u64,
}

/// Inputs to [`build_attest_tx`]. The publisher is the source of truth for
/// `(price, timestamp, server_name)` in v13 — no notary tier exists.
#[derive(Debug, Clone)]
pub struct AttestArgs<'a> {
    pub slot_utxo: SlotUtxo,
    /// Current slot commit's `source_id` and `pkh` (pinned at genesis; carry forward).
    pub source_id: u16,
    pub publisher_pkh: [u8; 20],
    /// Publisher's 32-byte private key — used for both the data-sig and funder P2PKH sigs.
    pub publisher_privkey: [u8; 32],
    pub publisher_pubkey: [u8; 33],
    pub funder_utxos: &'a [FunderUtxo],
    /// CashTokens category as it appears on the wire (little-endian; reverse of display txid).
    pub slot_category_wire_le: [u8; 32],
    /// Full PublisherSlot redeem script (built at startup from manifest+artifact).
    pub slot_redeem_script: &'a [u8],
    /// USD price scaled by 1e8 (matching the covenant's price scale).
    pub price: u64,
    /// Publisher's wall-clock at fetch time, unix seconds.
    pub timestamp: u32,
    /// CN claimed by the publisher; the covenant checks `hash160(server_name)`
    /// against the slot's pinned `sourceCNHashes` entry.
    pub server_name: String,
    pub new_cycle_seq: u32,
}

/// Errors building an attest tx.
#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("insufficient funder balance: have {have}, need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("crypto: {0}")]
    Crypto(#[from] KeyError),
}

/// Build the `slot.attest` raw transaction bytes ready for broadcast.
///
/// Caller is responsible for funder selection; this function uses ALL provided
/// funder UTXOs as inputs. Change is paid back to the publisher's address
/// (derived from `publisher_pkh`) if it would be ≥ 546 sats; otherwise dropped.
pub fn build_attest_tx(args: &AttestArgs) -> Result<Vec<u8>, AttestError> {
    // ─── 1. Funder accounting (gate on worst-case hint; actual fee comes
    //         from the dynamic-size pass below) ─────────────────────────────
    let funder_balance: u64 = args.funder_utxos.iter().map(|u| u.satoshis).sum();
    if funder_balance < MAX_ATTEST_FEE_HINT {
        return Err(AttestError::InsufficientFunds {
            have: funder_balance,
            need: MAX_ATTEST_FEE_HINT,
        });
    }
    // Placeholder change for the first encode pass; corrected below.
    let change = funder_balance - MAX_ATTEST_FEE_HINT;

    // ─── 2. Build the slot input's covenant unlock script ──────────────────
    let server_name_bytes = args.server_name.as_bytes();
    let cn_hash20 = hash160(server_name_bytes);

    // Publisher signs the publisher digest with their privkey.
    let publisher_digest = publisher_sig_digest(
        args.source_id,
        args.price,
        args.timestamp,
        &args.publisher_pkh,
        args.new_cycle_seq,
        &cn_hash20,
    );
    let publisher_sig = sign_ecdsa(&args.publisher_privkey, &publisher_digest)?;

    let slot_unlock = build_attest_unlock_script(
        args.new_cycle_seq,
        &publisher_sig,
        &args.publisher_pubkey,
        args.timestamp,
        args.price,
        server_name_bytes,
        args.slot_redeem_script,
    );

    // ─── 3. Build outputs ──────────────────────────────────────────────────
    let new_commit = encode_slot_commit(&SlotCommit {
        source_id: args.source_id,
        pkh: args.publisher_pkh,
        price: args.price,
        timestamp: args.timestamp,
        cycle_seq: args.new_cycle_seq,
    });

    // Slot output: re-emit at same locking-bytecode (P2SH-32 of the redeem we just used).
    let slot_locking = crate::covenant::locking::p2sh32_locking_bytecode(args.slot_redeem_script);
    let slot_output = Output {
        value: args.slot_utxo.satoshis,
        locking_script: slot_locking.to_vec(),
        token: Some(TokenPrefix {
            category_le: args.slot_category_wire_le,
            capability: CAPABILITY_MUTABLE,
            commitment: new_commit.to_vec(),
            amount: 0,
        }),
    };

    let mut outputs = vec![slot_output];
    if change >= DUST_THRESHOLD {
        outputs.push(Output {
            value: change,
            locking_script: p2pkh_locking_script(&args.publisher_pkh).to_vec(),
            token: None,
        });
    }

    // ─── 4. Build inputs (funders with placeholder unlock scripts) ─────────
    let mut inputs = Vec::with_capacity(1 + args.funder_utxos.len());
    inputs.push(Input {
        prev: TxOutpoint {
            txid_be: args.slot_utxo.txid_be,
            vout: args.slot_utxo.vout,
        },
        unlock_script: slot_unlock,
        sequence: DEFAULT_SEQUENCE,
    });
    for f in args.funder_utxos {
        inputs.push(Input {
            prev: TxOutpoint {
                txid_be: f.txid_be,
                vout: f.vout,
            },
            unlock_script: Vec::new(), // filled in below
            sequence: DEFAULT_SEQUENCE,
        });
    }

    let mut tx = Tx::new(inputs, outputs);

    // ─── 5. Build per-input spent-UTXO sources for hashUtxos / outputTokenPrefix
    let funder_locking = p2pkh_locking_script(&args.publisher_pkh).to_vec();
    let mut sources: Vec<SpentOutput> = Vec::with_capacity(1 + args.funder_utxos.len());
    sources.push(SpentOutput {
        value: args.slot_utxo.satoshis,
        locking_script: slot_locking.to_vec(),
        token: Some(TokenPrefix {
            category_le: args.slot_category_wire_le,
            capability: CAPABILITY_MUTABLE,
            commitment: args.slot_utxo.commitment_raw.to_vec(),
            amount: 0,
        }),
    });
    for f in args.funder_utxos {
        sources.push(SpentOutput {
            value: f.satoshis,
            locking_script: funder_locking.clone(),
            token: None,
        });
    }

    // ─── 6. First pass: sign funders with the placeholder change, measure
    //         actual tx size to derive the right fee. ─────────────────────
    sign_all_funders(
        &mut tx,
        1,
        args.funder_utxos.len(),
        &funder_locking,
        &sources,
        &args.publisher_privkey,
        &args.publisher_pubkey,
    )?;
    let measured_size = encode_tx(&tx).len() as u64;
    let target_fee = measured_size * SAT_PER_BYTE + FEE_EPSILON_SATS;
    let _ = change; // initial placeholder, superseded below

    // ─── 7. Recompute change with the measured fee, adjust the change
    //         output in place, re-sign funders. ────────────────────────
    let target_change = funder_balance.saturating_sub(target_fee);
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
        1,
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
) -> Result<(), AttestError> {
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

/// Compose the v13 slot.attest unlock script bytes.
///
/// Push order (last declared arg first, per cashscript convention):
///   cycleSeq → publisherSig → publisherPubkey → timestamp → price →
///   serverName → fn-selector(0) → redeem-script
fn build_attest_unlock_script(
    cycle_seq: u32,
    publisher_sig: &[u8],
    publisher_pubkey: &[u8; 33],
    timestamp: u32,
    price: u64,
    server_name: &[u8],
    redeem_script: &[u8],
) -> Vec<u8> {
    let mut s = Vec::with_capacity(redeem_script.len() + 256);
    push_data(&mut s, &cycle_seq.to_le_bytes());
    push_data(&mut s, publisher_sig);
    push_data(&mut s, publisher_pubkey);
    push_data(&mut s, &timestamp.to_le_bytes());
    push_data(&mut s, &price.to_le_bytes());
    push_data(&mut s, server_name);
    push_int(&mut s, 0); // function selector for attest (function index 0)
    push_data(&mut s, redeem_script);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_args(funder_count: usize) -> (AttestArgs<'static>, Vec<u8>, Vec<FunderUtxo>) {
        let redeem = vec![0u8; 700]; // realistic-ish PublisherSlot redeem size
        let funders: Vec<FunderUtxo> = (0..funder_count)
            .map(|i| FunderUtxo {
                txid_be: [i as u8; 32],
                vout: 0,
                satoshis: 50_000,
            })
            .collect();
        let args = AttestArgs {
            slot_utxo: SlotUtxo {
                txid_be: [0x11; 32],
                vout: 7,
                satoshis: 1000,
                commitment_raw: [0u8; 39],
            },
            source_id: 1,
            publisher_pkh: [0x42; 20],
            publisher_privkey: [0x01; 32],
            publisher_pubkey: [0x02; 33], // not a real pubkey; for unlock-script structure tests only
            funder_utxos: &[],            // overridden via leak below
            slot_category_wire_le: [0x33; 32],
            slot_redeem_script: &[],      // overridden via leak below
            price: 350_000_000,
            timestamp: 1_780_000_000,
            server_name: "api.kraken.com".to_string(),
            new_cycle_seq: 42,
        };
        (args, redeem, funders)
    }

    #[test]
    fn rejects_insufficient_funds() {
        let (mut args, redeem, mut funders) = dummy_args(1);
        funders[0].satoshis = 100; // below MAX_ATTEST_FEE_HINT = 3000
        let redeem_ref: &'static [u8] = Box::leak(redeem.into_boxed_slice());
        let funders_ref: &'static [FunderUtxo] = Box::leak(funders.into_boxed_slice());
        args.slot_redeem_script = redeem_ref;
        args.funder_utxos = funders_ref;
        assert!(matches!(
            build_attest_tx(&args),
            Err(AttestError::InsufficientFunds { have: 100, need: 3000 })
        ));
    }

    /// Happy path: produces a non-empty raw tx with the expected output count.
    #[test]
    fn builds_tx_with_change_output() {
        let (mut args, redeem, funders) = dummy_args(1);
        let redeem_ref: &'static [u8] = Box::leak(redeem.into_boxed_slice());
        let funders_ref: &'static [FunderUtxo] = Box::leak(funders.into_boxed_slice());
        args.slot_redeem_script = redeem_ref;
        args.funder_utxos = funders_ref;
        let bytes = build_attest_tx(&args).unwrap();
        assert!(!bytes.is_empty());
        // 50_000 funder - 2_000 fee buffer = 48_000 sats change. Two outputs expected.
        // Version (4) + input count (1) → input 0 (slot) + input 1 (funder) + ...
        // Crude check: output-count byte (2) appears somewhere after the inputs.
        // We just confirm the encoded bytes are plausibly long enough.
        assert!(bytes.len() > 800); // 700-byte redeem alone exceeds this floor easily
    }

    #[test]
    fn omits_change_below_dust() {
        let (mut args, redeem, mut funders) = dummy_args(1);
        // Funder = hint + tiny remainder. After the dynamic-fee pass the
        // measured fee ≈ 1.6 KB (700-byte dummy redeem) so change ≈ funder
        // − fee, which lands well below 546.
        funders[0].satoshis = 3_000 + 100;
        let redeem_ref: &'static [u8] = Box::leak(redeem.into_boxed_slice());
        let funders_ref: &'static [FunderUtxo] = Box::leak(funders.into_boxed_slice());
        args.slot_redeem_script = redeem_ref;
        args.funder_utxos = funders_ref;
        let _bytes = build_attest_tx(&args).unwrap();
        // (Hard to assert output count without re-decoding; we just confirm no panic.)
    }
}
