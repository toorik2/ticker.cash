//! BIP-143-style sighash preimage for BCH with FORKID, extended for CashTokens.
//!
//! Two variants depending on the `SIGHASH_UTXOS` bit:
//!
//!   * Pre-CashTokens (sighash byte `0x41` = `SIGHASH_ALL | FORKID`):
//!     classic BIP-143 layout. Used by `ticker-ops fund` (no token UTXOs).
//!
//!   * CashTokens (sighash byte `0x61` = `SIGHASH_ALL | UTXOS | FORKID`):
//!     adds `hashUtxos` after `hashPrevouts`, and adds the spent UTXO's token
//!     prefix bytes after the outpoint (before `scriptCode`). Used by every
//!     transaction that spends any token UTXO — `slot.attest` and
//!     `Oracle.update` both qualify.
//!
//! Implementation mirrors libauth's `encodeSigningSerializationBch`:
//! `daemon/node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/common/signing-serialization.js`.

use crate::crypto::double_sha256;
use crate::tx::encode::{encode_varint, Tx};

/// SIGHASH_ALL.
pub const SIGHASH_ALL_BIP143: u8 = 0x01;

/// BCH FORKID bit.
pub const SIGHASH_FORKID: u8 = 0x40;

/// SIGHASH_UTXOS (CashTokens — commit to spent UTXOs' token state).
pub const SIGHASH_UTXOS: u8 = 0x20;

/// Pre-CashTokens sighash byte: SIGHASH_ALL | FORKID.
pub const SIGHASH_BIT: u8 = SIGHASH_ALL_BIP143 | SIGHASH_FORKID;

/// CashTokens sighash byte: SIGHASH_ALL | UTXOS | FORKID.
pub const SIGHASH_BIT_TOKENS: u8 = SIGHASH_ALL_BIP143 | SIGHASH_UTXOS | SIGHASH_FORKID;

/// The spent UTXO an input is consuming — needed to compute `hashUtxos` and the
/// per-input `outputTokenPrefix` field of the CashTokens sighash.
#[derive(Debug, Clone)]
pub struct SpentOutput {
    pub value: u64,
    pub locking_script: Vec<u8>,
    pub token: Option<crate::tx::encode::TokenPrefix>,
}

/// CashTokens token prefix wire bytes (matches `encode_output_script_with_token`
/// in `tx::encode` but exposed here so the sighash builder can produce them
/// without reaching across modules).
pub(super) fn encode_token_prefix_bytes(token: &crate::tx::encode::TokenPrefix) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 32 + 1 + token.commitment.len() + 9);
    out.push(0xef);
    out.extend_from_slice(&token.category_le);
    let mut bits: u8 = 0;
    let has_nft = token.capability != 0 || !token.commitment.is_empty();
    if has_nft {
        bits |= 0x20 | (token.capability & 0x0f);
    }
    let has_commit = !token.commitment.is_empty();
    if has_commit {
        bits |= 0x40;
    }
    let has_amount = token.amount > 0;
    if has_amount {
        bits |= 0x10;
    }
    out.push(bits);
    if has_commit {
        encode_varint(&mut out, token.commitment.len() as u64);
        out.extend_from_slice(&token.commitment);
    }
    if has_amount {
        encode_varint(&mut out, token.amount);
    }
    out
}

/// Encode one spent UTXO for inclusion in the `hashUtxos` preimage.
///
/// Format: `value(8 LE) || varint(L) || token_prefix || locking_script`
/// where `L = len(token_prefix) + len(locking_script)`.
fn encode_spent_output_for_signing(spent: &SpentOutput) -> Vec<u8> {
    let token_bytes = spent.token.as_ref().map(encode_token_prefix_bytes).unwrap_or_default();
    let combined_len = token_bytes.len() + spent.locking_script.len();
    let mut out = Vec::with_capacity(8 + 5 + combined_len);
    out.extend_from_slice(&spent.value.to_le_bytes());
    encode_varint(&mut out, combined_len as u64);
    out.extend_from_slice(&token_bytes);
    out.extend_from_slice(&spent.locking_script);
    out
}

/// Build a CashTokens-aware sighash preimage.
///
/// `sources[i]` MUST be the spent UTXO that `tx.inputs[i]` consumes.
/// `sighash_type` selects the preimage layout: `0x41` = classic, `0x61` = with
/// `hashUtxos` + per-input token prefix.
pub fn p2pkh_sighash_preimage_bch(
    tx: &Tx,
    input_index: usize,
    script_code: &[u8],
    sources: &[SpentOutput],
    sighash_type: u8,
) -> Vec<u8> {
    let with_utxos = (sighash_type & SIGHASH_UTXOS) != 0;
    let input = &tx.inputs[input_index];
    let spent_for_this_input = &sources[input_index];

    let mut out = Vec::with_capacity(256);

    // 1. nVersion
    out.extend_from_slice(&tx.version.to_le_bytes());

    // 2. hashPrevouts
    let mut prevouts_buf = Vec::with_capacity(tx.inputs.len() * 36);
    for inp in &tx.inputs {
        let mut txid_le = inp.prev.txid_be;
        txid_le.reverse();
        prevouts_buf.extend_from_slice(&txid_le);
        prevouts_buf.extend_from_slice(&inp.prev.vout.to_le_bytes());
    }
    out.extend_from_slice(&double_sha256(&prevouts_buf));

    // 3. hashUtxos (only when SIGHASH_UTXOS bit set)
    if with_utxos {
        let mut utxos_buf = Vec::with_capacity(sources.len() * 64);
        for s in sources {
            utxos_buf.extend_from_slice(&encode_spent_output_for_signing(s));
        }
        out.extend_from_slice(&double_sha256(&utxos_buf));
    }

    // 4. hashSequence
    let mut seq_buf = Vec::with_capacity(tx.inputs.len() * 4);
    for inp in &tx.inputs {
        seq_buf.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    out.extend_from_slice(&double_sha256(&seq_buf));

    // 5. outpoint of this input
    let mut txid_le = input.prev.txid_be;
    txid_le.reverse();
    out.extend_from_slice(&txid_le);
    out.extend_from_slice(&input.prev.vout.to_le_bytes());

    // 6. outputTokenPrefix (only for CashTokens preimage; raw bytes, NOT length-prefixed)
    if with_utxos {
        if let Some(tok) = &spent_for_this_input.token {
            out.extend_from_slice(&encode_token_prefix_bytes(tok));
        }
        // Empty if no token — nothing to push.
    }

    // 7. scriptCode (P2PKH locking script for funder inputs)
    encode_varint(&mut out, script_code.len() as u64);
    out.extend_from_slice(script_code);

    // 8. outputValue (value of this input's spent UTXO)
    out.extend_from_slice(&spent_for_this_input.value.to_le_bytes());

    // 9. nSequence
    out.extend_from_slice(&input.sequence.to_le_bytes());

    // 10. hashOutputs
    let mut outs_buf = Vec::new();
    for o in &tx.outputs {
        outs_buf.extend_from_slice(&o.value.to_le_bytes());
        let token_bytes = o.token.as_ref().map(encode_token_prefix_bytes).unwrap_or_default();
        let combined_len = token_bytes.len() + o.locking_script.len();
        encode_varint(&mut outs_buf, combined_len as u64);
        outs_buf.extend_from_slice(&token_bytes);
        outs_buf.extend_from_slice(&o.locking_script);
    }
    out.extend_from_slice(&double_sha256(&outs_buf));

    // 11. nLocktime
    out.extend_from_slice(&tx.locktime.to_le_bytes());

    // 12. sighash type | FORKID (4 LE) — sighash_type is the low byte, top 3 bytes are 0.
    out.extend_from_slice(&(sighash_type as u32).to_le_bytes());

    out
}

/// Backwards-compat shim for the classic pre-CashTokens preimage.
///
/// Same as [`p2pkh_sighash_preimage_bch`] with `sources = [{value, script_code, no token}]`
/// for the single input being signed and `sighash_type = SIGHASH_BIT (0x41)`.
/// Used by `ticker-ops fund` (no token UTXOs anywhere in the tx).
pub fn p2pkh_sighash_preimage(
    tx: &Tx,
    input_index: usize,
    script_code: &[u8],
    value: u64,
) -> Vec<u8> {
    // Build a sources vector that's structurally correct for hashUtxos when
    // someone later flips the sighash type to 0x61. For 0x41 the sources vec
    // is unused (hashUtxos is skipped), but supply something coherent anyway.
    let sources: Vec<SpentOutput> = tx
        .inputs
        .iter()
        .enumerate()
        .map(|(i, _)| SpentOutput {
            value: if i == input_index { value } else { 0 },
            locking_script: script_code.to_vec(),
            token: None,
        })
        .collect();
    p2pkh_sighash_preimage_bch(tx, input_index, script_code, &sources, SIGHASH_BIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::encode::{Input, Output, Tx, TxOutpoint, DEFAULT_SEQUENCE};
    use crate::tx::script::p2pkh_locking_script;

    #[test]
    fn classic_preimage_ends_with_sighash_0x41() {
        let pkh = [0u8; 20];
        let lock = p2pkh_locking_script(&pkh).to_vec();
        let tx = Tx::new(
            vec![Input {
                prev: TxOutpoint { txid_be: [0u8; 32], vout: 0 },
                unlock_script: vec![],
                sequence: DEFAULT_SEQUENCE,
            }],
            vec![],
        );
        let pre = p2pkh_sighash_preimage(&tx, 0, &lock, 100);
        let last4 = &pre[pre.len() - 4..];
        assert_eq!(last4, &[0x41, 0, 0, 0]);
    }

    #[test]
    fn tokens_preimage_ends_with_sighash_0x61_and_is_longer() {
        let pkh = [0u8; 20];
        let lock = p2pkh_locking_script(&pkh).to_vec();
        let tx = Tx::new(
            vec![Input {
                prev: TxOutpoint { txid_be: [0u8; 32], vout: 0 },
                unlock_script: vec![],
                sequence: DEFAULT_SEQUENCE,
            }],
            vec![],
        );
        let sources = vec![SpentOutput {
            value: 1000,
            locking_script: lock.clone(),
            token: None,
        }];
        let classic = p2pkh_sighash_preimage(&tx, 0, &lock, 1000);
        let tokens =
            p2pkh_sighash_preimage_bch(&tx, 0, &lock, &sources, SIGHASH_BIT_TOKENS);
        // Tokens preimage is 32 bytes longer (the hashUtxos field).
        assert_eq!(tokens.len(), classic.len() + 32);
        let last4 = &tokens[tokens.len() - 4..];
        assert_eq!(last4, &[0x61, 0, 0, 0]);
    }
}
