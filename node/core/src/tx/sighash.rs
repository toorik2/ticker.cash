//! BIP-143-style sighash preimage for BCH with FORKID, extended for CashTokens (`SIGHASH_UTXOS`).
//!
//! `0x61 = SIGHASH_ALL | SIGHASH_UTXOS | SIGHASH_FORKID` adds `hashUtxos` after `hashPrevouts`
//! and the spent UTXO's token prefix after the outpoint. We use it for every signed input, with
//! or without token inputs present. Layout mirrors libauth's `encodeSigningSerializationBch`.

use crate::crypto::double_sha256;
use crate::tx::encode::{encode_token_prefix, encode_varint, TokenPrefix, Tx};

pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_FORKID: u8 = 0x40;
pub const SIGHASH_UTXOS: u8 = 0x20;
/// The one sighash type v25 signs with.
pub const SIGHASH_ALL_UTXOS_FORKID: u8 = SIGHASH_ALL | SIGHASH_UTXOS | SIGHASH_FORKID;

/// The UTXO an input spends (needed for `hashUtxos` and the per-input token prefix).
#[derive(Debug, Clone)]
pub struct SpentOutput {
    pub value: u64,
    pub locking_script: Vec<u8>,
    pub token: Option<TokenPrefix>,
}

fn encode_spent_output(spent: &SpentOutput) -> Vec<u8> {
    let token_bytes = spent.token.as_ref().map(encode_token_prefix).unwrap_or_default();
    let combined_len = token_bytes.len() + spent.locking_script.len();
    let mut out = Vec::with_capacity(8 + 5 + combined_len);
    out.extend_from_slice(&spent.value.to_le_bytes());
    encode_varint(&mut out, combined_len as u64);
    out.extend_from_slice(&token_bytes);
    out.extend_from_slice(&spent.locking_script);
    out
}

/// Sighash preimage for `tx.inputs[input_index]`. `sources[i]` is the UTXO spent by input `i`.
pub fn sighash_preimage(tx: &Tx, input_index: usize, script_code: &[u8], sources: &[SpentOutput], sighash_type: u8) -> Vec<u8> {
    let with_utxos = (sighash_type & SIGHASH_UTXOS) != 0;
    let input = &tx.inputs[input_index];
    let spent = &sources[input_index];
    let mut out = Vec::with_capacity(320);
    out.extend_from_slice(&tx.version.to_le_bytes());
    let mut prevouts = Vec::with_capacity(tx.inputs.len() * 36);
    for inp in &tx.inputs {
        let mut txid_le = inp.prev.txid_be;
        txid_le.reverse();
        prevouts.extend_from_slice(&txid_le);
        prevouts.extend_from_slice(&inp.prev.vout.to_le_bytes());
    }
    out.extend_from_slice(&double_sha256(&prevouts));
    if with_utxos {
        let mut utxos = Vec::with_capacity(sources.len() * 64);
        for s in sources {
            utxos.extend_from_slice(&encode_spent_output(s));
        }
        out.extend_from_slice(&double_sha256(&utxos));
    }
    let mut seqs = Vec::with_capacity(tx.inputs.len() * 4);
    for inp in &tx.inputs {
        seqs.extend_from_slice(&inp.sequence.to_le_bytes());
    }
    out.extend_from_slice(&double_sha256(&seqs));
    let mut txid_le = input.prev.txid_be;
    txid_le.reverse();
    out.extend_from_slice(&txid_le);
    out.extend_from_slice(&input.prev.vout.to_le_bytes());
    if with_utxos {
        if let Some(tok) = &spent.token {
            out.extend_from_slice(&encode_token_prefix(tok));
        }
    }
    encode_varint(&mut out, script_code.len() as u64);
    out.extend_from_slice(script_code);
    out.extend_from_slice(&spent.value.to_le_bytes());
    out.extend_from_slice(&input.sequence.to_le_bytes());
    let mut outs = Vec::new();
    for o in &tx.outputs {
        outs.extend_from_slice(&o.value.to_le_bytes());
        let token_bytes = o.token.as_ref().map(encode_token_prefix).unwrap_or_default();
        let combined_len = token_bytes.len() + o.locking_script.len();
        encode_varint(&mut outs, combined_len as u64);
        outs.extend_from_slice(&token_bytes);
        outs.extend_from_slice(&o.locking_script);
    }
    out.extend_from_slice(&double_sha256(&outs));
    out.extend_from_slice(&tx.locktime.to_le_bytes());
    out.extend_from_slice(&(sighash_type as u32).to_le_bytes());
    out
}

/// The 32-byte digest a transaction signature signs.
pub fn sighash_digest(tx: &Tx, input_index: usize, script_code: &[u8], sources: &[SpentOutput], sighash_type: u8) -> [u8; 32] {
    double_sha256(&sighash_preimage(tx, input_index, script_code, sources, sighash_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::encode::{Input, Tx, TxOutpoint, SEQUENCE_FINAL};
    use crate::tx::script::p2pkh_locking_script;

    #[test]
    fn utxos_variant_is_32_bytes_longer_and_ends_with_0x61() {
        let lock = p2pkh_locking_script(&[0u8; 20]).to_vec();
        let tx = Tx::new(vec![Input { prev: TxOutpoint { txid_be: [0u8; 32], vout: 0 }, unlock_script: vec![], sequence: SEQUENCE_FINAL }], vec![]);
        let sources = vec![SpentOutput { value: 1000, locking_script: lock.clone(), token: None }];
        let plain = sighash_preimage(&tx, 0, &lock, &sources, SIGHASH_ALL | SIGHASH_FORKID);
        let utxos = sighash_preimage(&tx, 0, &lock, &sources, SIGHASH_ALL_UTXOS_FORKID);
        assert_eq!(utxos.len(), plain.len() + 32);
        assert_eq!(&utxos[utxos.len() - 4..], &[0x61, 0, 0, 0]);
    }
}
