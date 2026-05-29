//! BIP-143-style sighash preimage for BCH (with FORKID).
//!
//! Used only for P2PKH funder inputs. Covenant unlocks use `checkDataSig`
//! against a separately-computed digest (see `chain::digest`), not a tx sighash.
//!
//! Preimage layout (BIP-143 §Specification, BCH FORKID variant):
//!
//! ```text
//!   1. nVersion (4)
//!   2. hashPrevouts (32)        — dSHA256 of all prevouts
//!   3. hashSequence (32)        — dSHA256 of all input nSequences
//!   4. outpoint of this input (32 + 4)
//!   5. scriptCode (varint + bytes)  — for P2PKH this is the P2PKH locking script
//!   6. value of this output (8 LE)
//!   7. nSequence of this input (4 LE)
//!   8. hashOutputs (32)         — dSHA256 of serialized outputs
//!   9. nLocktime (4 LE)
//!  10. sighash type | FORKID (4 LE)
//! ```
//!
//! BCH sighash uses FORKID = 0x40. SIGHASH_ALL = 0x01. Combined = 0x41.

use crate::crypto::double_sha256;
use crate::tx::encode::{encode_varint, Tx};

/// SIGHASH_ALL — sign everything (inputs + outputs).
pub const SIGHASH_ALL_BIP143: u8 = 0x01;

/// BCH FORKID bit.
pub const SIGHASH_FORKID: u8 = 0x40;

/// Composite sighash byte for SIGHASH_ALL | FORKID.
pub const SIGHASH_BIT: u8 = SIGHASH_ALL_BIP143 | SIGHASH_FORKID;

/// Build the BIP-143 preimage for one input.
///
/// `input_index`     — which input we're signing.
/// `script_code`     — the P2PKH locking script of the UTXO being spent (25 bytes).
/// `value`           — the satoshi value of the UTXO being spent.
pub fn p2pkh_sighash_preimage(
    tx: &Tx,
    input_index: usize,
    script_code: &[u8],
    value: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);

    // 1. nVersion
    out.extend_from_slice(&tx.version.to_le_bytes());

    // 2. hashPrevouts = dSHA256(concat(prevout for each input))
    let mut prevouts_buf = Vec::with_capacity(tx.inputs.len() * 36);
    for input in &tx.inputs {
        let mut txid_le = input.prev.txid_be;
        txid_le.reverse();
        prevouts_buf.extend_from_slice(&txid_le);
        prevouts_buf.extend_from_slice(&input.prev.vout.to_le_bytes());
    }
    out.extend_from_slice(&double_sha256(&prevouts_buf));

    // 3. hashSequence
    let mut seq_buf = Vec::with_capacity(tx.inputs.len() * 4);
    for input in &tx.inputs {
        seq_buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    out.extend_from_slice(&double_sha256(&seq_buf));

    // 4. outpoint of this input
    let input = &tx.inputs[input_index];
    let mut txid_le = input.prev.txid_be;
    txid_le.reverse();
    out.extend_from_slice(&txid_le);
    out.extend_from_slice(&input.prev.vout.to_le_bytes());

    // 5. scriptCode
    encode_varint(&mut out, script_code.len() as u64);
    out.extend_from_slice(script_code);

    // 6. value of this output
    out.extend_from_slice(&value.to_le_bytes());

    // 7. nSequence of this input
    out.extend_from_slice(&input.sequence.to_le_bytes());

    // 8. hashOutputs (SIGHASH_ALL → dSHA256 of all outputs serialized)
    let mut outs_buf = Vec::new();
    for o in &tx.outputs {
        outs_buf.extend_from_slice(&o.value.to_le_bytes());
        // Build locking-script-with-optional-token-prefix and serialize it length-prefixed.
        let mut script_buf = Vec::new();
        if let Some(token) = &o.token {
            // Same encoding as encode_tx (kept inline to avoid exposing internal helper).
            script_buf.push(0xef);
            script_buf.extend_from_slice(&token.category_le);
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
            script_buf.push(bits);
            if has_commit {
                encode_varint(&mut script_buf, token.commitment.len() as u64);
                script_buf.extend_from_slice(&token.commitment);
            }
            if has_amount {
                encode_varint(&mut script_buf, token.amount);
            }
        }
        script_buf.extend_from_slice(&o.locking_script);
        encode_varint(&mut outs_buf, script_buf.len() as u64);
        outs_buf.extend_from_slice(&script_buf);
    }
    out.extend_from_slice(&double_sha256(&outs_buf));

    // 9. nLocktime
    out.extend_from_slice(&tx.locktime.to_le_bytes());

    // 10. sighash | FORKID (4 B LE — type byte zero-padded to a u32)
    out.extend_from_slice(&(SIGHASH_BIT as u32).to_le_bytes());

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::encode::{Input, Output, Tx, TxOutpoint, DEFAULT_SEQUENCE};
    use crate::tx::script::p2pkh_locking_script;

    #[test]
    fn preimage_length_increases_with_outputs() {
        let pkh = [0u8; 20];
        let lock = p2pkh_locking_script(&pkh).to_vec();
        let prev = TxOutpoint { txid_be: [1u8; 32], vout: 0 };
        let one_out = Tx::new(
            vec![Input { prev, unlock_script: vec![], sequence: DEFAULT_SEQUENCE }],
            vec![Output { value: 100, locking_script: lock.clone(), token: None }],
        );
        let two_out = Tx::new(
            vec![Input { prev, unlock_script: vec![], sequence: DEFAULT_SEQUENCE }],
            vec![
                Output { value: 100, locking_script: lock.clone(), token: None },
                Output { value: 200, locking_script: lock.clone(), token: None },
            ],
        );
        let pre1 = p2pkh_sighash_preimage(&one_out, 0, &lock, 500);
        let pre2 = p2pkh_sighash_preimage(&two_out, 0, &lock, 500);
        // hashOutputs is fixed-size 32 B, so preimages should be the SAME length
        // (hash size doesn't change), but with different content.
        assert_eq!(pre1.len(), pre2.len());
        assert_ne!(pre1, pre2);
    }

    #[test]
    fn preimage_ends_with_sighash_byte() {
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
        // Last 4 bytes = SIGHASH_BIT as u32 LE.
        let last4 = &pre[pre.len() - 4..];
        assert_eq!(last4, &(SIGHASH_BIT as u32).to_le_bytes());
        assert_eq!(SIGHASH_BIT, 0x41);
    }
}
