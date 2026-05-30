//! Shared P2PKH transaction builder for the `fund` and `send` subcommands.
//!
//! All three coordinator transfer flavors (master → publishers, treasury →
//! master, master → arbitrary address) reduce to: spend N non-token UTXOs
//! controlled by one privkey, emit M P2PKH outputs, sign each input with
//! ECDSA-DER + classic BIP-143 sighash (0x41, no token UTXOs in the tx).

use ticker_core::crypto::{double_sha256, sign_ecdsa};
use ticker_core::electrum::types::Utxo;
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::encode::{encode_tx, Input, Output, Tx, TxOutpoint, DEFAULT_SEQUENCE};
use ticker_core::tx::script::{p2pkh_locking_script, push_data};
use ticker_core::tx::sighash::{p2pkh_sighash_preimage, SIGHASH_BIT};

/// A wallet that can sign P2PKH inputs.
pub struct Signer {
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
    pub pkh: [u8; 20],
}

/// Build, sign, and encode a P2PKH tx.
///
/// Inputs: every UTXO in `utxos` (caller filters to non-token).
/// Outputs: `outputs` plus an optional change-back-to-`signer` output if
/// `change >= 546`.
///
/// `fee_buffer` is subtracted from the signer's total to cover the miner fee
/// + dust headroom.
pub fn build_signed_p2pkh_tx(
    signer: &Signer,
    utxos: &[Utxo],
    outputs: Vec<Output>,
    fee_buffer: u64,
    prefix: AddressPrefix,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let total: u64 = utxos.iter().map(|u| u.value).sum();
    let spent_out: u64 = outputs.iter().map(|o| o.value).sum();
    let need = spent_out + fee_buffer;
    if total < need {
        return Err(format!("insufficient funds: have {total}, need {need}").into());
    }

    // Inputs (unlock scripts filled in after the tx skeleton is built).
    let mut inputs = Vec::with_capacity(utxos.len());
    for u in utxos {
        let mut txid_be = [0u8; 32];
        txid_be.copy_from_slice(&hex::decode(&u.tx_hash)?);
        inputs.push(Input {
            prev: TxOutpoint {
                txid_be,
                vout: u.tx_pos,
            },
            unlock_script: Vec::new(),
            sequence: DEFAULT_SEQUENCE,
        });
    }

    // Outputs (caller-supplied + change).
    let mut all_outputs = outputs;
    let change = total - spent_out - fee_buffer;
    if change >= 546 {
        let _ = encode_p2pkh_cashaddr(&signer.pkh, prefix); // for log clarity if caller wants
        all_outputs.push(Output {
            value: change,
            locking_script: p2pkh_locking_script(&signer.pkh).to_vec(),
            token: None,
        });
    }

    let mut tx = Tx::new(inputs, all_outputs);

    // Sign each input via classic BIP-143 (no token UTXOs are involved here).
    let locking = p2pkh_locking_script(&signer.pkh).to_vec();
    for (i, u) in utxos.iter().enumerate() {
        let preimage = p2pkh_sighash_preimage(&tx, i, &locking, u.value);
        let digest = double_sha256(&preimage);
        let sig = sign_ecdsa(&signer.private_key, &digest)?;
        let mut sig_with_sighash = Vec::with_capacity(sig.len() + 1);
        sig_with_sighash.extend_from_slice(&sig);
        sig_with_sighash.push(SIGHASH_BIT);
        let mut unlock = Vec::with_capacity(100);
        push_data(&mut unlock, &sig_with_sighash);
        push_data(&mut unlock, &signer.public_key);
        tx.inputs[i].unlock_script = unlock;
    }

    Ok(encode_tx(&tx))
}
