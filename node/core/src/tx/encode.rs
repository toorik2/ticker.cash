//! BCH + CashTokens transaction wire-format encoder.
//!
//! CashTokens (CHIP-2022-02) extends Bitcoin Cash transactions with token
//! prefixes on outputs. An output's serialized form is:
//!
//! ```text
//!   value (8 B LE) || locking_script_with_optional_token_prefix
//! ```
//!
//! When the output carries CashTokens, the locking script is prefixed with:
//!
//! ```text
//!   0xef || category (32 B LE) || bitfield (1 B) || [amount (CompactVariable)]
//!         || [commitment_length (CompactVariable) + commitment (≤ 40 B)]
//!         || actual locking script
//! ```
//!
//! Bitfield bits (from CHIP-2022-02 §4):
//!   - 0x10 = HAS_AMOUNT
//!   - 0x20 = HAS_NFT
//!   - 0x40 = HAS_COMMITMENT_LENGTH
//!   - low nibble = NFT capability: 0 (none/immutable), 1 (mutable), 2 (minting)
//!
//! For our NFT-only mutable / minting tokens with no fungible amount,
//! the prefix byte is `HAS_NFT | HAS_COMMITMENT_LENGTH | capability` = `0x60 | cap`.
//! For minting we use `0x62`, for mutable we use `0x61`.
//!
//! Length-prefixing the on-the-wire output script (including the token prefix)
//! is done with the surrounding varint, exactly as for non-token outputs.

use crate::tx::script::push_data;

/// NFT capability bits.
pub const NO_CAPABILITY: u8 = 0x00;
pub const MUTABLE_CAPABILITY: u8 = 0x01;
pub const MINTING_CAPABILITY: u8 = 0x02;

// CashTokens prefix marker (CHIP-2022-02): single byte placed before the locking script
// when an output carries a token.
const TOKEN_PREFIX_MARKER: u8 = 0xef;

// CashTokens bitfield masks.
const HAS_AMOUNT: u8 = 0x10;
const HAS_NFT: u8 = 0x20;
const HAS_COMMITMENT_LENGTH: u8 = 0x40;

/// Outpoint of a previous tx output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxOutpoint {
    /// Previous txid, BIG-ENDIAN (display order). The encoder reverses it on the wire.
    pub txid_be: [u8; 32],
    /// Output index of the previous tx.
    pub vout: u32,
}

/// A transaction input.
#[derive(Debug, Clone)]
pub struct Input {
    pub prev: TxOutpoint,
    /// Raw unlock script (scriptSig).
    pub unlock_script: Vec<u8>,
    /// `nSequence` — defaults to `0xfffffffe` (BIP-125 RBF off, locktime-eligible).
    pub sequence: u32,
}

/// CashTokens prefix data carried by an output, if any.
#[derive(Debug, Clone)]
pub struct TokenPrefix {
    /// Token category, **little-endian** as it appears on chain (txids in display form are big-endian; this is the reverse).
    pub category_le: [u8; 32],
    /// NFT capability: one of [`NO_CAPABILITY`], [`MUTABLE_CAPABILITY`], [`MINTING_CAPABILITY`].
    pub capability: u8,
    /// Optional NFT commitment (≤ 40 bytes).
    pub commitment: Vec<u8>,
    /// Optional fungible token amount. `0` means no amount (our v12 tokens are NFT-only, never set this).
    pub amount: u64,
}

/// A transaction output.
#[derive(Debug, Clone)]
pub struct Output {
    /// Sats.
    pub value: u64,
    /// Locking script (scriptPubKey) without any token prefix.
    pub locking_script: Vec<u8>,
    /// Optional CashTokens prefix.
    pub token: Option<TokenPrefix>,
}

/// Whole transaction.
#[derive(Debug, Clone)]
pub struct Tx {
    pub version: i32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
}

impl Tx {
    /// New tx with default version=2 and locktime=0 (matching cashscript's TransactionBuilder defaults).
    pub fn new(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Tx {
            version: 2,
            inputs,
            outputs,
            locktime: 0,
        }
    }
}

/// Default sequence number for inputs (BIP-125-disabled, locktime-eligible).
pub const DEFAULT_SEQUENCE: u32 = 0xffff_fffe;

/// Encode `n` as a Bitcoin CompactSize varint.
pub fn encode_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// Compose the CashTokens prefix bytes plus the actual locking script — what goes inside
/// the output's serialized locking-script payload when a token is present.
fn encode_output_script_with_token(out: &mut Vec<u8>, locking_script: &[u8], token: &TokenPrefix) {
    // Marker
    out.push(TOKEN_PREFIX_MARKER);
    // Category (32 B LE on the wire)
    out.extend_from_slice(&token.category_le);
    // Bitfield
    let has_nft = token.capability != NO_CAPABILITY || !token.commitment.is_empty();
    let has_commitment_length = !token.commitment.is_empty();
    let has_amount = token.amount > 0;
    let mut bits: u8 = 0;
    if has_nft {
        bits |= HAS_NFT | (token.capability & 0x0f);
    }
    if has_commitment_length {
        bits |= HAS_COMMITMENT_LENGTH;
    }
    if has_amount {
        bits |= HAS_AMOUNT;
    }
    out.push(bits);
    if has_commitment_length {
        encode_varint(out, token.commitment.len() as u64);
        out.extend_from_slice(&token.commitment);
    }
    if has_amount {
        encode_varint(out, token.amount);
    }
    // Actual locking script follows directly.
    out.extend_from_slice(locking_script);
}

/// Encode the full wire bytes of a tx, including a CashTokens-prefixed output script
/// when applicable. Returned bytes are ready to broadcast via Electrum `blockchain.transaction.broadcast`.
pub fn encode_tx(tx: &Tx) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // version
    buf.extend_from_slice(&tx.version.to_le_bytes());

    // input count
    encode_varint(&mut buf, tx.inputs.len() as u64);
    for input in &tx.inputs {
        // prev txid (32 B, reversed from display order)
        let mut txid_le = input.prev.txid_be;
        txid_le.reverse();
        buf.extend_from_slice(&txid_le);
        // prev vout (4 B LE)
        buf.extend_from_slice(&input.prev.vout.to_le_bytes());
        // unlock script length + bytes
        encode_varint(&mut buf, input.unlock_script.len() as u64);
        buf.extend_from_slice(&input.unlock_script);
        // sequence (4 B LE)
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // output count
    encode_varint(&mut buf, tx.outputs.len() as u64);
    for out in &tx.outputs {
        // value (8 B LE)
        buf.extend_from_slice(&out.value.to_le_bytes());
        // build locking-script-with-optional-token-prefix, length-prefixed
        let mut script_buf = Vec::with_capacity(64);
        if let Some(token) = &out.token {
            encode_output_script_with_token(&mut script_buf, &out.locking_script, token);
        } else {
            script_buf.extend_from_slice(&out.locking_script);
        }
        encode_varint(&mut buf, script_buf.len() as u64);
        buf.extend_from_slice(&script_buf);
    }

    // locktime
    buf.extend_from_slice(&tx.locktime.to_le_bytes());

    buf
}

/// Helper: serialize a vector of script bytes as a length-prefixed minimal data push
/// (used by the OP_PUSHDATA path inside sighash preimages).
#[allow(dead_code)]
pub(crate) fn push_data_to_vec(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(data.len() + 5);
    push_data(&mut v, data);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_below_fd() {
        let mut v = Vec::new();
        encode_varint(&mut v, 0xfc);
        assert_eq!(v, vec![0xfc]);
    }

    #[test]
    fn varint_fd_marker() {
        let mut v = Vec::new();
        encode_varint(&mut v, 0xfd);
        assert_eq!(v, vec![0xfd, 0xfd, 0x00]);
    }

    #[test]
    fn varint_u16_max() {
        let mut v = Vec::new();
        encode_varint(&mut v, 0xffff);
        assert_eq!(v, vec![0xfd, 0xff, 0xff]);
    }

    #[test]
    fn varint_above_u16() {
        let mut v = Vec::new();
        encode_varint(&mut v, 0x10000);
        assert_eq!(v, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn empty_tx_minimum_envelope() {
        let tx = Tx::new(vec![], vec![]);
        let bytes = encode_tx(&tx);
        // version (4) + input count (1) + output count (1) + locktime (4) = 10
        assert_eq!(bytes.len(), 10);
        assert_eq!(&bytes[..4], &[0x02, 0x00, 0x00, 0x00]); // version=2 LE
        assert_eq!(bytes[4], 0); // 0 inputs
        assert_eq!(bytes[5], 0); // 0 outputs
        assert_eq!(&bytes[6..10], &[0, 0, 0, 0]); // locktime=0
    }

    #[test]
    fn p2pkh_only_output_no_token_prefix() {
        let pkh = [0xaa; 20];
        let mut lock = Vec::new();
        lock.extend_from_slice(&[0x76, 0xa9, 0x14]);
        lock.extend_from_slice(&pkh);
        lock.extend_from_slice(&[0x88, 0xac]);
        let tx = Tx::new(
            vec![],
            vec![Output {
                value: 12345,
                locking_script: lock.clone(),
                token: None,
            }],
        );
        let bytes = encode_tx(&tx);
        // version (4) + inp count (1) + out count (1) + value (8) + scriptlen (1) + 25 + locktime (4)
        assert_eq!(bytes.len(), 4 + 1 + 1 + 8 + 1 + 25 + 4);
        // No 0xef byte anywhere — confirms no token prefix.
        assert!(!bytes.contains(&0xef));
    }

    #[test]
    fn mutable_nft_output_has_token_prefix() {
        let cat = [0x33u8; 32];
        let commit = vec![0x73, 0x01, 0x00]; // sample slot commit prefix (v13 version byte)
        let tx = Tx::new(
            vec![],
            vec![Output {
                value: 1500,
                locking_script: vec![0xaa, 0x20, 0xaa, 0xbb, 0xcc, 0x87], // P2SH-32-ish stub
                token: Some(TokenPrefix {
                    category_le: cat,
                    capability: MUTABLE_CAPABILITY,
                    commitment: commit.clone(),
                    amount: 0,
                }),
            }],
        );
        let bytes = encode_tx(&tx);
        // 0xef must appear in the output's script section.
        let prefix_pos = bytes.iter().position(|&b| b == 0xef).expect("token prefix byte");
        assert_eq!(&bytes[prefix_pos + 1..prefix_pos + 33], &cat);
        // bitfield: HAS_NFT (0x20) | HAS_COMMITMENT_LENGTH (0x40) | capability 0x01 = 0x61.
        assert_eq!(bytes[prefix_pos + 33], 0x61);
        // commitment length varint + commitment bytes
        assert_eq!(bytes[prefix_pos + 34], commit.len() as u8);
        assert_eq!(&bytes[prefix_pos + 35..prefix_pos + 35 + commit.len()], &commit[..]);
    }

    #[test]
    fn minting_nft_capability_byte() {
        let tx = Tx::new(
            vec![],
            vec![Output {
                value: 2000,
                locking_script: vec![0xaa, 0x20, 0xff, 0x87],
                token: Some(TokenPrefix {
                    category_le: [0u8; 32],
                    capability: MINTING_CAPABILITY,
                    commitment: vec![0x60, 0x01], // sample
                    amount: 0,
                }),
            }],
        );
        let bytes = encode_tx(&tx);
        let prefix_pos = bytes.iter().position(|&b| b == 0xef).unwrap();
        // capability 0x02 + HAS_NFT (0x20) + HAS_COMMITMENT_LENGTH (0x40) = 0x62.
        assert_eq!(bytes[prefix_pos + 33], 0x62);
    }

    #[test]
    fn txid_reversed_on_wire() {
        let txid_be: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let tx = Tx::new(
            vec![Input {
                prev: TxOutpoint { txid_be, vout: 7 },
                unlock_script: vec![],
                sequence: DEFAULT_SEQUENCE,
            }],
            vec![],
        );
        let bytes = encode_tx(&tx);
        // After version(4) + input_count(1), the next 32 bytes are the reversed txid.
        let wire_txid = &bytes[5..37];
        let mut expected_le = txid_be;
        expected_le.reverse();
        assert_eq!(wire_txid, &expected_le);
        // vout=7 (4 B LE)
        assert_eq!(&bytes[37..41], &7u32.to_le_bytes());
    }
}
