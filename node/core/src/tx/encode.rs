//! BCH + CashTokens transaction wire-format encoder (CHIP-2022-02).
//!
//! An output with a token is serialized as `value(8 LE) ‖ varint(L) ‖ prefix ‖ locking_script`
//! where the prefix is `0xef ‖ category(32, LE on the wire) ‖ bitfield ‖ [commitment_len ‖
//! commitment] ‖ [amount]`. Bitfield: `0x10` HAS_AMOUNT, `0x20` HAS_NFT, `0x40`
//! HAS_COMMITMENT_LENGTH, low nibble = capability (0 none, 1 mutable, 2 minting). Since the
//! May 2026 upgrade a commitment may be up to 128 bytes; v25 uses 12.

pub const NO_CAPABILITY: u8 = 0x00;
pub const MUTABLE_CAPABILITY: u8 = 0x01;
pub const MINTING_CAPABILITY: u8 = 0x02;

const TOKEN_PREFIX_MARKER: u8 = 0xef;
const HAS_AMOUNT: u8 = 0x10;
const HAS_NFT: u8 = 0x20;
const HAS_COMMITMENT_LENGTH: u8 = 0x40;

/// Outpoint of a previous tx output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxOutpoint {
    /// Previous txid, big-endian (display order). Reversed on the wire.
    pub txid_be: [u8; 32],
    pub vout: u32,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub prev: TxOutpoint,
    pub unlock_script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPrefix {
    /// Category as it appears on the wire (little-endian; the reverse of the display id).
    pub category_le: [u8; 32],
    pub capability: u8,
    pub commitment: Vec<u8>,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct Output {
    pub value: u64,
    /// Locking script without any token prefix.
    pub locking_script: Vec<u8>,
    pub token: Option<TokenPrefix>,
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub version: i32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
}

impl Tx {
    pub fn new(inputs: Vec<Input>, outputs: Vec<Output>) -> Self {
        Tx { version: 2, inputs, outputs, locktime: 0 }
    }
}

/// Default input sequence: final, no relative lock.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

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

/// CashTokens prefix bytes for an output (without the locking script).
pub fn encode_token_prefix(token: &TokenPrefix) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 32 + 1 + token.commitment.len() + 9);
    out.push(TOKEN_PREFIX_MARKER);
    out.extend_from_slice(&token.category_le);
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
        encode_varint(&mut out, token.commitment.len() as u64);
        out.extend_from_slice(&token.commitment);
    }
    if has_amount {
        encode_varint(&mut out, token.amount);
    }
    out
}

/// `prefix ‖ locking_script` as it sits inside an output (what the varint length covers).
pub fn output_script_bytes(out: &Output) -> Vec<u8> {
    let mut script_buf = Vec::with_capacity(96);
    if let Some(token) = &out.token {
        script_buf.extend_from_slice(&encode_token_prefix(token));
    }
    script_buf.extend_from_slice(&out.locking_script);
    script_buf
}

pub fn encode_tx(tx: &Tx) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2048);
    buf.extend_from_slice(&tx.version.to_le_bytes());
    encode_varint(&mut buf, tx.inputs.len() as u64);
    for input in &tx.inputs {
        let mut txid_le = input.prev.txid_be;
        txid_le.reverse();
        buf.extend_from_slice(&txid_le);
        buf.extend_from_slice(&input.prev.vout.to_le_bytes());
        encode_varint(&mut buf, input.unlock_script.len() as u64);
        buf.extend_from_slice(&input.unlock_script);
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }
    encode_varint(&mut buf, tx.outputs.len() as u64);
    for out in &tx.outputs {
        buf.extend_from_slice(&out.value.to_le_bytes());
        let script_buf = output_script_bytes(out);
        encode_varint(&mut buf, script_buf.len() as u64);
        buf.extend_from_slice(&script_buf);
    }
    buf.extend_from_slice(&tx.locktime.to_le_bytes());
    buf
}

/// Display-order txid of an encoded transaction.
pub fn txid_be(raw: &[u8]) -> [u8; 32] {
    let mut h = crate::crypto::double_sha256(raw);
    h.reverse();
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries() {
        let mut v = Vec::new();
        encode_varint(&mut v, 0xfc);
        encode_varint(&mut v, 0xfd);
        encode_varint(&mut v, 0x10000);
        assert_eq!(v, vec![0xfc, 0xfd, 0xfd, 0x00, 0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn empty_tx_is_ten_bytes() {
        assert_eq!(encode_tx(&Tx::new(vec![], vec![])).len(), 10);
    }

    #[test]
    fn immutable_nft_prefix_bitfield_is_0x60() {
        let t = TokenPrefix { category_le: [0x33; 32], capability: NO_CAPABILITY, commitment: vec![1; 12], amount: 0 };
        let p = encode_token_prefix(&t);
        assert_eq!(p[0], 0xef);
        assert_eq!(p[33], 0x60);
        assert_eq!(p[34], 12);
        assert_eq!(p.len(), 1 + 32 + 1 + 1 + 12);
    }

    #[test]
    fn minting_nft_prefix_bitfield_is_0x62() {
        let t = TokenPrefix { category_le: [0; 32], capability: MINTING_CAPABILITY, commitment: vec![0; 12], amount: 0 };
        assert_eq!(encode_token_prefix(&t)[33], 0x62);
    }

    /// The v25 Ticker output is 87 bytes on the wire: 8 value + 1 varint + 47 prefix + 31 lock
    /// (BCHN's dust rule adds 148 and triples: 705; the covenant pins 708, three sats of margin).
    #[test]
    fn ticker_output_is_87_bytes() {
        let out = Output { value: 708, locking_script: vec![0u8; 31], token: Some(TokenPrefix { category_le: [0; 32], capability: NO_CAPABILITY, commitment: vec![0; 12], amount: 0 }) };
        let tx = Tx::new(vec![], vec![out]);
        assert_eq!(encode_tx(&tx).len(), 10 + 87);
    }

    #[test]
    fn txid_reverses_on_wire() {
        let mut txid = [0u8; 32];
        txid[0] = 0xaa;
        let tx = Tx::new(vec![Input { prev: TxOutpoint { txid_be: txid, vout: 1 }, unlock_script: vec![], sequence: SEQUENCE_FINAL }], vec![]);
        let raw = encode_tx(&tx);
        assert_eq!(raw[5 + 31], 0xaa);
    }
}
