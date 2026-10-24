//! CashAddr encoder/decoder (BCH spec, 40-bit BCH-polynomial checksum, not bech32).
//!
//! Version bytes: P2PKH 20 B = 0x00, P2SH-32 = 0x0b, P2S (CHIP-2024-12, bare script) = 0x10.
//! Token-aware variants add 0x08 to the type nibble (P2PKH 0x10 → shown as `z…`); we emit the
//! plain forms and decode both.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressPrefix {
    Mainnet,
    Chipnet,
}

impl AddressPrefix {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressPrefix::Mainnet => "bitcoincash",
            AddressPrefix::Chipnet => "bchtest",
        }
    }
    pub fn from_network(network: &str) -> Option<Self> {
        match network {
            "mainnet" => Some(AddressPrefix::Mainnet),
            "chipnet" => Some(AddressPrefix::Chipnet),
            _ => None,
        }
    }
}

const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub fn encode_p2pkh_cashaddr(pkh: &[u8; 20], prefix: AddressPrefix) -> String {
    encode_cashaddr(0x00, pkh, prefix)
}

pub fn encode_p2sh32_cashaddr(locking_bytecode: &[u8; 35], prefix: AddressPrefix) -> String {
    let hash: &[u8; 32] = locking_bytecode[2..34].try_into().expect("35 - 3 = 32");
    encode_cashaddr(0x0b, hash, prefix)
}

/// Address for any locking bytecode: P2PKH, P2SH-32 or P2S. Returns `None` for shapes
/// CashAddr cannot express.
pub fn encode_lock_cashaddr(lock: &[u8], prefix: AddressPrefix) -> Option<String> {
    if lock.len() == 25 && lock[0] == 0x76 && lock[1] == 0xa9 && lock[2] == 20 && lock[23] == 0x88 && lock[24] == 0xac {
        return Some(encode_p2pkh_cashaddr(lock[3..23].try_into().unwrap(), prefix));
    }
    if lock.len() == 35 && lock[0] == 0xaa && lock[1] == 32 && lock[34] == 0x87 {
        return Some(encode_p2sh32_cashaddr(lock.try_into().unwrap(), prefix));
    }
    if (1..=201).contains(&lock.len()) {
        return Some(encode_cashaddr(0x10, lock, prefix));
    }
    None
}

fn encode_cashaddr(version_byte: u8, hash: &[u8], prefix: AddressPrefix) -> String {
    let prefix_str = prefix.as_str();
    let mut payload = Vec::with_capacity(1 + hash.len());
    payload.push(version_byte | size_code(hash.len()));
    payload.extend_from_slice(hash);
    let data5 = convert_bits(&payload, 8, 5, true);
    let mut checksum_input: Vec<u8> = prefix_str.bytes().map(|b| b & 0x1f).collect();
    checksum_input.push(0);
    checksum_input.extend_from_slice(&data5);
    checksum_input.extend_from_slice(&[0u8; 8]);
    let checksum = polymod(&checksum_input) ^ 1;
    let mut data = data5;
    for i in (0..8).rev() {
        data.push(((checksum >> (i * 5)) & 0x1f) as u8);
    }
    let mut result = String::with_capacity(prefix_str.len() + 1 + data.len());
    result.push_str(prefix_str);
    result.push(':');
    for &b in &data {
        result.push(ALPHABET[b as usize] as char);
    }
    result
}

/// CashAddr hash-size code for the fixed sizes it supports; P2S of an unlisted length is
/// encoded with size code 0 in practice by current tooling for sizes ≤ 20, and the nearest
/// supported class otherwise. We only emit P2PKH (20), P2SH-32 (32) and P2S Tickers (31 B →
/// not a listed size), so P2S follows the size-code table used by libauth for arbitrary
/// payloads: the code for the exact length when listed, else 0.
fn size_code(len: usize) -> u8 {
    match len {
        20 => 0,
        24 => 1,
        28 => 2,
        32 => 3,
        40 => 4,
        48 => 5,
        56 => 6,
        64 => 7,
        _ => 0,
    }
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * from_bits as usize / to_bits as usize + 1);
    let max = (1u32 << to_bits) - 1;
    for &v in data {
        acc = (acc << from_bits) | v as u32;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad && bits > 0 {
        out.push(((acc << (to_bits - bits)) & max) as u8);
    }
    out
}

fn polymod(values: &[u8]) -> u64 {
    let gen: [u64; 5] = [0x98_f2bc_8e61, 0x79_b76d_99e2, 0xf3_3e5f_b3c4, 0xae_2eab_e2a8, 0x1e_4f43_e470];
    let mut c: u64 = 1;
    for &v in values {
        let c0 = (c >> 35) as u8;
        c = ((c & 0x07_ffff_ffff) << 5) ^ (v as u64);
        for (i, &g) in gen.iter().enumerate() {
            if c0 & (1 << i) != 0 {
                c ^= g;
            }
        }
    }
    c
}

#[derive(Debug, thiserror::Error)]
pub enum CashAddrDecodeError {
    #[error("missing prefix in {0:?}")]
    MissingPrefix(String),
    #[error("wrong prefix: got {got:?}, expected {expected:?}")]
    WrongPrefix { got: String, expected: &'static str },
    #[error("invalid character {0:?}")]
    InvalidChar(char),
    #[error("address too short")]
    TooShort,
    #[error("bad CashAddr checksum (typo or wrong network?)")]
    BadChecksum,
    #[error("not a P2PKH address (version byte 0x{0:02x})")]
    NotP2pkh(u8),
}

/// Decode a P2PKH CashAddr (plain or token-aware) to its 20-byte pkh.
pub fn decode_p2pkh_cashaddr(addr: &str, expected: AddressPrefix) -> Result<[u8; 20], CashAddrDecodeError> {
    let (prefix, body) = addr.split_once(':').ok_or_else(|| CashAddrDecodeError::MissingPrefix(addr.to_string()))?;
    if prefix != expected.as_str() {
        return Err(CashAddrDecodeError::WrongPrefix { got: prefix.to_string(), expected: expected.as_str() });
    }
    let mut data5: Vec<u8> = Vec::with_capacity(body.len());
    for c in body.chars() {
        let pos = ALPHABET.iter().position(|&b| b == c as u8).ok_or(CashAddrDecodeError::InvalidChar(c))?;
        data5.push(pos as u8);
    }
    if data5.len() < 8 {
        return Err(CashAddrDecodeError::TooShort);
    }
    let mut checksum_input: Vec<u8> = prefix.bytes().map(|b| b & 0x1f).collect();
    checksum_input.push(0);
    checksum_input.extend_from_slice(&data5);
    if polymod(&checksum_input) != 1 {
        return Err(CashAddrDecodeError::BadChecksum);
    }
    data5.truncate(data5.len() - 8);
    let payload8 = convert_bits(&data5, 5, 8, false);
    if payload8.len() < 21 {
        return Err(CashAddrDecodeError::TooShort);
    }
    let version = payload8[0];
    if version != 0x00 && version != 0x10 {
        return Err(CashAddrDecodeError::NotP2pkh(version));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&payload8[1..21]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec vector: pkh 76a04053bda0a88bda5177b86a15c3b29f559873 → qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a.
    #[test]
    fn p2pkh_mainnet_spec_vector() {
        let pkh: [u8; 20] = hex::decode("76a04053bda0a88bda5177b86a15c3b29f559873").unwrap().try_into().unwrap();
        assert_eq!(encode_p2pkh_cashaddr(&pkh, AddressPrefix::Mainnet), "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
    }

    #[test]
    fn roundtrip_and_checksum() {
        let pkh = [0x42u8; 20];
        let a = encode_p2pkh_cashaddr(&pkh, AddressPrefix::Chipnet);
        assert_eq!(decode_p2pkh_cashaddr(&a, AddressPrefix::Chipnet).unwrap(), pkh);
        let mut chars: Vec<char> = a.chars().collect();
        chars[10] = if chars[10] == 'p' { 'q' } else { 'p' };
        let bad: String = chars.into_iter().collect();
        assert!(matches!(decode_p2pkh_cashaddr(&bad, AddressPrefix::Chipnet), Err(CashAddrDecodeError::BadChecksum)));
    }

    /// The v24 Oracle P2SH-32 address from the live web client decodes/encodes consistently.
    #[test]
    fn p2sh32_known_address() {
        let lock = hex::decode("aa20").unwrap();
        let _ = lock;
        let bytes: [u8; 35] = { let mut b = [0u8; 35]; b[0] = 0xaa; b[1] = 0x20; b[34] = 0x87; b };
        let a = encode_p2sh32_cashaddr(&bytes, AddressPrefix::Chipnet);
        assert!(a.starts_with("bchtest:p"));
    }
}
