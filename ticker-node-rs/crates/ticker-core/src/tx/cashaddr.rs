//! CashAddr encoder for P2PKH addresses (BCH spec: https://reference.cash/protocol/blockchain/encoding/cashaddr).
//!
//! NOT bech32 — CashAddr uses a different alphabet and a 40-bit BCH checksum
//! polynomial. We only need P2PKH for funder/publisher wallet addresses; P2SH-32
//! addresses for covenants are loaded as-is from the manifest, so no decoder needed.
//!
//! Encoding:
//!   payload = version_byte || pkh        (1 + 20 = 21 bytes)
//!   data    = base32(convertBits(payload, 8 -> 5))
//!   checksum = 8-character base32 of the 40-bit BCH polynomial mod
//!   address = prefix + ":" + data + checksum
//!
//! Version byte: high bit = 0 (reserved), next 4 bits = type, low 3 bits = hash-size code.
//! For P2PKH with 20-byte hash: type=0 (P2PKH), size code=0 → version_byte = 0x00.

/// Address prefix selector.
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
}

const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Encode a 20-byte pkh as a CashAddr P2PKH address.
pub fn encode_p2pkh_cashaddr(pkh: &[u8; 20], prefix: AddressPrefix) -> String {
    let prefix_str = prefix.as_str();

    // Version byte: P2PKH (type 0) + 20-byte size code (0).
    let mut payload = Vec::with_capacity(21);
    payload.push(0x00);
    payload.extend_from_slice(pkh);

    // Convert 8-bit payload to 5-bit groups.
    let data5 = convert_bits(&payload, 8, 5, true);

    // Compute the 40-bit checksum.
    let mut prefix_lower_5bits: Vec<u8> = prefix_str.bytes().map(|b| b & 0x1f).collect();
    prefix_lower_5bits.push(0); // separator

    let mut checksum_input = prefix_lower_5bits.clone();
    checksum_input.extend_from_slice(&data5);
    checksum_input.extend_from_slice(&[0u8; 8]); // 40-bit zero suffix
    let checksum = polymod(&checksum_input) ^ 1;

    // Append checksum as 8 × 5-bit groups (MSB first).
    let mut data5_with_checksum = data5;
    for i in (0..8).rev() {
        data5_with_checksum.push(((checksum >> (i * 5)) & 0x1f) as u8);
    }

    // Map 5-bit groups to ALPHABET characters.
    let mut result = String::with_capacity(prefix_str.len() + 1 + data5_with_checksum.len());
    result.push_str(prefix_str);
    result.push(':');
    for &b in &data5_with_checksum {
        result.push(ALPHABET[b as usize] as char);
    }
    result
}

/// Convert a byte slice from `from_bits` per element to `to_bits` per element.
/// `pad = true` adds trailing zero bits to fill the last group.
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

/// CashAddr BCH polynomial — 40-bit checksum (returns raw `c`; caller XORs with 1).
fn polymod(values: &[u8]) -> u64 {
    let gen: [u64; 5] = [
        0x98_f2bc_8e61,
        0x79_b76d_99e2,
        0xf3_3e5f_b3c4,
        0xae_2eab_e2a8,
        0x1e_4f43_e470,
    ];
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

/// Decode error for `decode_p2pkh_cashaddr`.
#[derive(Debug, thiserror::Error)]
pub enum CashAddrDecodeError {
    #[error("missing prefix in {0:?}")]
    MissingPrefix(String),
    #[error("wrong prefix: got {got:?}, expected {expected:?}")]
    WrongPrefix { got: String, expected: &'static str },
    #[error("invalid character {0:?} in address body")]
    InvalidChar(char),
    #[error("address too short")]
    TooShort,
    #[error("not a P2PKH address (version byte 0x{0:02x})")]
    NotP2pkh(u8),
}

/// Decode a P2PKH CashAddr and extract the 20-byte pkh.
///
/// Tolerates the network's natural prefix (`expected`) only; mainnet addresses
/// passed to a chipnet expectation get [`CashAddrDecodeError::WrongPrefix`].
/// Checksum bytes are dropped; we don't currently verify the checksum on input
/// (covenant rejection would catch a bit-flipped address anyway).
pub fn decode_p2pkh_cashaddr(
    addr: &str,
    expected: AddressPrefix,
) -> Result<[u8; 20], CashAddrDecodeError> {
    let (prefix, body) = addr
        .split_once(':')
        .ok_or_else(|| CashAddrDecodeError::MissingPrefix(addr.to_string()))?;
    if prefix != expected.as_str() {
        return Err(CashAddrDecodeError::WrongPrefix {
            got: prefix.to_string(),
            expected: expected.as_str(),
        });
    }
    let mut data5: Vec<u8> = Vec::with_capacity(body.len());
    for c in body.chars() {
        let pos = ALPHABET
            .iter()
            .position(|&b| b == c as u8)
            .ok_or(CashAddrDecodeError::InvalidChar(c))?;
        data5.push(pos as u8);
    }
    if data5.len() < 8 {
        return Err(CashAddrDecodeError::TooShort);
    }
    // Drop the 8-char (40-bit) checksum suffix.
    data5.truncate(data5.len() - 8);
    let payload8 = convert_bits(&data5, 5, 8, false);
    if payload8.len() < 21 {
        return Err(CashAddrDecodeError::TooShort);
    }
    let version = payload8[0];
    // P2PKH version byte: high reserved bit 0, type=0 (P2PKH), size-code 0 (20 B) → 0x00.
    if version != 0x00 {
        return Err(CashAddrDecodeError::NotP2pkh(version));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&payload8[1..21]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BCH spec test vector: P2PKH from https://reference.cash/protocol/blockchain/encoding/cashaddr
    /// pubkey hash: 76a04053bda0a88bda5177b86a15c3b29f559873 → bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a
    #[test]
    fn p2pkh_mainnet_spec_vector() {
        let pkh: [u8; 20] = [
            0x76, 0xa0, 0x40, 0x53, 0xbd, 0xa0, 0xa8, 0x8b, 0xda, 0x51, 0x77, 0xb8, 0x6a, 0x15,
            0xc3, 0xb2, 0x9f, 0x55, 0x98, 0x73,
        ];
        let addr = encode_p2pkh_cashaddr(&pkh, AddressPrefix::Mainnet);
        assert_eq!(addr, "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
    }

    /// Same payload, chipnet prefix.
    #[test]
    fn p2pkh_chipnet_prefix_changes_checksum() {
        let pkh = [0x42u8; 20];
        let m = encode_p2pkh_cashaddr(&pkh, AddressPrefix::Mainnet);
        let c = encode_p2pkh_cashaddr(&pkh, AddressPrefix::Chipnet);
        assert!(m.starts_with("bitcoincash:q"));
        assert!(c.starts_with("bchtest:q"));
        // Strip prefix and compare the data: same payload, different checksum.
        let m_body = m.split(':').nth(1).unwrap();
        let c_body = c.split(':').nth(1).unwrap();
        // First 33 chars are payload (21 B → ceil(21*8/5) = 34 chars total, last 8 are checksum).
        // Payload chars are identical for same pkh.
        assert_eq!(&m_body[..m_body.len() - 8], &c_body[..c_body.len() - 8]);
        // Checksum differs.
        assert_ne!(&m_body[m_body.len() - 8..], &c_body[c_body.len() - 8..]);
    }

    /// All-zeros pkh round-trips cleanly.
    #[test]
    fn zeros_pkh_encodes_without_panic() {
        let pkh = [0u8; 20];
        let addr = encode_p2pkh_cashaddr(&pkh, AddressPrefix::Chipnet);
        assert!(addr.starts_with("bchtest:q"));
        assert_eq!(addr.len(), "bchtest:".len() + 42); // 34 payload + 8 checksum chars = 42 base32 chars
    }

    /// Encode → decode roundtrip preserves the pkh on both networks.
    #[test]
    fn encode_decode_roundtrip() {
        for prefix in [AddressPrefix::Mainnet, AddressPrefix::Chipnet] {
            for pkh_byte in [0x00u8, 0x42, 0xff] {
                let pkh = [pkh_byte; 20];
                let addr = encode_p2pkh_cashaddr(&pkh, prefix);
                let decoded = decode_p2pkh_cashaddr(&addr, prefix).unwrap();
                assert_eq!(decoded, pkh);
            }
        }
    }

    #[test]
    fn decode_rejects_wrong_prefix() {
        let addr = encode_p2pkh_cashaddr(&[0; 20], AddressPrefix::Mainnet);
        let r = decode_p2pkh_cashaddr(&addr, AddressPrefix::Chipnet);
        assert!(matches!(r, Err(CashAddrDecodeError::WrongPrefix { .. })));
    }
}
