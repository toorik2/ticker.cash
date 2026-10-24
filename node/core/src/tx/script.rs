//! Bitcoin Script pushes and the few opcodes the builders emit.

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_1: u8 = 0x51;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CHECKSIG: u8 = 0xac;

/// Minimal-encoded data push (BIP-62 rules: `OP_0` for empty, `OP_1..16` for one-byte 1..16,
/// `OP_1NEGATE` for 0x81, length byte up to 75, then PUSHDATA1/2/4).
pub fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        out.push(OP_0);
        return;
    }
    if data.len() == 1 {
        let b = data[0];
        if b == 0x81 {
            out.push(OP_1NEGATE);
            return;
        }
        if (0x01..=0x10).contains(&b) {
            out.push(OP_1 + (b - 1));
            return;
        }
    }
    let len = data.len();
    if len <= 75 {
        out.push(len as u8);
    } else if len <= u8::MAX as usize {
        out.push(OP_PUSHDATA1);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(OP_PUSHDATA2);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Minimal script-number push.
pub fn push_int(out: &mut Vec<u8>, n: i64) {
    if n == 0 {
        out.push(OP_0);
        return;
    }
    let negative = n < 0;
    let mut abs = n.unsigned_abs();
    let mut buf = Vec::with_capacity(8);
    while abs > 0 {
        buf.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    if buf.last().unwrap() & 0x80 != 0 {
        buf.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *buf.last_mut().unwrap() |= 0x80;
    }
    push_data(out, &buf);
}

/// `OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_locking_script(pkh: &[u8; 20]) -> [u8; 25] {
    let mut s = [0u8; 25];
    s[0] = OP_DUP;
    s[1] = OP_HASH160;
    s[2] = 20;
    s[3..23].copy_from_slice(pkh);
    s[23] = OP_EQUALVERIFY;
    s[24] = OP_CHECKSIG;
    s
}

/// `OP_HASH256 <32-byte hash> OP_EQUAL` for a redeem script.
pub fn p2sh32_locking_script(redeem: &[u8]) -> [u8; 35] {
    let h = crate::crypto::double_sha256(redeem);
    let mut s = [0u8; 35];
    s[0] = OP_HASH256;
    s[1] = 32;
    s[2..34].copy_from_slice(&h);
    s[34] = OP_EQUAL;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pushes_are_minimal() {
        let mut s = Vec::new();
        push_data(&mut s, &[]);
        push_data(&mut s, &[5]);
        push_data(&mut s, &[0x81]);
        push_data(&mut s, &[0x80]);
        assert_eq!(s, vec![OP_0, OP_1 + 4, OP_1NEGATE, 0x01, 0x80]);
        let mut s = Vec::new();
        push_data(&mut s, &[0u8; 76]);
        assert_eq!(&s[..2], &[OP_PUSHDATA1, 76]);
        let mut s = Vec::new();
        push_data(&mut s, &[0u8; 442]);
        assert_eq!(&s[..3], &[OP_PUSHDATA2, 0xba, 0x01]);
    }

    #[test]
    fn ints() {
        let mut s = Vec::new();
        push_int(&mut s, 0);
        push_int(&mut s, 1);
        push_int(&mut s, 127);
        push_int(&mut s, 128);
        push_int(&mut s, -5);
        assert_eq!(s, vec![OP_0, OP_1, 0x01, 0x7f, 0x02, 0x80, 0x00, 0x01, 0x85]);
    }

    #[test]
    fn p2sh32_shape() {
        let s = p2sh32_locking_script(b"abc");
        assert_eq!(s[0], OP_HASH256);
        assert_eq!(s[1], 32);
        assert_eq!(s[34], OP_EQUAL);
    }
}
