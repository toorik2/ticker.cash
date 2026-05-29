//! Bitcoin Script primitives — push opcodes and small helpers.
//!
//! Spec: https://reference.cash/protocol/blockchain/script.html
//!
//! For data pushes ≤ 75 bytes, the length byte IS the opcode (`0x01..=0x4B`).
//! For larger pushes, we use `OP_PUSHDATA1` / `OP_PUSHDATA2` / `OP_PUSHDATA4`.

// ─── Push opcodes ──────────────────────────────────────────────────────────

pub const OP_0:        u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE:  u8 = 0x4f;
pub const OP_1:        u8 = 0x51;
// ... OP_2..OP_16 = 0x52..0x60

// ─── Stack / hash / sig opcodes (the ones we actually emit) ────────────────

pub const OP_DUP:           u8 = 0x76;
pub const OP_EQUALVERIFY:   u8 = 0x88;
pub const OP_HASH160:       u8 = 0xa9;
pub const OP_CHECKSIG:      u8 = 0xac;

/// Append a minimal-encoded data push of `data` to `out`.
///
/// Encoding rules (Bitcoin standard, BIP-62 minimal-push):
/// - empty payload  → `OP_0` (single byte `0x00`).
/// - 1-byte value 1..=16 → `OP_1..OP_16` (single byte).
/// - 1-byte value 0x81 (`-1`) → `OP_1NEGATE`.
/// - len 1..=75   → length byte then data.
/// - len 76..=255 → `OP_PUSHDATA1` + u8 length + data.
/// - len 256..=65535 → `OP_PUSHDATA2` + u16 LE length + data.
/// - len 65536..  → `OP_PUSHDATA4` + u32 LE length + data.
pub fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        out.push(OP_0);
        return;
    }
    // Minimal-push: single-byte 0x01..=0x10 collapses to OP_1..OP_16.
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

/// Append a minimal-encoded integer push (Script Number encoding) to `out`.
///
/// Script Number: signed magnitude little-endian, with sign bit on the MSByte.
/// Values 0..=16 and -1 collapse to single-byte opcodes via `push_data`.
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
    // If high bit of last byte is set, append a sign byte; otherwise set the sign bit in place.
    if buf.last().unwrap() & 0x80 != 0 {
        buf.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *buf.last_mut().unwrap() |= 0x80;
    }
    push_data(out, &buf);
}

/// P2PKH locking script: `OP_DUP OP_HASH160 <20 B pkh> OP_EQUALVERIFY OP_CHECKSIG` (25 bytes).
pub fn p2pkh_locking_script(pkh: &[u8; 20]) -> [u8; 25] {
    let mut s = [0u8; 25];
    s[0] = OP_DUP;
    s[1] = OP_HASH160;
    s[2] = 20; // push 20 bytes
    s[3..23].copy_from_slice(pkh);
    s[23] = OP_EQUALVERIFY;
    s[24] = OP_CHECKSIG;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_push_is_op_0() {
        let mut s = Vec::new();
        push_data(&mut s, &[]);
        assert_eq!(s, vec![OP_0]);
    }

    #[test]
    fn small_int_push_collapses() {
        let mut s = Vec::new();
        push_data(&mut s, &[0x05]);
        assert_eq!(s, vec![OP_1 + 4]); // OP_5
    }

    #[test]
    fn neg_one_push_collapses() {
        let mut s = Vec::new();
        push_data(&mut s, &[0x81]);
        assert_eq!(s, vec![OP_1NEGATE]);
    }

    #[test]
    fn push_75_bytes_uses_length_opcode() {
        let mut s = Vec::new();
        let payload = vec![0u8; 75];
        push_data(&mut s, &payload);
        assert_eq!(s[0], 75);
        assert_eq!(s.len(), 76);
    }

    #[test]
    fn push_76_bytes_uses_pushdata1() {
        let mut s = Vec::new();
        let payload = vec![0u8; 76];
        push_data(&mut s, &payload);
        assert_eq!(s[0], OP_PUSHDATA1);
        assert_eq!(s[1], 76);
        assert_eq!(s.len(), 78);
    }

    #[test]
    fn push_256_bytes_uses_pushdata2() {
        let mut s = Vec::new();
        let payload = vec![0u8; 256];
        push_data(&mut s, &payload);
        assert_eq!(s[0], OP_PUSHDATA2);
        assert_eq!(&s[1..3], &256u16.to_le_bytes());
        assert_eq!(s.len(), 3 + 256);
    }

    #[test]
    fn push_int_zero_is_op_0() {
        let mut s = Vec::new();
        push_int(&mut s, 0);
        assert_eq!(s, vec![OP_0]);
    }

    #[test]
    fn push_int_one_is_op_1() {
        let mut s = Vec::new();
        push_int(&mut s, 1);
        assert_eq!(s, vec![OP_1]);
    }

    #[test]
    fn push_int_127_is_one_byte() {
        let mut s = Vec::new();
        push_int(&mut s, 127);
        assert_eq!(s, vec![0x01, 0x7f]);
    }

    /// 128 requires a sign-byte to disambiguate from negative.
    #[test]
    fn push_int_128_requires_sign_byte() {
        let mut s = Vec::new();
        push_int(&mut s, 128);
        assert_eq!(s, vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn push_int_negative_uses_sign_bit() {
        let mut s = Vec::new();
        push_int(&mut s, -5);
        assert_eq!(s, vec![0x01, 0x85]);
    }

    #[test]
    fn p2pkh_locking_script_shape() {
        let pkh = [0x42u8; 20];
        let s = p2pkh_locking_script(&pkh);
        assert_eq!(s[0], OP_DUP);
        assert_eq!(s[1], OP_HASH160);
        assert_eq!(s[2], 20);
        assert_eq!(&s[3..23], &pkh);
        assert_eq!(s[23], OP_EQUALVERIFY);
        assert_eq!(s[24], OP_CHECKSIG);
    }
}
