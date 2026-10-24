//! Exact decimal parsing of exchange price strings into 1e-8 USD units.
//!
//! No floating point anywhere: v23's F14 incident came from `"1.5e3"` being truncated to 1.5 by
//! a lenient parser. Here anything that is not `digits[.digits]` is rejected outright; more than
//! eight fractional digits round half-up to the eighth.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PriceError {
    #[error("empty price string")]
    Empty,
    #[error("price contains a character other than digits and one dot: {0:?}")]
    BadChar(char),
    #[error("price has no digits around the decimal point")]
    NoDigits,
    #[error("price integer part exceeds 11 digits")]
    TooLarge,
    #[error("price is zero")]
    Zero,
}

pub const SCALE: u64 = 100_000_000;

/// Parse `"277.15"` → `27_715_000_000`.
pub fn parse_price_1e8(s: &str) -> Result<u64, PriceError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(PriceError::Empty);
    }
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, f),
        None => (s, ""),
    };
    if int_part.is_empty() && frac_part.is_empty() {
        return Err(PriceError::NoDigits);
    }
    for c in int_part.chars().chain(frac_part.chars()) {
        if !c.is_ascii_digit() {
            return Err(PriceError::BadChar(c));
        }
    }
    let int_digits = int_part.trim_start_matches('0');
    if int_digits.len() > 11 {
        return Err(PriceError::TooLarge);
    }
    let int_val: u64 = if int_digits.is_empty() { 0 } else { int_digits.parse().unwrap() };
    let mut frac_val: u64 = 0;
    let mut round_up = false;
    for (i, c) in frac_part.chars().enumerate() {
        let d = c.to_digit(10).unwrap() as u64;
        if i < 8 {
            frac_val = frac_val * 10 + d;
        } else if i == 8 {
            round_up = d >= 5;
        }
    }
    let taken = frac_part.len().min(8);
    frac_val *= 10u64.pow((8 - taken) as u32);
    let mut value = int_val * SCALE + frac_val;
    if round_up {
        value += 1;
    }
    if value == 0 {
        return Err(PriceError::Zero);
    }
    Ok(value)
}

/// `27_715_000_000` → `"277.15000000"`.
pub fn format_price_1e8(v: u64) -> String {
    format!("{}.{:08}", v / SCALE, v % SCALE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_decimals() {
        assert_eq!(parse_price_1e8("277.15"), Ok(27_715_000_000));
        assert_eq!(parse_price_1e8("285.20000000"), Ok(28_520_000_000));
        assert_eq!(parse_price_1e8("277"), Ok(27_700_000_000));
        assert_eq!(parse_price_1e8("0.5"), Ok(50_000_000));
        assert_eq!(parse_price_1e8(".5"), Ok(50_000_000));
        assert_eq!(parse_price_1e8("5."), Ok(500_000_000));
    }

    #[test]
    fn rounding_half_up_at_ninth_digit() {
        assert_eq!(parse_price_1e8("1.123456785"), Ok(112_345_679));
        assert_eq!(parse_price_1e8("1.123456784"), Ok(112_345_678));
        assert_eq!(parse_price_1e8("1.1234567849999"), Ok(112_345_678));
    }

    #[test]
    fn rejects_everything_else() {
        assert_eq!(parse_price_1e8("1.5e3"), Err(PriceError::BadChar('e')));
        assert_eq!(parse_price_1e8("-5"), Err(PriceError::BadChar('-')));
        assert_eq!(parse_price_1e8("+5"), Err(PriceError::BadChar('+')));
        assert_eq!(parse_price_1e8("1,5"), Err(PriceError::BadChar(',')));
        assert_eq!(parse_price_1e8(""), Err(PriceError::Empty));
        assert_eq!(parse_price_1e8("."), Err(PriceError::NoDigits));
        assert_eq!(parse_price_1e8("0"), Err(PriceError::Zero));
        assert_eq!(parse_price_1e8("123456789012"), Err(PriceError::TooLarge));
    }

    #[test]
    fn format_roundtrip() {
        assert_eq!(format_price_1e8(27_715_000_000), "277.15000000");
        assert_eq!(parse_price_1e8(&format_price_1e8(1)), Ok(1));
    }
}
