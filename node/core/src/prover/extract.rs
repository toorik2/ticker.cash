//! Price extractors — per-source body-to-f64 logic for the 13 CEX endpoints.
//!
//! Mirrors `daemon/scripts/notary.ts:79-108` line-for-line. All patterns are
//! literal substring searches (no regex dep needed) plus one JSON parse for the
//! Bitfinex array form.

use serde_json::Value;

use crate::chain::sources::Source;

/// Per-source URL.
pub fn source_url(s: &Source) -> &'static str {
    match s.id {
        1 => "https://api.kraken.com/0/public/Ticker?pair=BCHUSD",
        2 => "https://api.coinbase.com/v2/prices/BCH-USD/spot",
        3 => "https://api.gemini.com/v1/pubticker/bchusd",
        4 => "https://api.binance.us/api/v3/ticker/price?symbol=BCHUSD",
        5 => "https://www.bitstamp.net/api/v2/ticker/bchusd",
        6 => "https://api.crypto.com/v2/public/get-ticker?instrument_name=BCH_USD",
        7 => "https://api-pub.bitfinex.com/v2/tickers?symbols=tBCHN:USD",
        8 => "https://api.exmo.com/v1.1/ticker",
        9 => "https://api.independentreserve.com/Public/GetMarketSummary?primaryCurrencyCode=Bch&secondaryCurrencyCode=Usd",
        10 => "https://www.okx.com/api/v5/market/ticker?instId=BCH-USDC",
        11 => "https://api.kucoin.com/api/v1/market/orderbook/level1?symbol=BCH-USDC",
        12 => "https://api.bybit.com/v5/market/tickers?category=spot&symbol=BCHUSDT",
        13 => "https://api.huobi.pro/market/detail?symbol=bchusdt",
        _ => "",
    }
}

/// Run the per-source extractor on the response body. Returns the price in USD
/// as `f64`, or `None` if the pattern doesn't match.
pub fn extract_price(source_id: u16, body: &str) -> Option<f64> {
    match source_id {
        // ── USD ──────────────────────────────────────────────────────────
        1 => extract_after_quoted(body, &[r#""BCHUSD":"#, r#""c":[""#]),
        2 => extract_after_quoted(body, &[r#""amount":""#]),
        3 => extract_after_quoted(body, &[r#""last":""#]),
        4 => extract_after_quoted(body, &[r#""price":""#]),
        5 => extract_after_quoted(body, &[r#""last":""#]),
        6 => extract_after_quoted(body, &[r#""a":""#]),
        7 => bitfinex_extract(body),
        8 => extract_after_quoted(body, &[r#""BCH_USD":"#, r#""last_trade":""#]),
        9 => extract_after_unquoted(body, r#""LastPrice":"#),
        // ── USDC ─────────────────────────────────────────────────────────
        10 => extract_after_quoted(body, &[r#""last":""#]),
        11 => extract_after_quoted(body, &[r#""price":""#]),
        // ── USDT ─────────────────────────────────────────────────────────
        12 => extract_after_quoted(body, &[r#""lastPrice":""#]),
        13 => extract_after_unquoted(body, r#""close":"#),
        _ => None,
    }
}

/// Walk through `prefixes` sequentially, advancing the cursor past each one;
/// at the end of the last prefix, parse digits + dot as f64.
///
/// v23 F14 — if the digit run is immediately followed by an exponent marker
/// (`e`/`E`) or an explicit sign (`+`/`-`), the upstream price is NOT a plain
/// decimal. Refuse instead of silently truncating (e.g. `"1.5e3"` had been
/// truncated to `1.5`, producing a 1000× wrong price).
fn extract_after_quoted(body: &str, prefixes: &[&str]) -> Option<f64> {
    let mut cursor = 0usize;
    for p in prefixes {
        let i = body[cursor..].find(p)? + cursor;
        cursor = i + p.len();
    }
    let rest = &body[cursor..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    if let Some(c) = rest[end..].chars().next() {
        if matches!(c, 'e' | 'E' | '+' | '-') {
            return None;
        }
    }
    rest[..end].parse().ok()
}

fn extract_after_unquoted(body: &str, prefix: &str) -> Option<f64> {
    extract_after_quoted(body, &[prefix])
}

/// Bitfinex returns `[[SYMBOL, BID, BID_SIZE, ASK, ASK_SIZE, DAILY_CHG, DAILY_CHG_REL, LAST_PRICE, ...]]`.
///
/// Note: serde_json parses JSON numerics into a canonical `f64` regardless of
/// their on-wire textual form (`1.5e3` → `1500.0` at parse time), so the F14
/// sci-notation gate that we apply to the substring extractors above is moot
/// here — the raw notation is gone by the time we see it. Downstream range
/// gate (`prover/plain.rs:45-49`) catches impossible magnitudes.
fn bitfinex_extract(body: &str) -> Option<f64> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.get(0)?.get(7)?.as_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kraken_synthetic() {
        let body = r#"{"error":[],"result":{"BCHUSD":{"a":["123.456","1","1.000"],"b":["123.4","1","1.000"],"c":["123.456","0.10"]}}}"#;
        assert_eq!(extract_price(1, body), Some(123.456));
    }

    #[test]
    fn coinbase_synthetic() {
        let body = r#"{"data":{"base":"BCH","currency":"USD","amount":"450.10"}}"#;
        assert_eq!(extract_price(2, body), Some(450.10));
    }

    #[test]
    fn independentreserve_unquoted() {
        let body = r#"{"LastPrice":312.99,"Volume":1234}"#;
        assert_eq!(extract_price(9, body), Some(312.99));
    }

    #[test]
    fn bitfinex_array_form() {
        // SYMBOL, BID, BID_SIZE, ASK, ASK_SIZE, DAILY_CHG, DAILY_CHG_REL, LAST_PRICE, ...
        let body = r#"[["tBCHN:USD", 250.1, 10.0, 250.5, 11.0, 5.0, 0.02, 333.42, 100, 320, 340]]"#;
        assert_eq!(extract_price(7, body), Some(333.42));
    }

    #[test]
    fn unknown_source_returns_none() {
        assert_eq!(extract_price(99, "anything"), None);
    }

    #[test]
    fn no_match_returns_none() {
        assert_eq!(extract_price(1, "garbage"), None);
    }

    #[test]
    fn htx_close_unquoted() {
        let body = r#"{"status":"ok","tick":{"close":250.5,"open":248.0}}"#;
        assert_eq!(extract_price(13, body), Some(250.5));
    }

    /// v23 F14 — substring extractors must REFUSE scientific notation rather
    /// than silently truncate. `1.5e3` had been truncated to `1.5`, producing
    /// a 1000× wrong price; rejection forces the daemon to drop the source
    /// instead of pricing on a fictitious decimal.
    #[test]
    fn rejects_scientific_notation_quoted() {
        let body = r#"{"data":{"amount":"1.5e3"}}"#;
        assert_eq!(extract_price(2, body), None);
    }

    #[test]
    fn rejects_scientific_notation_capital_e() {
        let body = r#"{"data":{"amount":"1.5E3"}}"#;
        assert_eq!(extract_price(2, body), None);
    }

    #[test]
    fn rejects_signed_exponent_unquoted() {
        let body = r#"{"LastPrice":1.5,"Volume":1234}"#;
        // sanity — plain decimal still works
        assert_eq!(extract_price(9, body), Some(1.5));
        let body_sci = r#"{"LastPrice":1.5e3,"Volume":1234}"#;
        assert_eq!(extract_price(9, body_sci), None);
    }

}
