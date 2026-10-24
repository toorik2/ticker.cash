//! The exchange registry: every endpoint a table row may name.
//!
//! The registry is append-only. An `id` is never reused or redefined, because it is the `source`
//! byte of every statement a row ever signed; a statement must stay interpretable after the
//! exchange behind it is gone. Replacing an exchange means a new id and a new table (a re-genesis).
//! Each table row of a deployment names one entry by `id`. A notary configured for a row accepts only sessions to that source's host,
//! with that path, and extracts the price from the JSON at the first pointer that resolves.
//! Pointers follow RFC 6901. Numbers are read from their exact JSON text (serde_json's
//! `arbitrary_precision`), never through a float.

use crate::price::{parse_price_1e8, PriceError};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    Usd,
    Usdc,
    Usdt,
}

#[derive(Debug, Clone, Copy)]
pub struct Source {
    pub id: u8,
    /// Stable slug, used in configuration and logs.
    pub name: &'static str,
    /// Display name of the exchange.
    pub label: &'static str,
    pub host: &'static str,
    pub path: &'static str,
    pub quote: Quote,
    /// JSON pointers tried in order; the first that resolves to a string or number wins.
    pub pointers: &'static [&'static str],
}

pub const SOURCES: [Source; 16] = [
    Source { id: 1, name: "kraken", label: "Kraken", host: "api.kraken.com", path: "/0/public/Ticker?pair=BCHUSD", quote: Quote::Usd, pointers: &["/result/BCHUSD/c/0"] },
    Source { id: 2, name: "coinbase", label: "Coinbase", host: "api.coinbase.com", path: "/v2/prices/BCH-USD/spot", quote: Quote::Usd, pointers: &["/data/amount"] },
    Source { id: 3, name: "gemini", label: "Gemini", host: "api.gemini.com", path: "/v1/pubticker/bchusd", quote: Quote::Usd, pointers: &["/last"] },
    // retired 2026-10-24: Binance.US BCH/USD traded 0.03 BCH in 24 h (one trade). Kept for old statements.
    Source { id: 4, name: "binance_us", label: "Binance.US", host: "api.binance.us", path: "/api/v3/ticker/price?symbol=BCHUSD", quote: Quote::Usd, pointers: &["/price"] },
    Source { id: 5, name: "bitstamp", label: "Bitstamp", host: "www.bitstamp.net", path: "/api/v2/ticker/bchusd/", quote: Quote::Usd, pointers: &["/last"] },
    Source { id: 6, name: "cryptocom", label: "Crypto.com", host: "api.crypto.com", path: "/v2/public/get-ticker?instrument_name=BCH_USD", quote: Quote::Usd, pointers: &["/result/data/0/a", "/result/data/a"] },
    Source { id: 7, name: "bitfinex", label: "Bitfinex", host: "api-pub.bitfinex.com", path: "/v2/tickers?symbols=tBCHN:USD", quote: Quote::Usd, pointers: &["/0/7"] },
    // retired 2026-10-24: EXMO delisted BCH_USD (the pointer no longer resolves). Kept for old statements.
    Source { id: 8, name: "exmo", label: "EXMO", host: "api.exmo.com", path: "/v1.1/ticker", quote: Quote::Usd, pointers: &["/BCH_USD/last_trade"] },
    // retired 2026-10-24: Independent Reserve BCH/USD had no trade since 2026-09-23. Kept for old statements.
    Source { id: 9, name: "independentreserve", label: "Independent Reserve", host: "api.independentreserve.com", path: "/Public/GetMarketSummary?primaryCurrencyCode=Bch&secondaryCurrencyCode=Usd", quote: Quote::Usd, pointers: &["/LastPrice"] },
    Source { id: 10, name: "okx_usdc", label: "OKX", host: "www.okx.com", path: "/api/v5/market/ticker?instId=BCH-USDC", quote: Quote::Usdc, pointers: &["/data/0/last"] },
    Source { id: 11, name: "kucoin_usdc", label: "KuCoin", host: "api.kucoin.com", path: "/api/v1/market/orderbook/level1?symbol=BCH-USDC", quote: Quote::Usdc, pointers: &["/data/price"] },
    Source { id: 12, name: "bybit", label: "Bybit", host: "api.bybit.com", path: "/v5/market/tickers?category=spot&symbol=BCHUSDT", quote: Quote::Usdt, pointers: &["/result/list/0/lastPrice"] },
    Source { id: 13, name: "htx", label: "HTX", host: "api.huobi.pro", path: "/market/detail?symbol=bchusdt", quote: Quote::Usdt, pointers: &["/tick/close"] },
    Source { id: 14, name: "gateio", label: "Gate.io", host: "api.gateio.ws", path: "/api/v4/spot/tickers?currency_pair=BCH_USDT", quote: Quote::Usdt, pointers: &["/0/last"] },
    Source { id: 15, name: "bitget", label: "Bitget", host: "api.bitget.com", path: "/api/v2/spot/market/tickers?symbol=BCHUSDT", quote: Quote::Usdt, pointers: &["/data/0/lastPr"] },
    // api.binance.com answers HTTP 451 to US addresses; a US operator takes another row.
    Source { id: 16, name: "binance_usdc", label: "Binance", host: "api.binance.com", path: "/api/v3/ticker/price?symbol=BCHUSDC", quote: Quote::Usdc, pointers: &["/price"] },
];

pub fn source_by_id(id: u8) -> Option<&'static Source> {
    SOURCES.iter().find(|s| s.id == id)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExtractError {
    #[error("body is not JSON: {0}")]
    NotJson(String),
    #[error("no pointer resolved to a price")]
    NoPointer,
    #[error("price field is neither string nor number")]
    BadType,
    #[error("price: {0}")]
    Price(#[from] PriceError),
}

impl Source {
    /// Extract the price (1e-8 USD) from a JSON response body.
    pub fn extract_price(&self, body: &[u8]) -> Result<u64, ExtractError> {
        let v: Value = serde_json::from_slice(body).map_err(|e| ExtractError::NotJson(e.to_string()))?;
        for p in self.pointers {
            if let Some(node) = v.pointer(p) {
                let text = match node {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => return Err(ExtractError::BadType),
                };
                return Ok(parse_price_1e8(&text)?);
            }
        }
        Err(ExtractError::NoPointer)
    }

    pub fn url(&self) -> String {
        format!("https://{}{}", self.host, self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(id: u8) -> &'static Source {
        source_by_id(id).unwrap()
    }

    /// Append-only: ids are contiguous from 1 and never reused; each host appears once.
    #[test]
    fn ids_are_contiguous_and_hosts_unique() {
        let ids: Vec<u8> = SOURCES.iter().map(|s| s.id).collect();
        assert_eq!(ids, (1..=SOURCES.len() as u8).collect::<Vec<u8>>());
        let mut hosts: Vec<&str> = SOURCES.iter().map(|s| s.host).collect();
        hosts.sort();
        hosts.dedup();
        assert_eq!(hosts.len(), SOURCES.len());
    }

    /// Bodies captured in the M0 benchmark (2026-10-24).
    #[test]
    fn extracts_from_live_shapes() {
        assert_eq!(s(1).extract_price(br#"{"error":[],"result":{"BCHUSD":{"a":["277.060000","7","7.000"],"b":["276.930000","1","1.000"],"c":["277.150000","0.16164102"]}}}"#).unwrap(), 27_715_000_000);
        assert_eq!(s(2).extract_price(br#"{"data":{"amount":"277.37","base":"BCH","currency":"USD"}}"#).unwrap(), 27_737_000_000);
        assert_eq!(s(3).extract_price(br#"{"bid":"276.97000","ask":"277.01000","last":"277.18000","volume":{"BCH":"92.73"}}"#).unwrap(), 27_718_000_000);
        assert_eq!(s(4).extract_price(br#"{"symbol":"BCHUSD","price":"285.20000000"}"#).unwrap(), 28_520_000_000);
        assert_eq!(s(5).extract_price(br#"{"timestamp":"1792849226","last":"277.14","volume":"1486.43"}"#).unwrap(), 27_714_000_000);
        assert_eq!(s(6).extract_price(br#"{"id":-1,"method":"public/get-tickers","code":0,"result":{"data":[{"i":"BCH_USD","a":"277.35"}]}}"#).unwrap(), 27_735_000_000);
        assert_eq!(s(7).extract_price(br#"[["tBCHN:USD",277.2,312.39,277.68,822.16,-8.49,-0.0297,277.19,25.12,287.71,274.42,1605446396270]]"#).unwrap(), 27_719_000_000);
        assert_eq!(s(8).extract_price(br#"{"ADA_USDC":{"last_trade":"0.194"},"BCH_USD":{"buy_price":"276.1","sell_price":"278.9","last_trade":"277.5"}}"#).unwrap(), 27_750_000_000);
        assert_eq!(s(9).extract_price(br#"{"DayHighestPrice":286.17,"LastPrice":279.91,"PrimaryCurrencyCode":"Bch"}"#).unwrap(), 27_991_000_000);
        assert_eq!(s(10).extract_price(br#"{"code":"0","data":[{"instType":"SPOT","instId":"BCH-USDC","last":"276.8"}]}"#).unwrap(), 27_680_000_000);
        assert_eq!(s(11).extract_price(br#"{"code":"200000","data":{"time":1792846048206,"price":"278.09"}}"#).unwrap(), 27_809_000_000);
        assert_eq!(s(12).extract_price(br#"{"retCode":0,"result":{"category":"spot","list":[{"symbol":"BCHUSDT","lastPrice":"277.28"}]}}"#).unwrap(), 27_728_000_000);
        assert_eq!(s(13).extract_price(br#"{"status":"ok","tick":{"close":277.13,"open":284.51}}"#).unwrap(), 27_713_000_000);
        // added 2026-10-24
        assert_eq!(s(14).extract_price(br#"[{"currency_pair":"BCH_USDT","last":"273.2","lowest_ask":"273.05","highest_bid":"272.95","base_volume":"1828.909994"}]"#).unwrap(), 27_320_000_000);
        assert_eq!(s(15).extract_price(br#"{"code":"00000","msg":"success","requestTime":1792852955355,"data":[{"open":"284","symbol":"BCHUSDT","lastPr":"272.8","bidPr":"272.8","askPr":"272.9"}]}"#).unwrap(), 27_280_000_000);
        assert_eq!(s(16).extract_price(br#"{"symbol":"BCHUSDC","price":"272.50000000"}"#).unwrap(), 27_250_000_000);
    }

    #[test]
    fn exact_text_for_numbers_no_float_drift() {
        // 0.1 + float drift would show as 0.10000000000000001; exact text must not
        assert_eq!(s(13).extract_price(br#"{"tick":{"close":0.1}}"#).unwrap(), 10_000_000);
        assert_eq!(s(9).extract_price(br#"{"LastPrice":1e3}"#), Err(ExtractError::Price(PriceError::BadChar('e'))));
    }

    #[test]
    fn failures_are_typed() {
        assert!(matches!(s(1).extract_price(b"garbage"), Err(ExtractError::NotJson(_))));
        assert_eq!(s(1).extract_price(br#"{"result":{}}"#), Err(ExtractError::NoPointer));
        assert_eq!(s(2).extract_price(br#"{"data":{"amount":[1]}}"#), Err(ExtractError::BadType));
    }
}
