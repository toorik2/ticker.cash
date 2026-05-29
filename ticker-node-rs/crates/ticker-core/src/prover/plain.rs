//! `HttpsPlainProver` — v12 implementation.
//!
//! Fetch the source URL over HTTPS, run the per-source extractor, scale to
//! satoshi precision, stamp the timestamp. No transcript proof — federated
//! trust (notaries are members of the protocol's covenant pubkey list).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::extract::{extract_price, source_url};
use super::http::https_get;
use super::trait_::{PriceProof, PriceProver, ProverError};
use crate::chain::sources::Source;

/// Default per-request timeout (matches the TS daemon's `AbortController` at 5 s).
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Plain HTTPS + regex/JSON extract + Schnorr-sign at the call-site.
#[derive(Debug, Clone)]
pub struct HttpsPlainProver {
    pub timeout: Duration,
}

impl Default for HttpsPlainProver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_FETCH_TIMEOUT,
        }
    }
}

impl PriceProver for HttpsPlainProver {
    fn prove(&self, source: &Source) -> Result<PriceProof, ProverError> {
        let url = source_url(source);
        if url.is_empty() {
            return Err(ProverError::UnknownSource(source.id));
        }
        let (_status, body) = https_get(url, self.timeout)?;
        let usd = extract_price(source.id, &body).ok_or_else(|| ProverError::ExtractFailed {
            source_name: source.name,
            reason: format!("no price found in body of len {}", body.len()),
        })?;
        if !usd.is_finite() || usd <= 0.0 {
            return Err(ProverError::ExtractFailed {
                source_name: source.name,
                reason: format!("invalid usd: {usd}"),
            });
        }
        let price = (usd * 1e8).round() as u64;
        if price == 0 {
            return Err(ProverError::ExtractFailed {
                source_name: source.name,
                reason: "scaled price rounded to 0".to_string(),
            });
        }
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
        Ok(PriceProof {
            price,
            timestamp,
            server_name: source.canonical_cn.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::sources::SOURCES;

    /// All 13 source URLs are well-formed.
    #[test]
    fn all_source_urls_nonempty() {
        for s in SOURCES.iter() {
            assert!(!source_url(s).is_empty(), "no url for source {}", s.name);
            assert!(source_url(s).starts_with("https://"));
        }
    }

    #[test]
    fn unknown_source_id_yields_error() {
        let p = HttpsPlainProver::default();
        let fake = Source {
            id: 99,
            name: "fake",
            canonical_cn: "nowhere",
        };
        assert!(matches!(p.prove(&fake), Err(ProverError::UnknownSource(99))));
    }
}
