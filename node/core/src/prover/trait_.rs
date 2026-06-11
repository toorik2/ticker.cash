//! `PriceProver` trait — single implementation point for the publisher's price source.

use crate::chain::sources::Source;

/// Result of a successful price proof: a price + a timestamp + the canonical CN.
#[derive(Debug, Clone)]
pub struct PriceProof {
    /// USD price scaled by 1e8 (matching the covenant's price scale).
    pub price: u64,
    /// Publisher wall-clock at fetch time, unix seconds (u40 wire form; u64 in Rust).
    pub timestamp: u64,
    /// Canonical CN (server name) — committed to in the publisher's signed digest
    /// via `hash160(server_name)`.
    pub server_name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("HTTP fetch failed: {0}")]
    Http(#[from] super::http::HttpError),
    #[error("price extraction failed for source {source_name}: {reason}")]
    ExtractFailed {
        source_name: &'static str,
        reason: String,
    },
    #[error("unknown source id {0}")]
    UnknownSource(u16),
    #[error("clock error (pre-epoch): {0}")]
    Clock(#[from] std::time::SystemTimeError),
}

/// Anything that can produce a [`PriceProof`] for a [`Source`].
pub trait PriceProver {
    fn prove(&self, source: &Source) -> Result<PriceProof, ProverError>;
}
