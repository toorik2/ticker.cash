//! Price prover — how a publisher obtains a price for its pinned source.
//!
//! Today the only impl is [`HttpsPlainProver`] — plain HTTPS fetch + per-source
//! extractor. Trust model: federated (the 13 publishers' median is the
//! protocol's source of truth).

pub mod extract;
pub mod http;
pub mod plain;
pub mod trait_;

pub use http::{https_get, HttpError};
pub use plain::HttpsPlainProver;
pub use trait_::{PriceProof, PriceProver, ProverError};
