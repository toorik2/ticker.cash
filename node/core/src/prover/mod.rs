//! Price prover — what the notary daemon uses to obtain a verifiable price for
//! a given source.
//!
//! Phase A (v12): [`HttpsPlainProver`] — plain HTTPS fetch + regex extraction +
//! Schnorr sign. Trust model: federated (notaries are members of the protocol's
//! covenant constructor pubkey list).
//!
//! Phase B (v13): the planned `TlsnProver` will capture and commit to a TLS
//! transcript per fetch (TLSNotary). Implemented behind a feature flag once the
//! v13 covenant ships.

pub mod extract;
pub mod http;
pub mod plain;
pub mod trait_;

pub use http::{https_get, HttpError};
pub use plain::HttpsPlainProver;
pub use trait_::{PriceProof, PriceProver, ProverError};
