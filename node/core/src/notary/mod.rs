//! Notary HTTP server — `POST /sign`, `GET /health`.
//!
//! Loopback-only by default (matches the TS daemon's posture; the notary trusts
//! its co-located publisher process and isn't exposed to the public internet
//! without a separate reverse proxy).
//!
//! Hand-rolled HTTP/1.1, ~200 LOC. Thread-per-connection (no async runtime).
//! At ~0.5 RPS the model is unambiguous and avoids tokio entirely.

pub mod http;
pub mod server;
pub mod wire;

pub use server::{run_notary, NotaryHandler, NotaryServerError};
pub use wire::{SignRequest, SignResponse};
