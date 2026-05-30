//! ticker.cash v13 protocol — Rust runtime.
//!
//! Module map:
//!   chain     — byte layouts, sig digests, SOURCES registry, protocol constants
//!   tx        — CashTokens-aware BCH transaction encoder, CashAddr, attest/update builders
//!   covenant  — embedded cashc artifacts, P2SH-32 locking-script derivation
//!   electrum  — JSON-RPC over rustls for Fulcrum (get_utxos, send_raw_tx)
//!   identity  — operator-key + manifest loaders
//!   prover    — PriceProver trait + HttpsPlainProver (publisher fetches price in-process)
//!   cycle     — CycleState enum, CycleError, Env trait, pure step() transition, orchestrator loop
//!   http      — hand-rolled HTTP/1.1 request parser + response writer (used by /stats)
//!   logging   — structured stdout (JSON-per-line)
//!
//! v13 dropped the notary tier (see PR13a / Phase B). What used to be `notary/`
//! and the `POST /sign` HTTP path no longer exists.

pub mod chain;
pub mod covenant;
pub mod crypto;
pub mod cycle;
pub mod electrum;
pub mod http;
pub mod identity;
pub mod logging;
pub mod prover;
pub mod stats;
pub mod tx;
