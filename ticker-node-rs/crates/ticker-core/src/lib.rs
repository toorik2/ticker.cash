//! ticker.cash v12 protocol — Rust runtime.
//!
//! Module map:
//!   chain     — byte layouts, sig digests, SOURCES registry, protocol constants
//!   tx        — CashTokens-aware BCH transaction encoder, CashAddr, attest/update builders
//!   covenant  — embedded cashc artifacts, P2SH-32 locking-script derivation
//!   electrum  — JSON-RPC over rustls for Fulcrum (get_utxos, send_raw_tx)
//!   identity  — operator-key + manifest loaders (no legacy seed-derived at runtime)
//!   prover    — PriceProver trait + HttpsPlainProver (v12). TlsnProver lives behind feature "tlsn" [Phase B]
//!   cycle     — CycleState enum, CycleError, Env trait, pure step() transition, orchestrator loop
//!   http      — hand-rolled HTTP/1.1 client + server (notary, stats)
//!   logging   — structured stdout (JSON-per-line)

pub mod chain;
pub mod covenant;
pub mod crypto;
pub mod electrum;
pub mod identity;
pub mod prover;
pub mod tx;
