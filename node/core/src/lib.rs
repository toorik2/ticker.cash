//! ticker.cash v25 — Proof-of-Fetch oracle, protocol core.
//!
//! Module map:
//!   crypto     — sha256 / hash160, secp256k1 keys, BCH Schnorr (CHIP-2019-05) sign + verify
//!   commit     — the 12-byte head/Ticker commitment: seq (u32 Unix minute) ‖ price (u64, 1e-8 USD)
//!   statement  — the 47-byte notary message and the signed Statement that travels to builders
//!   price      — exact decimal parsing (no floats) of exchange price strings
//!   sources    — the 13 pinned exchange endpoints and their JSON extraction paths
//!   httpx      — minimal HTTP/1.1 request/response parsing for revealed TLS transcripts
//!   tx         — CashTokens transaction encoder, scripts, sighash, CashAddr, covenant bytes, builders
//!   electrum   — blocking JSON-RPC client for Fulcrum (listunspent, broadcast, tip)
//!   keyfile    — 32-byte hex key loader with permission checks and zeroize-on-drop
//!   manifest   — the public deployment manifest (category, locks, notary table)
//!   logging    — JSON-per-line structured stdout
//!
//! Design rules carried by this crate (see docs/design/v25-plan.md):
//!   * The Oracle covenant reads no foreign inputs and no clock. Time is the Unix minute the
//!     notary majority signed; consensus enforces only `seq > previous`.
//!   * Fees are exactly `size + 1` sat. Every update is fixed-width before it is built.
//!   * Ticker value is the exact dust floor (708 sats) and is pinned by the covenant.

pub mod commit;
pub mod crypto;
pub mod electrum;
pub mod httpx;
pub mod keyfile;
pub mod logging;
pub mod manifest;
pub mod price;
pub mod sources;
pub mod statement;
pub mod tx;

/// Quorum: statements required per update (covenant literal, `Oracle.cash`).
pub const QUORUM: usize = 7;
/// Rows in the notary table (covenant literal: `table.length == 13 * 34`).
pub const ROWS: usize = 13;
/// Ticker outputs per update (covenant literal).
pub const TICKERS_PER_UPDATE: usize = 2;
/// Ticker value: the dust floor of an 88-byte P2S token output, pinned by the covenant.
pub const TICKER_SATS: u64 = 708;
/// Reserve cap: the head may lose at most this many sats per update (covenant literal).
pub const RESERVE_CAP_SATS: u64 = 5_000;
/// Sweep age for Tickers in legacy relative-lock units (600 ticks each).
pub const TICKER_SWEEP_UNITS: u32 = 144;
/// Statement domain tag.
pub const STATEMENT_TAG: u8 = 0x4e;
