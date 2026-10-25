//! ticker.cash v27 — a notarized BCH/USD price feed whose chain state is one 37-byte commitment.
//!
//! Module map:
//!   crypto     — sha256 / hash160, secp256k1 keys, BCH Schnorr (CHIP-2019-05) sign + verify
//!   commit     — the 17-byte snapshot (a General Protocols price message ‖ k) and the 37-byte head commitment (‖ tableHash)
//!   statement  — the 42-byte notary message, the signed Statement, and rotation Approvals
//!   price      — exact decimal parsing (no floats) of exchange price strings
//!   sources    — the append-only exchange registry: host, path, JSON pointer per source id
//!   httpx      — HTTPS GET with Mozilla roots (the notary's fetch) and HTTP/1.1 parsing
//!   tx         — CashTokens transaction encoder, scripts, sighash, CashAddr, covenant bytes, builders
//!   electrum   — blocking JSON-RPC client for Fulcrum (listunspent, broadcast, tip, median-time-past)
//!   keyfile    — 32-byte hex key loader with permission checks and zeroize-on-drop
//!   manifest   — the public deployment manifest (category, locks, notary table)
//!   logging    — JSON-per-line structured stdout
//!
//! Design rules carried by this crate (see docs/design/v27-plan.md):
//!   * The Oracle covenant reads its own input, the values of all inputs and its own outputs.
//!     Time is the start of the Unix minute the notaries signed; the chain enforces that it
//!     increases, that it leads median-time-past by at most six hours, and that the update counter
//!     advances by exactly one.
//!   * Fees are exactly `size + 1` sat. Every update is fixed-width before it is built.
//!   * The Ticker value is the exact dust floor (792 sats) and is pinned by the covenant.
//!   * `k`, the number of rows that signed, is written into every commitment: the floor is 7, the
//!     bar is the consumer's.

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

/// Rows that must sign an update (covenant literal, `Oracle.cash`).
pub const QUORUM: usize = 7;
/// Ticker outputs per update (covenant literal).
pub const TICKERS_PER_UPDATE: usize = 2;
/// Ticker value: the dust floor of a 116-byte P2S token output, 3 × (116 + 148), pinned exactly.
pub const TICKER_SATS: u64 = 792;
/// The v26 Ticker value, still met at the v26 Ticker lock until those Tickers are recycled.
pub const LEGACY_TICKER_SATS: u64 = 786;
/// A consumer adds at least this many sats to a Ticker it re-emits (`Ticker.consume`).
pub const TOLL_SATS: u64 = 1_000;
/// A Ticker may be recycled once its timestamp is this old by median-time-past (`Ticker.recycle`).
pub const TICKER_LIFE_SECS: u64 = 86_400;
/// The v26 Ticker lifetime (its commitment carries a minute, not a timestamp).
pub const LEGACY_TICKER_LIFE_SECS: u64 = 3_600;
/// An update's minute may lead median-time-past by at most this much (`Oracle.update`).
pub const SEQ_AHEAD_SECS: u64 = 21_600;
/// Fee cap an update or rotation may draw: base plus per byte of the head input's unlocking data.
pub const FEE_CAP_BASE_SATS: u64 = 1_000;
pub const FEE_CAP_PER_UNLOCK_BYTE: u64 = 2;
/// Bytes per notary table entry: compressed pubkey (33) ‖ source id (1).
pub const TABLE_ENTRY_LEN: usize = 34;
/// Largest table: `k` must encode as one positive script-number byte.
pub const MAX_ROWS: usize = 127;
/// Domain tags of the two signed messages.
pub const STATEMENT_TAG: u8 = 0x4e;
pub const APPROVAL_TAG: u8 = 0x52;
/// Input sequence number used on every input: non-final (so CHECKLOCKTIMEVERIFY applies) with the
/// BIP68 disable bit set (so no relative lock is implied).
pub const SEQUENCE_TIMELOCK: u32 = 0xffff_fffe;
/// Builder policy: recycled Tickers per update, bounding the transaction's width.
pub const MAX_RECYCLE_PER_UPDATE: usize = 10;
