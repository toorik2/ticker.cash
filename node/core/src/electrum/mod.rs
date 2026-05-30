//! Minimal Electrum/Fulcrum client.
//!
//! Line-framed JSON-RPC over a TLS-wrapped TCP socket. Implements only the
//! two methods the daemon uses:
//!
//!   * `blockchain.address.listunspent` — BCH-Fulcrum extension that returns
//!     the CashTokens-extended UTXO list including `token_data` (category,
//!     capability, commitment).
//!   * `blockchain.transaction.broadcast` — submit a raw tx hex; returns its txid.

pub mod client;
pub mod tls;
pub mod types;

pub use client::{ElectrumClient, ElectrumError, Endpoint};
pub use tls::tls_client_config;
pub use types::{NftCapability, TokenData, Utxo};
