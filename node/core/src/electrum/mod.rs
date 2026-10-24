//! Blocking Electrum/Fulcrum JSON-RPC client with endpoint failover.

pub mod client;
pub mod tls;
pub mod types;

pub use client::{ElectrumClient, ElectrumError, Endpoint};
pub use types::{NftCapability, TokenData, Utxo};
