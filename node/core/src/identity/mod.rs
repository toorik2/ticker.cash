//! Identity resolution: manifest + per-operator key file.
//!
//! Runtime daemon convention:
//!
//! ```text
//!   .ticker/
//!     manifest.json       ← public bundle (contracts, slot list, electrum default)
//!     publisher.key       ← 32 B hex, mode 0600
//! ```
//!
//! Operators must have the publisher keyfile from their installer. The
//! coordinator's `.ticker/seed.hex` is used only by `ticker-ops`
//! (see [`seed`]).

pub mod key;
pub mod manifest;
pub mod resolve;
pub mod seed;

pub use key::{load_operator_key, OperatorKey, OperatorKeyError};
pub use manifest::{
    load_manifest, load_manifest_hash_pinned, ContractInfo, ElectrumDefault, Manifest,
    ManifestError, Network, TokenContractInfo, MANIFEST_PIN_FILE,
};
pub use resolve::{resolve_identity, BaseIdentity, IdentityError};
pub use seed::{derive_wallet, load_seed, SeedError, MASTER_LABEL, PUBLISHER_LABEL};
