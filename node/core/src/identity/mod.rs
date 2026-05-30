//! Identity resolution: manifest + per-operator key file.
//!
//! Runtime daemon convention:
//!
//! ```text
//!   .ticker/
//!     manifest.json       ← public bundle (contracts, slot list, electrum default)
//!     notary.key          ← 32 B hex, mode 0600 (notary operators only)
//!     publisher.key       ← 32 B hex, mode 0600 (publisher operators only)
//! ```
//!
//! No legacy seed-derived layout at runtime — operators must have the per-role
//! keyfile from their installer. The coordinator's `.ticker/seed.hex` is used
//! only by `ticker-ops` (see [`seed`]).

pub mod key;
pub mod manifest;
pub mod resolve;
pub mod seed;

pub use key::{load_operator_key, OperatorKey, OperatorKeyError};
pub use manifest::{
    load_manifest, ContractInfo, ElectrumDefault, Manifest, ManifestError, Network,
    TokenContractInfo,
};
pub use resolve::{resolve_identity, BaseIdentity, IdentityError, Role};
pub use seed::{derive_wallet, load_seed, SeedError, NOTARY_LABEL, PUBLISHER_LABEL, MASTER_LABEL};
