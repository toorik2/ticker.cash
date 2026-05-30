//! Identity resolver: load manifest + load key + derive slot via manifest lookup.
//!
//! No legacy seed-derived fallback. Operators run a v12 binary that requires
//! the per-operator install layout (manifest.json + per-role key file).

use super::key::{load_operator_key, OperatorKey, OperatorKeyError};
use super::manifest::{load_manifest, Manifest, ManifestError};
use std::path::Path;

/// Which role this process runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Notary,
    Publisher,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Notary => "notary",
            Role::Publisher => "publisher",
        }
    }
    /// Default keyfile path for this role under `.ticker/`.
    pub fn default_key_path(self) -> &'static str {
        match self {
            Role::Notary => ".ticker/notary.key",
            Role::Publisher => ".ticker/publisher.key",
        }
    }
}

/// Result of resolving an operator's identity at startup.
#[derive(Debug, Clone)]
pub struct BaseIdentity {
    pub role: Role,
    pub slot: u8,
    pub key: OperatorKey,
    pub manifest: Manifest,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    OperatorKey(#[from] OperatorKeyError),
    #[error(
        "{role} key identity {ident_hex} not found in manifest's {role} list.\n\
         wrong installer? wrong manifest? verify with your coordinator."
    )]
    KeyNotInManifest {
        role: &'static str,
        ident_hex: String,
    },
    #[error("--slot {supplied} disagrees with derived slot {derived} (from key); omit --slot")]
    SlotFlagMismatch { supplied: u8, derived: u8 },
}

/// Resolve the operator's slot, key, and manifest. `slot_flag` is optional and
/// must agree with the derived slot when supplied.
pub fn resolve_identity(
    role: Role,
    manifest_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    slot_flag: Option<u8>,
) -> Result<BaseIdentity, IdentityError> {
    let manifest = load_manifest(manifest_path)?;
    let key = load_operator_key(key_path, role.name())?;

    let (ident_hex, slot) = match role {
        Role::Notary => {
            let id_hex = hex::encode(key.public_key);
            let slot = manifest
                .notary_pubkeys
                .iter()
                .position(|p| p == &id_hex)
                .ok_or_else(|| IdentityError::KeyNotInManifest {
                    role: "notary",
                    ident_hex: id_hex.clone(),
                })?;
            (id_hex, slot as u8)
        }
        Role::Publisher => {
            let id_hex = hex::encode(key.pkh);
            let slot = manifest
                .publisher_pkhs
                .iter()
                .position(|p| p == &id_hex)
                .ok_or_else(|| IdentityError::KeyNotInManifest {
                    role: "publisher",
                    ident_hex: id_hex.clone(),
                })?;
            (id_hex, slot as u8)
        }
    };

    if let Some(s) = slot_flag {
        if s != slot {
            return Err(IdentityError::SlotFlagMismatch {
                supplied: s,
                derived: slot,
            });
        }
    }

    let _ = ident_hex; // pin in case we want to log it later
    Ok(BaseIdentity {
        role,
        slot,
        key,
        manifest,
    })
}
