//! Identity resolver: load manifest + load publisher key + derive slot via
//! manifest lookup.

use super::key::{load_operator_key, OperatorKey, OperatorKeyError};
use super::manifest::{load_manifest, Manifest, ManifestError};
use std::path::Path;

/// Result of resolving an operator's identity at startup.
#[derive(Debug, Clone)]
pub struct BaseIdentity {
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
        "publisher key identity {ident_hex} not found in manifest's publisher list.\n\
         wrong installer? wrong manifest? verify with your coordinator."
    )]
    KeyNotInManifest { ident_hex: String },
    #[error("--slot {supplied} disagrees with derived slot {derived} (from key); omit --slot")]
    SlotFlagMismatch { supplied: u8, derived: u8 },
}

/// Resolve the operator's slot, key, and manifest. `slot_flag` is optional and
/// must agree with the derived slot when supplied.
pub fn resolve_identity(
    manifest_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    slot_flag: Option<u8>,
) -> Result<BaseIdentity, IdentityError> {
    let manifest = load_manifest(manifest_path)?;
    let key = load_operator_key(key_path)?;

    let id_hex = hex::encode(key.pkh);
    let slot = manifest
        .slots
        .iter()
        .position(|s| s.publisher_pkh_hex == id_hex)
        .ok_or_else(|| IdentityError::KeyNotInManifest {
            ident_hex: id_hex.clone(),
        })? as u8;

    if let Some(s) = slot_flag {
        if s != slot {
            return Err(IdentityError::SlotFlagMismatch {
                supplied: s,
                derived: slot,
            });
        }
    }

    Ok(BaseIdentity {
        slot,
        key,
        manifest,
    })
}
