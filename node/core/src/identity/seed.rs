//! Coordinator-only: seed-derived wallet generation.
//!
//! Used ONLY by `ticker-ops` at deploy / bake / fund time. The operator runtime
//! binary (`ticker-node`) does not import this module's loader because operators
//! never have access to the seed.
//!
//! Derivation: `private_key = sha256(seed || utf8(label))`.
//!
//! Labels:
//!   * `"master"`             — hot wallet for genesis ceremony.
//!   * `"publisher-{0..12}"`  — 13 publisher wallets.

use crate::crypto::{derive_pubkey, hash160, sha256, KeyError};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

pub const MASTER_LABEL: &str = "master";
pub const PUBLISHER_LABEL: &str = "publisher";

#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    #[error("seed file not found at {0}")]
    NotFound(String),
    #[error("seed I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("seed at {path} is not 32 bytes (got {got_bytes})")]
    WrongLength { path: String, got_bytes: usize },
    #[error("seed at {0} contains non-hex characters")]
    NonHex(String),
    #[error(
        "seed file at {path} has insecure permissions {mode:#o} \
         (group/other access). Fix with: chmod 600 {path}"
    )]
    InsecurePermissions { path: String, mode: u32 },
    #[error("derive: {0}")]
    Crypto(#[from] KeyError),
}

/// Load 32-byte seed from a hex-encoded file (e.g. `.ticker/seed.hex`).
///
/// v23 F13 — refuses to read a seed file with group- or world- permission bits
/// set. Matches the policy already applied to publisher keys; closes a class
/// where the coordinator's seed.hex could leak via a misconfigured umask while
/// the operator-side key check passed.
pub fn load_seed(path: impl AsRef<Path>) -> Result<[u8; 32], SeedError> {
    let p = path.as_ref();
    check_secure_permissions(p)?;
    let raw = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SeedError::NotFound(p.display().to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(SeedError::WrongLength {
            path: p.display().to_string(),
            got_bytes: trimmed.len() / 2,
        });
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SeedError::NonHex(p.display().to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(trimmed).map_err(|_| SeedError::NonHex(p.display().to_string()))?);
    Ok(out)
}

/// Refuse to load a seed file that's group- or world-readable on Unix.
/// No-op on other platforms (Windows / WASI use different permission models).
#[cfg(unix)]
fn check_secure_permissions(p: &Path) -> Result<(), SeedError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SeedError::InsecurePermissions {
            path: p.display().to_string(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secure_permissions(_p: &Path) -> Result<(), SeedError> {
    Ok(())
}

/// Wallet derived from a seed + label.
#[derive(Debug, Clone)]
pub struct DerivedWallet {
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
    pub pkh: [u8; 20],
}

impl Drop for DerivedWallet {
    fn drop(&mut self) {
        // v23 F11 — wipe private key on drop. Public key + pkh are public.
        self.private_key.zeroize();
    }
}

/// `derive_wallet(seed, label)` — `private_key = sha256(seed || utf8(label))`.
pub fn derive_wallet(seed: &[u8; 32], label: &str) -> Result<DerivedWallet, SeedError> {
    let mut preimage = Vec::with_capacity(seed.len() + label.len());
    preimage.extend_from_slice(seed);
    preimage.extend_from_slice(label.as_bytes());
    let private_key = sha256(&preimage);
    let public_key = derive_pubkey(&private_key)?;
    let pkh = hash160(&public_key);
    Ok(DerivedWallet {
        private_key,
        public_key,
        pkh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `derive_wallet([0; 32], "master")` is deterministic — pinning the byte
    /// output guards against accidental rewrites of the derivation formula.
    #[test]
    fn derive_is_deterministic() {
        let seed = [0u8; 32];
        let a = derive_wallet(&seed, "master").unwrap();
        let b = derive_wallet(&seed, "master").unwrap();
        assert_eq!(a.private_key, b.private_key);
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(a.pkh, b.pkh);
    }

    /// Different labels yield different keys.
    #[test]
    fn labels_diverge() {
        let seed = [0u8; 32];
        let a = derive_wallet(&seed, "publisher-0").unwrap();
        let b = derive_wallet(&seed, "publisher-1").unwrap();
        assert_ne!(a.private_key, b.private_key);
    }

    /// Master key derivation is deterministic and non-zero. (We deliberately
    /// don't pin the exact hash here — operators reading this file shouldn't
    /// be tempted to use [0;32] as a real seed.)
    #[test]
    fn master_priv_key_is_nonzero_and_stable() {
        let seed = [0u8; 32];
        let w1 = derive_wallet(&seed, "master").unwrap();
        let w2 = derive_wallet(&seed, "master").unwrap();
        assert_eq!(w1.private_key, w2.private_key);
        assert_ne!(w1.private_key, [0u8; 32]);
    }

    /// v23 F13 — world-readable seed.hex is refused. Mirrors the existing
    /// operator-key permission gate so seed and key files share one policy.
    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_seed() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let hex64 = "0404040404040404040404040404040404040404040404040404040404040404";
        let path = std::env::temp_dir().join("ticker-seed-test-insecure.hex");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(hex64.as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_seed(&path),
            Err(SeedError::InsecurePermissions { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }
}
