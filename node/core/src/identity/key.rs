//! Operator key loader — one 32-byte private key per role.
//!
//! File format: 64 lowercase hex chars (32 bytes), trailing whitespace tolerated.
//! Non-hex characters trigger a hard error rather than silent coercion to zero
//! (which would produce a publicly-precomputable wallet).
//!
//! On Unix the loader refuses to read a keyfile that has any group or other
//! permission bits set — operators with a misconfigured umask or `unzip`-flattened
//! permissions get a hard error at startup rather than a silently-leaked key.
//!
//! `OperatorKey` zeroizes the private key on drop and redacts it from `Debug`.

use crate::crypto::{derive_pubkey, hash160, KeyError};
use std::fs;
use std::path::Path;

/// Decoded operator key + derived public material.
///
/// Derives `Clone` so it can be threaded into `CycleConfig`; each clone owns
/// its own `private_key` and zeroizes on drop.
#[derive(Clone)]
pub struct OperatorKey {
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
    pub pkh: [u8; 20],
}

impl std::fmt::Debug for OperatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorKey")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &hex::encode(self.public_key))
            .field("pkh", &hex::encode(self.pkh))
            .finish()
    }
}

impl Drop for OperatorKey {
    fn drop(&mut self) {
        // Volatile writes prevent the compiler from optimising away the wipe.
        for i in 0..self.private_key.len() {
            unsafe { std::ptr::write_volatile(&mut self.private_key[i], 0) };
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorKeyError {
    #[error("operator key file not found at {0}")]
    NotFound(String),
    #[error("operator key read error: {0}")]
    Io(#[from] std::io::Error),
    #[error("operator key at {path} is not 32 bytes (got {got_bytes})")]
    WrongLength { path: String, got_bytes: usize },
    #[error("operator key at {0} contains non-hex characters")]
    NonHex(String),
    #[error(
        "operator key at {path} has insecure permissions {mode:#o} \
         (group/other access). Fix with: chmod 600 {path}"
    )]
    InsecurePermissions { path: String, mode: u32 },
    #[error("crypto: {0}")]
    Crypto(#[from] KeyError),
}

/// Read the operator's private key from disk and derive its public material.
pub fn load_operator_key(path: impl AsRef<Path>) -> Result<OperatorKey, OperatorKeyError> {
    let p = path.as_ref();
    check_secure_permissions(p)?;
    let raw = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OperatorKeyError::NotFound(p.display().to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(OperatorKeyError::WrongLength {
            path: p.display().to_string(),
            got_bytes: trimmed.len() / 2,
        });
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(OperatorKeyError::NonHex(p.display().to_string()));
    }
    let bytes = hex::decode(trimmed)
        .map_err(|_| OperatorKeyError::NonHex(p.display().to_string()))?;
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&bytes);
    let public_key = derive_pubkey(&private_key)?;
    let pkh = hash160(&public_key);
    Ok(OperatorKey {
        private_key,
        public_key,
        pkh,
    })
}

/// Refuse to load a keyfile that's group- or world-readable on Unix. No-op on
/// other platforms (Windows / WASI have different permission models).
#[cfg(unix)]
fn check_secure_permissions(p: &Path) -> Result<(), OperatorKeyError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(OperatorKeyError::InsecurePermissions {
            path: p.display().to_string(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secure_permissions(_p: &Path) -> Result<(), OperatorKeyError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_key(content: &str, file_name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ticker-key-test-{file_name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn loads_valid_hex_key() {
        let hex64 = "0101010101010101010101010101010101010101010101010101010101010101";
        let path = write_key(hex64, "valid.hex");
        let k = load_operator_key(&path).unwrap();
        assert_eq!(k.private_key, [0x01; 32]);
        assert!(k.public_key[0] == 0x02 || k.public_key[0] == 0x03);
        assert_eq!(k.public_key.len(), 33);
        assert_eq!(k.pkh.len(), 20);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tolerates_trailing_newline() {
        let path = write_key(
            "0202020202020202020202020202020202020202020202020202020202020202\n",
            "newline.hex",
        );
        assert!(load_operator_key(&path).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_wrong_length() {
        let path = write_key("0102030405", "short.hex");
        assert!(matches!(
            load_operator_key(&path),
            Err(OperatorKeyError::WrongLength { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_non_hex() {
        let path = write_key(
            "ZZ01010101010101010101010101010101010101010101010101010101010101",
            "nonhex2.hex",
        );
        assert!(matches!(
            load_operator_key(&path),
            Err(OperatorKeyError::NonHex(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file() {
        assert!(matches!(
            load_operator_key("/tmp/no/such/key.hex"),
            Err(OperatorKeyError::NotFound(_))
        ));
    }

    /// World-readable keys are refused on Unix.
    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let hex64 = "0303030303030303030303030303030303030303030303030303030303030303";
        let path = std::env::temp_dir().join("ticker-key-test-insecure.hex");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(hex64.as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            load_operator_key(&path),
            Err(OperatorKeyError::InsecurePermissions { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    /// Debug doesn't leak the private key.
    #[test]
    fn debug_redacts_private_key() {
        let hex64 = "abcdef0102030405060708090a0b0c0d0e0f10111213141516171819ff00aabb";
        let path = write_key(hex64, "redact.hex");
        let k = load_operator_key(&path).unwrap();
        let d = format!("{k:?}");
        assert!(!d.contains("abcdef0102"), "Debug leaked private key: {d}");
        assert!(d.contains("REDACTED"));
        let _ = std::fs::remove_file(&path);
    }
}
