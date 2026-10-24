//! 32-byte private key files: 64 hex chars, mode 0600, zeroized on drop.
//!
//! Used by notaries (their table key) and by operators (funding / sweep key). A keyfile with
//! group or world permission bits is refused at startup rather than silently used.

use crate::crypto::{derive_pubkey, hash160, KeyError};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct KeyMaterial {
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
    pub pkh: [u8; 20],
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &hex::encode(self.public_key))
            .finish()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("key file not found at {0}")]
    NotFound(String),
    #[error("key file read error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key at {path} is not 32 bytes (got {got_bytes})")]
    WrongLength { path: String, got_bytes: usize },
    #[error("key at {0} contains non-hex characters")]
    NonHex(String),
    #[error("key at {path} has insecure permissions {mode:#o}; fix with: chmod 600 {path}")]
    InsecurePermissions { path: String, mode: u32 },
    #[error("crypto: {0}")]
    Crypto(#[from] KeyError),
}

impl KeyMaterial {
    pub fn from_private_key(private_key: [u8; 32]) -> Result<Self, KeyError> {
        let public_key = derive_pubkey(&private_key)?;
        let pkh = hash160(&public_key);
        Ok(KeyMaterial { private_key, public_key, pkh })
    }
}

pub fn load_key(path: impl AsRef<Path>) -> Result<KeyMaterial, KeyFileError> {
    let p = path.as_ref();
    check_secure_permissions(p)?;
    let raw = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(KeyFileError::NotFound(p.display().to_string())),
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(KeyFileError::WrongLength { path: p.display().to_string(), got_bytes: trimmed.len() / 2 });
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KeyFileError::NonHex(p.display().to_string()));
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&hex::decode(trimmed).map_err(|_| KeyFileError::NonHex(p.display().to_string()))?);
    Ok(KeyMaterial::from_private_key(private_key)?)
}

/// Write a fresh random key with mode 0600. Refuses to overwrite.
pub fn generate_key_file(path: impl AsRef<Path>) -> Result<KeyMaterial, KeyFileError> {
    let p = path.as_ref();
    if p.exists() {
        return Err(KeyFileError::Io(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "key file exists")));
    }
    let mut sk = [0u8; 32];
    loop {
        getrandom_fill(&mut sk)?;
        if derive_pubkey(&sk).is_ok() {
            break;
        }
    }
    let km = KeyMaterial::from_private_key(sk)?;
    sk.zeroize();
    {
        use std::io::Write;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(p)?;
        writeln!(f, "{}", hex::encode(km.private_key))?;
    }
    Ok(km)
}

fn getrandom_fill(buf: &mut [u8; 32]) -> std::io::Result<()> {
    use std::io::Read;
    let mut f = fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

#[cfg(unix)]
fn check_secure_permissions(p: &Path) -> Result<(), KeyFileError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyFileError::InsecurePermissions { path: p.display().to_string(), mode });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secure_permissions(_p: &Path) -> Result<(), KeyFileError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ticker-v25-key-{}", std::process::id()));
        let _ = fs::remove_file(&dir);
        let k = generate_key_file(&dir).unwrap();
        let l = load_key(&dir).unwrap();
        assert_eq!(k.public_key, l.public_key);
        assert!(generate_key_file(&dir).is_err(), "must not overwrite");
        fs::remove_file(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn insecure_permissions_refused() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("ticker-v25-insecure-{}", std::process::id()));
        let mut f = fs::File::create(&p).unwrap();
        writeln!(f, "{}", "11".repeat(32)).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load_key(&p), Err(KeyFileError::InsecurePermissions { .. })));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_key(&p).is_ok());
        fs::remove_file(&p).unwrap();
    }
}
