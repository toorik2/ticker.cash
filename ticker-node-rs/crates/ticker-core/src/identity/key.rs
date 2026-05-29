//! Operator key loader — one 32-byte private key per role.
//!
//! File format: 64 lowercase hex chars (32 bytes), trailing whitespace tolerated.
//! Non-hex characters trigger a hard error rather than silent coercion to zero
//! (which would produce a publicly-precomputable wallet).

use crate::crypto::{derive_pubkey, hash160, KeyError};
use std::fs;
use std::path::Path;

/// Decoded operator key + derived public material.
#[derive(Debug, Clone)]
pub struct OperatorKey {
    pub label: String,
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
    pub pkh: [u8; 20],
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
    #[error("crypto: {0}")]
    Crypto(#[from] KeyError),
}

/// Read the operator's private key from disk and derive its public material.
pub fn load_operator_key(
    path: impl AsRef<Path>,
    label: &str,
) -> Result<OperatorKey, OperatorKeyError> {
    let p = path.as_ref();
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
        label: label.to_string(),
        private_key,
        public_key,
        pkh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_key(content: &str, file_name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ticker-key-test-{file_name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_valid_hex_key() {
        let hex64 = "0101010101010101010101010101010101010101010101010101010101010101";
        let path = write_key(hex64, "valid.hex");
        let k = load_operator_key(&path, "test").unwrap();
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
        assert!(load_operator_key(&path, "test").is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_wrong_length() {
        let path = write_key("0102030405", "short.hex");
        assert!(matches!(
            load_operator_key(&path, "test"),
            Err(OperatorKeyError::WrongLength { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_non_hex() {
        let path = write_key(
            "ZZ0101010101010101010101010101010101010101010101010101010101010101",
            "nonhex.hex",
        );
        // Length is 66 not 64 — caught by wrong-length first. Adjust:
        let _ = std::fs::remove_file(&path);
        let path = write_key(
            "ZZ01010101010101010101010101010101010101010101010101010101010101",
            "nonhex2.hex",
        );
        assert!(matches!(
            load_operator_key(&path, "test"),
            Err(OperatorKeyError::NonHex(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file() {
        assert!(matches!(
            load_operator_key("/tmp/no/such/key.hex", "test"),
            Err(OperatorKeyError::NotFound(_))
        ));
    }
}
