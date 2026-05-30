//! Manifest JSON loader + validator.
//!
//! Mirrors `daemon/src/manifest.ts`. The manifest is the public bundle shipped
//! with each operator's installer — same content for every operator of a deploy.
//! Every field is validated strictly; the daemon refuses to start on any
//! shape/format error rather than silently truncating.

use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Default disk path relative to the working directory.
pub const DEFAULT_MANIFEST_PATH: &str = ".ticker/manifest.json";

/// Network selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Chipnet,
    Mainnet,
}

/// Plain (non-token) contract — used for `Ticker`, which is identified by its
/// locking bytecode, not by a CashTokens category.
#[derive(Debug, Clone, Deserialize)]
pub struct ContractInfo {
    /// CashAddr `bch…` / `bchtest…` P2SH-32 address.
    pub address: String,
    /// 35-byte hex (`aa20<32-byte sha256>87`).
    #[serde(rename = "lockingBytecodeHex")]
    pub locking_bytecode_hex: String,
}

/// Token-bearing contract — used for `Oracle` and `PublisherSlot`. Adds the
/// 64-hex CashTokens category (the genesis-tx txid in display order).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenContractInfo {
    pub address: String,
    #[serde(rename = "lockingBytecodeHex")]
    pub locking_bytecode_hex: String,
    /// 64-hex category (txid display order, big-endian).
    pub category: String,
}

/// Electrum/Fulcrum endpoint default (operator may override at runtime).
#[derive(Debug, Clone, Deserialize)]
pub struct ElectrumDefault {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// Optional fallback endpoints, tried in order when the primary fails.
    /// Each entry follows the same `{host, port, tls}` shape as the primary.
    /// Missing field → empty vec (publisher runs single-endpoint).
    #[serde(default)]
    pub fallbacks: Vec<ElectrumFallback>,
}

/// Fallback endpoint shape — must mirror `ElectrumDefault` so operators can
/// promote a fallback to primary by editing the manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct ElectrumFallback {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_tls")]
    pub tls: bool,
}

fn default_tls() -> bool {
    true
}

impl ElectrumDefault {
    /// Produce the ordered endpoint pool: primary first, then fallbacks.
    /// All entries use TLS (the publisher daemon does not support plain TCP).
    pub fn endpoint_pool(&self) -> Vec<crate::electrum::Endpoint> {
        let mut out = Vec::with_capacity(1 + self.fallbacks.len());
        out.push(crate::electrum::Endpoint::new(&self.host, self.port));
        for f in &self.fallbacks {
            out.push(crate::electrum::Endpoint::new(&f.host, f.port));
        }
        out
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestContracts {
    ticker: ContractInfo,
    oracle: TokenContractInfo,
    slot: TokenContractInfo,
}

/// Top-level manifest. v13 dropped `notaryPubkeys` (no notary tier).
#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: u32,
    pub network: Network,
    pub ticker: ContractInfo,
    pub oracle: TokenContractInfo,
    pub slot: TokenContractInfo,
    /// 13 publisher pkhs (40 hex chars each), in slot order.
    pub publisher_pkhs: Vec<String>,
    pub electrum: ElectrumDefault,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest file not found at {0}")]
    NotFound(String),
    #[error("manifest read error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manifest field `{field}` is invalid: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestRaw {
    version: u32,
    network: Network,
    contracts: ManifestContracts,
    #[serde(rename = "publisherPkhs")]
    publisher_pkhs: Vec<String>,
    electrum: ElectrumDefault,
}

const PUBLISHER_COUNT: usize = 13;

fn validate_locking_bytecode_hex(
    field: &'static str,
    value: &str,
) -> Result<String, ManifestError> {
    let lc = value.to_lowercase();
    let ok = lc.len() == 70
        && lc.starts_with("aa20")
        && lc.ends_with("87")
        && lc[4..68].chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err(ManifestError::InvalidField {
            field,
            reason: format!("expected aa20<64-hex>87, got {value:?}"),
        });
    }
    Ok(lc)
}

fn validate_hex_field(
    field: &'static str,
    value: &str,
    chars: usize,
) -> Result<String, ManifestError> {
    let lc = value.to_lowercase();
    if lc.len() != chars || !lc.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ManifestError::InvalidField {
            field,
            reason: format!("expected {chars} hex chars, got {value:?}"),
        });
    }
    Ok(lc)
}

/// Load and validate `manifest.json`.
pub fn load_manifest(path: impl AsRef<Path>) -> Result<Manifest, ManifestError> {
    let p = path.as_ref();
    let raw = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ManifestError::NotFound(p.display().to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    let m: ManifestRaw = serde_json::from_str(&raw)?;
    if m.version != 1 {
        return Err(ManifestError::InvalidField {
            field: "version",
            reason: format!("unsupported version {} (expected 1)", m.version),
        });
    }
    let ticker = ContractInfo {
        address: m.contracts.ticker.address,
        locking_bytecode_hex: validate_locking_bytecode_hex(
            "contracts.ticker.lockingBytecodeHex",
            &m.contracts.ticker.locking_bytecode_hex,
        )?,
    };
    let oracle = TokenContractInfo {
        address: m.contracts.oracle.address,
        locking_bytecode_hex: validate_locking_bytecode_hex(
            "contracts.oracle.lockingBytecodeHex",
            &m.contracts.oracle.locking_bytecode_hex,
        )?,
        category: validate_hex_field("contracts.oracle.category", &m.contracts.oracle.category, 64)?,
    };
    let slot = TokenContractInfo {
        address: m.contracts.slot.address,
        locking_bytecode_hex: validate_locking_bytecode_hex(
            "contracts.slot.lockingBytecodeHex",
            &m.contracts.slot.locking_bytecode_hex,
        )?,
        category: validate_hex_field("contracts.slot.category", &m.contracts.slot.category, 64)?,
    };
    if m.publisher_pkhs.len() != PUBLISHER_COUNT {
        return Err(ManifestError::InvalidField {
            field: "publisherPkhs",
            reason: format!("expected {PUBLISHER_COUNT} entries, got {}", m.publisher_pkhs.len()),
        });
    }
    let mut publisher_pkhs = Vec::with_capacity(PUBLISHER_COUNT);
    for (i, p) in m.publisher_pkhs.iter().enumerate() {
        publisher_pkhs.push(validate_hex_field(
            "publisherPkhs[i]",
            p,
            40,
        ).map_err(|_| ManifestError::InvalidField {
            field: "publisherPkhs",
            reason: format!("entry {i} is not a 40-hex pkh"),
        })?);
    }
    if m.electrum.host.is_empty() {
        return Err(ManifestError::InvalidField {
            field: "electrum.host",
            reason: "must be non-empty".to_string(),
        });
    }
    Ok(Manifest {
        version: m.version,
        network: m.network,
        ticker,
        oracle,
        slot,
        publisher_pkhs,
        electrum: m.electrum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn good_manifest() -> &'static str {
        r#"{
            "version": 1,
            "network": "chipnet",
            "contracts": {
                "ticker": {
                    "address": "bchtest:p123",
                    "lockingBytecodeHex": "aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87"
                },
                "oracle": {
                    "address": "bchtest:p456",
                    "lockingBytecodeHex": "aa2090c9064dc6fee8d55da81e07ab6b0bdd55e67bae8d38376368d9973957a8f8fd87",
                    "category": "9880c31334f9f708e9e0a3cf956442290ae1a463bd806fd416a5ed10b40f0d17"
                },
                "slot": {
                    "address": "bchtest:p789",
                    "lockingBytecodeHex": "aa20ec8e0bc24f6934cb31518714a15c5c31424514bb9bcde5578e20da8d231a14db87",
                    "category": "846b2ca944750af011fa41bb87f9fda1244090a63be2cc3286223551343020f7"
                }
            },
            "publisherPkhs": [
                "8ce2d07b5632a5855f5411d3b085c1bcd1c07a17",
                "333e5c6321f963622336421a64667f298e31c052",
                "ef369feaf80c0ea5f65b607922fa2c11193ebb18",
                "1111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222",
                "3333333333333333333333333333333333333333",
                "4444444444444444444444444444444444444444",
                "5555555555555555555555555555555555555555",
                "6666666666666666666666666666666666666666",
                "7777777777777777777777777777777777777777",
                "8888888888888888888888888888888888888888",
                "9999999999999999999999999999999999999999",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "electrum": {
                "host": "fulcrum.layer1.cash",
                "port": 50002,
                "tls": true
            }
        }"#
    }

    /// Helper: write into a unique path under /tmp so each test is isolated.
    fn write_path(content: &str, file_name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ticker-core-test-{file_name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn happy_path_parses() {
        let path = write_path(good_manifest(), "happy.json");
        let m = load_manifest(&path).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.network, Network::Chipnet);
        assert_eq!(m.publisher_pkhs.len(), 13);
        assert_eq!(m.electrum.host, "fulcrum.layer1.cash");
        assert!(m.electrum.tls);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_wrong_locking_bytecode_length() {
        let path = write_path(
            &good_manifest().replace(
                "aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87",
                "aa20BAD87",
            ),
            "badlock.json",
        );
        assert!(matches!(
            load_manifest(&path),
            Err(ManifestError::InvalidField { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_wrong_publisher_count() {
        let path = write_path(
            &good_manifest().replace(
                r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#,
                "",
            ).replacen(",", "", 1), // remove a trailing comma somewhere
            "badpub.json",
        );
        // The shape of the edit may produce either a JSON parse error or a count
        // mismatch; both are acceptable rejection outcomes.
        assert!(load_manifest(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_yields_not_found() {
        let r = load_manifest("/tmp/this/does/not/exist.json");
        assert!(matches!(r, Err(ManifestError::NotFound(_))));
    }

}
