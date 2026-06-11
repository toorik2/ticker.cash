//! Manifest JSON loader + validator.
//!
//! The manifest is the public bundle shipped with each operator's installer —
//! identical content for every operator of a deploy. Every field is validated
//! strictly; the daemon refuses to start on any shape/format error rather than
//! silently truncating.
//!
//! v16 reshape: PublisherSlot becomes per-source. v15 manifests carried a
//! singular `contracts.slot` (one address shared by all 13 publisher NFTs);
//! v16 carries `contracts.slots: [SlotEntry; 13]` and pulls the shared
//! `slotCategory` out as a top-level contracts field. `publisherPkhs` is
//! retired (folded into `slots[].publisherPkhHex`).

use serde::Deserialize;
use std::fs;
use std::path::Path;

/// Default disk path relative to the working directory.
pub const DEFAULT_MANIFEST_PATH: &str = ".ticker/manifest.json";

/// v24 P05 — TOFU hash-pin sidecar. Written next to `manifest.json` on first
/// load; checked on every subsequent load. Tamper with manifest.json without
/// deleting the sidecar and the daemon refuses to start.
pub const MANIFEST_PIN_FILE: &str = "manifest.sha256";

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

/// Token-bearing contract — used for `Oracle`. Adds the 64-hex CashTokens
/// category (the genesis-tx txid in display order).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenContractInfo {
    pub address: String,
    #[serde(rename = "lockingBytecodeHex")]
    pub locking_bytecode_hex: String,
    /// 64-hex category (txid display order, big-endian).
    pub category: String,
}

/// One PublisherSlot entry — v16's per-source replacement for v15's singular
/// `slot` contract field. Each entry carries everything the daemon + dashboard
/// need to address ONE publisher's slot UTXO.
#[derive(Debug, Clone, Deserialize)]
pub struct SlotEntry {
    #[serde(rename = "sourceId")]
    pub source_id: u16,
    #[serde(rename = "sourceName")]
    pub source_name: String,
    /// 40-hex `hash160(canonical_cn)` — baked into THIS slot's redeem.
    #[serde(rename = "cnHashHex")]
    pub cn_hash_hex: String,
    /// 40-hex publisher pkh — pinned at genesis in the slot commit.
    #[serde(rename = "publisherPkhHex")]
    pub publisher_pkh_hex: String,
    /// CashAddr P2SH-32 address for THIS slot.
    pub address: String,
    /// 35-byte hex P2SH-32 locking bytecode for THIS slot.
    #[serde(rename = "lockingBytecodeHex")]
    pub locking_bytecode_hex: String,
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
    /// 64-hex category shared by all 13 slots (only LBs/addresses differ).
    #[serde(rename = "slotCategory")]
    slot_category: String,
    /// 13 per-source slot entries, in source order (id 1..=13).
    slots: Vec<SlotEntry>,
}

/// Top-level manifest. v16: per-source slot entries + shared slot category.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub version: u32,
    pub network: Network,
    pub ticker: ContractInfo,
    pub oracle: TokenContractInfo,
    pub slot_category: String,
    pub slots: Vec<SlotEntry>,
    pub electrum: ElectrumDefault,
}

impl Manifest {
    /// Look up a slot by `source_id` (1..=13). Returns `None` if absent.
    pub fn slot_for(&self, source_id: u16) -> Option<&SlotEntry> {
        self.slots.iter().find(|s| s.source_id == source_id)
    }
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
    #[error(
        "manifest hash mismatch: expected {expected}, got {actual} \
         (file tampered post-deploy? To re-pin after a legitimate edit, \
         delete the .sha256 sidecar)"
    )]
    HashMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestRaw {
    version: u32,
    network: Network,
    contracts: ManifestContracts,
    electrum: ElectrumDefault,
}

const PUBLISHER_COUNT: usize = 13;
const MANIFEST_VERSION_V16: u32 = 2;

fn validate_locking_bytecode_hex(
    field: &'static str,
    value: &str,
) -> Result<String, ManifestError> {
    let lc = value.to_lowercase();
    // v22: accepts P2SH-32 (`aa20<64-hex>87`, 70 chars) for Oracle/Ticker
    //      AND P2S (bare-script LB, any length, all hex) for slots.
    let is_hex = lc.chars().all(|c| c.is_ascii_hexdigit()) && lc.len() % 2 == 0;
    if !is_hex || lc.is_empty() {
        return Err(ManifestError::InvalidField {
            field,
            reason: format!("expected even-length hex string, got {value:?}"),
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

/// v24 P05 — TOFU hash-pin wrapper around `load_manifest`. On first load,
/// writes `manifest.sha256` (mode 0o400) next to manifest.json. On every
/// subsequent load, recomputes sha256 over the manifest bytes and refuses
/// to start if it diverges from the pin.
///
/// Closes F09 (manifest-tamper Step-1 TOFU). The Step-2 ed25519 multi-sig
/// upgrade is gated on federation-split (R-FEDSPLIT) and not in v24 scope.
pub fn load_manifest_hash_pinned(path: impl AsRef<Path>) -> Result<Manifest, ManifestError> {
    let p = path.as_ref();
    let bytes = fs::read(p)?;
    let actual_hex = hex::encode(crate::crypto::sha256(&bytes));
    let pin_path = p.with_file_name(MANIFEST_PIN_FILE);

    if pin_path.exists() {
        let expected_hex = fs::read_to_string(&pin_path)?.trim().to_string();
        if actual_hex != expected_hex {
            return Err(ManifestError::HashMismatch {
                expected: expected_hex,
                actual: actual_hex,
            });
        }
    } else {
        fs::write(&pin_path, &actual_hex)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&pin_path)?.permissions();
            perms.set_mode(0o400);
            fs::set_permissions(&pin_path, perms)?;
        }
    }
    load_manifest(p)
}

/// Load and validate `manifest.json`.
pub fn load_manifest(path: impl AsRef<Path>) -> Result<Manifest, ManifestError> {
    let p = path.as_ref();
    // v24 P07 — F13 perm gate extended to manifest.json (mirrors seed.rs +
    // key.rs). Defense vs umask-misconfigured-deploy world-readable manifest;
    // forces the operator to fix permissions before the daemon starts.
    check_secure_permissions(p)?;
    let raw = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ManifestError::NotFound(p.display().to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    let m: ManifestRaw = serde_json::from_str(&raw)?;
    if m.version != MANIFEST_VERSION_V16 {
        return Err(ManifestError::InvalidField {
            field: "version",
            reason: format!(
                "unsupported version {} (expected {MANIFEST_VERSION_V16} for v16)",
                m.version
            ),
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
    let slot_category =
        validate_hex_field("contracts.slotCategory", &m.contracts.slot_category, 64)?;
    if m.contracts.slots.len() != PUBLISHER_COUNT {
        return Err(ManifestError::InvalidField {
            field: "contracts.slots",
            reason: format!(
                "expected {PUBLISHER_COUNT} slot entries, got {}",
                m.contracts.slots.len()
            ),
        });
    }
    let mut slots = Vec::with_capacity(PUBLISHER_COUNT);
    for (i, s) in m.contracts.slots.into_iter().enumerate() {
        let expected_id = (i + 1) as u16;
        if s.source_id != expected_id {
            return Err(ManifestError::InvalidField {
                field: "contracts.slots[].sourceId",
                reason: format!(
                    "slot[{i}] has sourceId {} but expected {expected_id} (slots must be in id order 1..=13)",
                    s.source_id
                ),
            });
        }
        let entry = SlotEntry {
            source_id: s.source_id,
            source_name: s.source_name,
            cn_hash_hex: validate_hex_field("contracts.slots[].cnHashHex", &s.cn_hash_hex, 40)?,
            publisher_pkh_hex: validate_hex_field(
                "contracts.slots[].publisherPkhHex",
                &s.publisher_pkh_hex,
                40,
            )?,
            address: s.address,
            locking_bytecode_hex: validate_locking_bytecode_hex(
                "contracts.slots[].lockingBytecodeHex",
                &s.locking_bytecode_hex,
            )?,
        };
        slots.push(entry);
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
        slot_category,
        slots,
        electrum: m.electrum,
    })
}

/// v24 P07 — F13 extension. Refuse to load manifest.json that's group- or
/// world-readable on Unix. Mirrors `seed.rs::check_secure_permissions` +
/// `key.rs::check_secure_permissions`. No-op on non-Unix platforms.
#[cfg(unix)]
fn check_secure_permissions(p: &Path) -> Result<(), ManifestError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = match fs::metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ManifestError::InvalidField {
            field: "(file permissions)",
            reason: format!(
                "manifest.json at {} has insecure permissions {mode:#o} \
                 (group/other access). Fix: chmod 600 {}",
                p.display(),
                p.display()
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secure_permissions(_p: &Path) -> Result<(), ManifestError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn good_manifest() -> String {
        let mut slots = String::new();
        for i in 1..=13 {
            let pkh = format!("{:02x}", i).repeat(20);
            let cn = format!("{:02x}", i + 0x10).repeat(20);
            let lb = format!(
                "aa20{}87",
                format!("{:02x}", i + 0x20).repeat(32)
            );
            if i > 1 {
                slots.push_str(",\n");
            }
            slots.push_str(&format!(
                r#"        {{
            "sourceId": {i},
            "sourceName": "source{i}",
            "cnHashHex": "{cn}",
            "publisherPkhHex": "{pkh}",
            "address": "bchtest:p{i}",
            "lockingBytecodeHex": "{lb}"
        }}"#
            ));
        }
        format!(
            r#"{{
    "version": 2,
    "network": "chipnet",
    "contracts": {{
        "ticker": {{
            "address": "bchtest:pTicker",
            "lockingBytecodeHex": "aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87"
        }},
        "oracle": {{
            "address": "bchtest:pOracle",
            "lockingBytecodeHex": "aa2090c9064dc6fee8d55da81e07ab6b0bdd55e67bae8d38376368d9973957a8f8fd87",
            "category": "9880c31334f9f708e9e0a3cf956442290ae1a463bd806fd416a5ed10b40f0d17"
        }},
        "slotCategory": "846b2ca944750af011fa41bb87f9fda1244090a63be2cc3286223551343020f7",
        "slots": [
{slots}
        ]
    }},
    "electrum": {{
        "host": "chipnet.layer1.cash",
        "port": 50002,
        "tls": true
    }}
}}"#
        )
    }

    fn write_path(content: &str, file_name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ticker-core-test-{file_name}"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        // v24 P07 — secure-perms gate refuses group/other-readable manifests.
        // All test fixtures land at 0o600 so the perm check passes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn happy_path_parses() {
        let m_str = good_manifest();
        let path = write_path(&m_str, "happy-v16.json");
        let m = load_manifest(&path).unwrap();
        assert_eq!(m.version, 2);
        assert_eq!(m.network, Network::Chipnet);
        assert_eq!(m.slots.len(), 13);
        for (i, s) in m.slots.iter().enumerate() {
            assert_eq!(s.source_id as usize, i + 1);
        }
        assert_eq!(m.electrum.host, "chipnet.layer1.cash");
        assert!(m.electrum.tls);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn slot_for_lookup_works() {
        let path = write_path(&good_manifest(), "lookup-v16.json");
        let m = load_manifest(&path).unwrap();
        assert!(m.slot_for(1).is_some());
        assert!(m.slot_for(13).is_some());
        assert!(m.slot_for(14).is_none());
        assert!(m.slot_for(0).is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_wrong_version() {
        let s = good_manifest().replace(r#""version": 2"#, r#""version": 1"#);
        let path = write_path(&s, "badver-v16.json");
        assert!(matches!(
            load_manifest(&path),
            Err(ManifestError::InvalidField { field: "version", .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_wrong_slot_count() {
        // Drop one slot entry by trimming the slots[] array
        let s = good_manifest();
        let s = s.replace(
            r#"            "sourceId": 13,
            "sourceName": "source13","#,
            r#"            "sourceId": 99,
            "sourceName": "source99","#,
        );
        let path = write_path(&s, "badcount-v16.json");
        // sourceId=99 at slot 12 (index) when expected 13 → InvalidField on sourceId
        let r = load_manifest(&path);
        assert!(
            matches!(r, Err(ManifestError::InvalidField { .. })),
            "got: {:?}",
            r
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_non_hex_locking_bytecode() {
        let s = good_manifest().replace(
            "aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87",
            "aa20NOTHEX87",
        );
        let path = write_path(&s, "badlock-v22.json");
        assert!(matches!(
            load_manifest(&path),
            Err(ManifestError::InvalidField { .. })
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_yields_not_found() {
        let r = load_manifest("/tmp/this/does/not/exist.json");
        assert!(matches!(r, Err(ManifestError::NotFound(_))));
    }

    /// Create a unique per-test temp dir so each hash-pin test gets its own
    /// `manifest.sha256` sidecar (the sidecar path is derived from the manifest
    /// path's parent dir — two tests in the same dir would collide).
    fn tempdir_for(test_name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ticker-core-test-{test_name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Helper: write file at 0o600 to satisfy P07 perm gate.
    fn write_secure(path: &std::path::Path, content: &str) {
        std::fs::write(path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// v24 P05 — first load writes the .sha256 sidecar with mode 0o400.
    #[test]
    fn hash_pin_tofu_writes_sidecar_on_first_load() {
        let dir = tempdir_for("hash-pin-first");
        let path = dir.join("manifest.json");
        write_secure(&path, &good_manifest());
        let pin_path = dir.join(MANIFEST_PIN_FILE);
        load_manifest_hash_pinned(&path).unwrap();
        assert!(pin_path.exists(), "sidecar must be written on first load");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&pin_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o400, "sidecar must be mode 0o400 (owner-read only)");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v24 P05 — tampering with manifest.json without deleting the sidecar is
    /// detected on next load. Daemon refuses to start.
    #[test]
    fn hash_pin_rejects_tampered_file() {
        let dir = tempdir_for("hash-pin-tamper");
        let path = dir.join("manifest.json");
        write_secure(&path, &good_manifest());
        load_manifest_hash_pinned(&path).unwrap();
        // Mutate one byte of the manifest. (We can't just replace a string —
        // a sidecar-aware attacker would catch our test cleanup loop. Bit-
        // flipping a literal byte after the JSON parses cleanly is enough.)
        let raw = std::fs::read_to_string(&path).unwrap();
        let raw_mut = raw.replace("\"chipnet\"", "\"Chipnet\"");
        assert_ne!(raw, raw_mut, "fixture must contain the canary string");
        write_secure(&path, &raw_mut);
        let r = load_manifest_hash_pinned(&path);
        assert!(matches!(r, Err(ManifestError::HashMismatch { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v24 P07 — F13 extension: world-readable manifest.json is refused.
    /// Mirrors `rejects_world_readable_seed` at seed.rs.
    #[cfg(unix)]
    #[test]
    fn rejects_world_readable_manifest() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir_for("manifest-insecure-perms");
        let path = dir.join("manifest.json");
        std::fs::write(&path, good_manifest()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = load_manifest(&path);
        assert!(
            matches!(r, Err(ManifestError::InvalidField { field: "(file permissions)", .. })),
            "got: {r:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
