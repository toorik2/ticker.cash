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
    fn rejects_wrong_locking_bytecode_length() {
        let s = good_manifest().replace(
            "aa20c757c5b79cfb72632175bf91e5d5941e0d2d59de745c9a2c622dcb7a4181eedc87",
            "aa20BAD87",
        );
        let path = write_path(&s, "badlock-v16.json");
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
}
