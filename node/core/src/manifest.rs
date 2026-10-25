//! The public deployment manifest.
//!
//! Everything a builder, consumer or dashboard needs to find and verify a deployment, and
//! nothing secret: the token category, the two locking bytecodes, the notary table with each
//! row's exchange and statement API, and the Electrum pool. The table's hash160 is what the head
//! commitment carries; the loader recomputes it and refuses a manifest whose parts disagree. After
//! a rotation the operator rewrites the table here and republishes.

use crate::sources::source_by_id;
use crate::tx::covenant::{oracle_lock, table_hash, ticker_lock};
use crate::{MAX_ROWS, QUORUM, TABLE_ENTRY_LEN};
use serde::{Deserialize, Serialize};

pub const MANIFEST_VERSION: u32 = 26;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableRow {
    pub row: u8,
    /// Exchange id (`sources::SOURCES`), the `source` byte of every statement from this row.
    pub source: u8,
    /// 33-byte compressed notary pubkey, hex.
    pub pubkey: String,
    pub operator: String,
    /// Statement API base, `http://host:port`.
    pub api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElectrumEndpoint {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    /// "chipnet" or "mainnet".
    pub network: String,
    /// Token category, display order hex (64 chars).
    pub category: String,
    pub genesis_txid: String,
    /// P2SH-32 locking bytecode of the head, hex (35 B). The same for every v26 deployment.
    pub oracle_lock: String,
    /// P2S locking bytecode of Tickers, hex (57 B).
    pub ticker_lock: String,
    /// hash160 of the table below, hex (40 chars): what the head commitment carries.
    pub table_hash: String,
    pub table: Vec<TableRow>,
    pub electrum: Vec<ElectrumEndpoint>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manifest version {0} is not {MANIFEST_VERSION}")]
    Version(u32),
    #[error("table has {0} rows, expected {QUORUM}..={MAX_ROWS}")]
    Rows(usize),
    #[error("table row {0} out of order or duplicated")]
    RowOrder(u8),
    #[error("row {row}: unknown source id {source_id}")]
    Source { row: u8, source_id: u8 },
    #[error("row {0}: pubkey is not 33 bytes of hex")]
    Pubkey(u8),
    #[error("duplicate notary pubkey in rows {0} and {1}")]
    DuplicateKey(u8, u8),
    #[error("duplicate source in rows {0} and {1}")]
    DuplicateSource(u8, u8),
    #[error("category is not 32 bytes of hex")]
    Category,
    #[error("oracle_lock is not the v26 Oracle lock")]
    OracleLock,
    #[error("ticker_lock does not match the compiled Ticker covenant")]
    TickerLock,
    #[error("table_hash does not match the table")]
    TableHash,
    #[error("network must be chipnet or mainnet")]
    Network,
    #[error("no electrum endpoints")]
    Electrum,
}

impl Manifest {
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ManifestError> {
        let raw = std::fs::read_to_string(path)?;
        let m: Manifest = serde_json::from_str(&raw)?;
        m.validate()?;
        Ok(m)
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version != MANIFEST_VERSION {
            return Err(ManifestError::Version(self.version));
        }
        if self.network != "chipnet" && self.network != "mainnet" {
            return Err(ManifestError::Network);
        }
        validate_rows(&self.table)?;
        if self.electrum.is_empty() {
            return Err(ManifestError::Electrum);
        }
        if hex::decode(&self.category).map(|c| c.len() != 32).unwrap_or(true) {
            return Err(ManifestError::Category);
        }
        if hex::encode(oracle_lock()) != self.oracle_lock {
            return Err(ManifestError::OracleLock);
        }
        if hex::encode(ticker_lock()) != self.ticker_lock {
            return Err(ManifestError::TickerLock);
        }
        if hex::encode(table_hash(&self.table_bytes())) != self.table_hash {
            return Err(ManifestError::TableHash);
        }
        Ok(())
    }

    /// The table exactly as the covenant hashes it: rows in order, `pubkey ‖ source` each.
    pub fn table_bytes(&self) -> Vec<u8> {
        table_bytes(&self.table)
    }

    pub fn table_hash_bytes(&self) -> [u8; 20] {
        table_hash(&self.table_bytes())
    }

    pub fn category_bytes(&self) -> [u8; 32] {
        hex::decode(&self.category).expect("validated").try_into().expect("validated")
    }

    /// Category in VM byte order (reversed display order), as the covenant sees it.
    pub fn category_vm(&self) -> [u8; 32] {
        let mut c = self.category_bytes();
        c.reverse();
        c
    }

    /// Replace the table (after a rotation) and recompute its hash.
    pub fn set_table(&mut self, rows: Vec<TableRow>) -> Result<(), ManifestError> {
        validate_rows(&rows)?;
        self.table_hash = hex::encode(table_hash(&table_bytes(&rows)));
        self.table = rows;
        Ok(())
    }
}

/// Row-level checks shared by the manifest and by `genesis.json` / rotation table files.
pub fn validate_rows(rows: &[TableRow]) -> Result<(), ManifestError> {
    if rows.len() < QUORUM || rows.len() > MAX_ROWS {
        return Err(ManifestError::Rows(rows.len()));
    }
    for (i, r) in rows.iter().enumerate() {
        if r.row as usize != i {
            return Err(ManifestError::RowOrder(r.row));
        }
        if source_by_id(r.source).is_none() {
            return Err(ManifestError::Source { row: r.row, source_id: r.source });
        }
        if r.pubkey_bytes().is_none() {
            return Err(ManifestError::Pubkey(r.row));
        }
        for other in &rows[..i] {
            if other.pubkey.eq_ignore_ascii_case(&r.pubkey) {
                return Err(ManifestError::DuplicateKey(other.row, r.row));
            }
            if other.source == r.source {
                return Err(ManifestError::DuplicateSource(other.row, r.row));
            }
        }
    }
    Ok(())
}

pub fn table_bytes(rows: &[TableRow]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rows.len() * TABLE_ENTRY_LEN);
    for r in rows {
        out.extend_from_slice(&r.pubkey_bytes().expect("validated"));
        out.push(r.source);
    }
    out
}

impl TableRow {
    pub fn pubkey_bytes(&self) -> Option<[u8; 33]> {
        hex::decode(&self.pubkey).ok()?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_pubkey;

    fn rows(n: u8) -> Vec<TableRow> {
        (0..n).map(|i| TableRow { row: i, source: i + 1, pubkey: hex::encode(derive_pubkey(&[i + 1; 32]).unwrap()), operator: "t".into(), api: "http://127.0.0.1:1".into() }).collect()
    }

    fn manifest(n: u8) -> Manifest {
        let table = rows(n);
        Manifest {
            version: MANIFEST_VERSION,
            network: "chipnet".into(),
            category: "11".repeat(32),
            genesis_txid: "22".repeat(32),
            oracle_lock: hex::encode(oracle_lock()),
            ticker_lock: hex::encode(ticker_lock()),
            table_hash: hex::encode(table_hash(&table_bytes(&table))),
            table,
            electrum: vec![ElectrumEndpoint { host: "x".into(), port: 1, tls: true }],
        }
    }

    #[test]
    fn valid_manifest_roundtrips() {
        let m = manifest(13);
        m.validate().unwrap();
        let s = serde_json::to_string(&m).unwrap();
        let back: Manifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.table_bytes().len(), 13 * 34);
    }

    #[test]
    fn rejects_bad_parts() {
        let mut m = manifest(13);
        m.table_hash = "00".repeat(20);
        assert!(matches!(m.validate(), Err(ManifestError::TableHash)));
        let mut m = manifest(13);
        m.oracle_lock = "aa".repeat(35);
        assert!(matches!(m.validate(), Err(ManifestError::OracleLock)));
        assert!(matches!(manifest(6).validate(), Err(ManifestError::Rows(6))));
        let mut m = manifest(13);
        m.table[5].source = 1;
        assert!(matches!(m.validate(), Err(ManifestError::DuplicateSource(0, 5))));
        let mut m = manifest(13);
        m.table[4].pubkey = m.table[2].pubkey.clone();
        assert!(matches!(m.validate(), Err(ManifestError::DuplicateKey(2, 4))));
    }

    #[test]
    fn set_table_recomputes_hash() {
        let mut m = manifest(13);
        let old = m.table_hash.clone();
        m.set_table(rows(14)).unwrap();
        assert_ne!(m.table_hash, old);
        m.validate().unwrap();
    }
}
