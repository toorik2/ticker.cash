//! The public deployment manifest.
//!
//! Everything a prover, builder, sweeper, consumer or dashboard needs to find and verify a
//! deployment, and nothing secret: the token category, the two locking bytecodes, the notary
//! table with each row's exchange and endpoints, and the Electrum pool. The table is also
//! what the Oracle covenant was deployed with, so `oracle_lock` is derivable from it; the
//! loader checks that derivation and refuses a manifest whose parts disagree.

use crate::sources::source_by_id;
use crate::tx::covenant::{oracle_lock_for_table, ticker_lock, TABLE_ENTRY_LEN};
use crate::ROWS;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableRow {
    pub row: u8,
    /// Exchange id (`sources::SOURCES`), the `source` byte of every statement from this row.
    pub source: u8,
    /// 33-byte compressed notary pubkey, hex.
    pub pubkey: String,
    pub operator: String,
    /// Prover session endpoint, `tcp://host:port`.
    pub notary: String,
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
    /// P2SH-32 locking bytecode of the head, hex (35 B).
    pub oracle_lock: String,
    /// P2S locking bytecode of Tickers, hex (31 B).
    pub ticker_lock: String,
    pub table: Vec<TableRow>,
    pub electrum: Vec<ElectrumEndpoint>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("manifest version {0} is not 25")]
    Version(u32),
    #[error("table has {0} rows, expected 13")]
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
    #[error("oracle_lock does not match the lock derived from the table")]
    OracleLock,
    #[error("ticker_lock does not match the compiled Ticker covenant")]
    TickerLock,
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
        if self.version != 25 {
            return Err(ManifestError::Version(self.version));
        }
        if self.network != "chipnet" && self.network != "mainnet" {
            return Err(ManifestError::Network);
        }
        if self.table.len() != ROWS {
            return Err(ManifestError::Rows(self.table.len()));
        }
        if self.electrum.is_empty() {
            return Err(ManifestError::Electrum);
        }
        for (i, r) in self.table.iter().enumerate() {
            if r.row as usize != i {
                return Err(ManifestError::RowOrder(r.row));
            }
            if source_by_id(r.source).is_none() {
                return Err(ManifestError::Source { row: r.row, source_id: r.source });
            }
            if r.pubkey_bytes().is_none() {
                return Err(ManifestError::Pubkey(r.row));
            }
            for other in &self.table[..i] {
                if other.pubkey == r.pubkey {
                    return Err(ManifestError::DuplicateKey(other.row, r.row));
                }
                if other.source == r.source {
                    return Err(ManifestError::DuplicateSource(other.row, r.row));
                }
            }
        }
        if hex::decode(&self.category).map(|c| c.len() != 32).unwrap_or(true) {
            return Err(ManifestError::Category);
        }
        let derived = oracle_lock_for_table(&self.table_bytes());
        if hex::encode(derived) != self.oracle_lock {
            return Err(ManifestError::OracleLock);
        }
        if hex::encode(ticker_lock()) != self.ticker_lock {
            return Err(ManifestError::TickerLock);
        }
        Ok(())
    }

    /// The 442-byte table exactly as the Oracle covenant was deployed with it.
    pub fn table_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ROWS * TABLE_ENTRY_LEN);
        for r in &self.table {
            out.extend_from_slice(&r.pubkey_bytes().expect("validated"));
            out.push(r.source);
        }
        out
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
}

impl TableRow {
    pub fn pubkey_bytes(&self) -> Option<[u8; 33]> {
        hex::decode(&self.pubkey).ok()?.try_into().ok()
    }
}
