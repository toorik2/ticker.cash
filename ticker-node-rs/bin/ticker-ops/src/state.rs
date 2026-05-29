//! Shared deploy-state schema for coordinator tooling.
//!
//! Mirrors TS `daemon/scripts/deploy.ts`'s persisted `.ticker/deploy-state.json`
//! so a Rust deploy can resume a partial TS deploy and vice-versa.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const DEFAULT_DEPLOY_STATE_PATH: &str = ".ticker/deploy-state.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotMinted {
    pub source_id: u16,
    pub pkh_hex: String,
    pub publisher_label: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployState {
    // Ticker
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticker_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticker_locking_bytecode_hex: Option<String>,
    // Oracle
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_locking_bytecode_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_mint_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oracle_prep_txid: Option<String>,
    // Slot
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_locking_bytecode_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_mint_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot_prep_txid: Option<String>,
    // Slot mint outcomes (per-publisher)
    #[serde(default)]
    pub slots_minted: Vec<SlotMinted>,
    // Oracle bootstrap
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_last_ts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_median_sats: Option<String>,
}

pub fn load(path: impl AsRef<Path>) -> Result<DeployState, Box<dyn std::error::Error>> {
    match fs::read_to_string(&path) {
        Ok(s) => Ok(serde_json::from_str(&s)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeployState::default()),
        Err(e) => Err(Box::new(e)),
    }
}

pub fn save(
    path: impl AsRef<Path>,
    state: &DeployState,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let body = serde_json::to_vec_pretty(state)?;
    fs::write(path, body)?;
    Ok(())
}
