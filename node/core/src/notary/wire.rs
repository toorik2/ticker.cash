//! Wire shapes for `POST /sign`.
//!
//! Mirrors the TS daemon (`daemon/scripts/notary.ts:111-126`) bit-for-bit so a
//! Rust publisher can talk to a TS notary and vice-versa.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct SignRequest {
    #[serde(rename = "sourceId")]
    pub source_id: u16,
    #[serde(rename = "cycleSeq")]
    pub cycle_seq: u32,
    /// 40-hex publisher pubkey-hash (the slot's pinned identity).
    #[serde(rename = "pubkeyHash")]
    pub pubkey_hash: String,
    /// Optional flag (unused server-side today; present for forward-compat).
    #[serde(default)]
    pub fresh: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignResponse {
    #[serde(rename = "sourceId")]
    pub source_id: u16,
    #[serde(rename = "cycleSeq")]
    pub cycle_seq: u32,
    /// u64 as decimal string (matches TS `BigInt.toString()`).
    pub price: String,
    pub timestamp: u32,
    #[serde(rename = "serverName")]
    pub server_name: String,
    /// 128 hex chars (64 B Schnorr signature).
    #[serde(rename = "notarySig")]
    pub notary_sig: String,
    /// 66 hex chars (33 B compressed notary pubkey).
    #[serde(rename = "notaryPubkey")]
    pub notary_pubkey: String,
}
