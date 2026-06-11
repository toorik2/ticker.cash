//! Embedded cashc artifact JSONs — parsed once to extract `debug.bytecode`
//! (the compiled-bytecode hex string).
//!
//! cashc v0.13 stores two bytecode representations in each artifact:
//!   - `bytecode`         — human-readable assembly (OP_DUP OP_HASH160 …)
//!   - `debug.bytecode`   — the same script as raw hex (THIS is what we want)
//!
//! Parsing happens at runtime (once, on first access) via a thread-safe `OnceLock`.
//! The JSON files themselves are embedded at compile time via `include_str!()`.
//!
//! **v24 P06 — cashc-version-pin: 0.13.0.** Any cashc upgrade requires
//! re-running both `cargo test oracle_v23_template_fingerprint` and
//! `cargo test slot_v23_template_fingerprint` ; both tests trip loudly on
//! emit drift so the operator notices before the regenerated artifact
//! lands in a release build.

use serde_json::Value;
use std::sync::OnceLock;

const ORACLE_JSON: &str = include_str!("../../../../contracts/artifacts/Oracle.json");
const PUBLISHER_SLOT_JSON: &str = include_str!("../../../../contracts/artifacts/PublisherSlot.json");
const TICKER_JSON: &str = include_str!("../../../../contracts/artifacts/Ticker.json");

/// Errors that can occur parsing an embedded artifact.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact missing field `debug.bytecode`")]
    MissingBytecode,
    #[error("artifact `debug.bytecode` is not a string")]
    BytecodeNotString,
    #[error("artifact `debug.bytecode` is not valid hex: {0}")]
    BadHex(#[from] hex::FromHexError),
}

fn parse_debug_bytecode(json_text: &str) -> Result<Vec<u8>, ArtifactError> {
    let root: Value = serde_json::from_str(json_text)?;
    let bc = root
        .get("debug")
        .and_then(|d| d.get("bytecode"))
        .ok_or(ArtifactError::MissingBytecode)?
        .as_str()
        .ok_or(ArtifactError::BytecodeNotString)?;
    Ok(hex::decode(bc)?)
}

static ORACLE_BYTECODE: OnceLock<Vec<u8>> = OnceLock::new();
static SLOT_BYTECODE: OnceLock<Vec<u8>> = OnceLock::new();
static TICKER_BYTECODE: OnceLock<Vec<u8>> = OnceLock::new();

/// Raw bytecode of `Oracle.cash`, before constructor-arg prepending.
pub fn oracle_bytecode() -> Result<&'static [u8], ArtifactError> {
    if let Some(bc) = ORACLE_BYTECODE.get() {
        return Ok(bc);
    }
    let parsed = parse_debug_bytecode(ORACLE_JSON)?;
    Ok(ORACLE_BYTECODE.get_or_init(|| parsed))
}

/// Raw bytecode of `PublisherSlot.cash`, before constructor-arg prepending.
pub fn publisher_slot_bytecode() -> Result<&'static [u8], ArtifactError> {
    if let Some(bc) = SLOT_BYTECODE.get() {
        return Ok(bc);
    }
    let parsed = parse_debug_bytecode(PUBLISHER_SLOT_JSON)?;
    Ok(SLOT_BYTECODE.get_or_init(|| parsed))
}

/// Raw bytecode of `Ticker.cash`. `Ticker` has no constructor args, so this
/// IS the full redeem script.
pub fn ticker_bytecode() -> Result<&'static [u8], ArtifactError> {
    if let Some(bc) = TICKER_BYTECODE.get() {
        return Ok(bc);
    }
    let parsed = parse_debug_bytecode(TICKER_JSON)?;
    Ok(TICKER_BYTECODE.get_or_init(|| parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticker_bytecode_is_nonempty() {
        let bc = ticker_bytecode().unwrap();
        assert!(!bc.is_empty());
    }

    #[test]
    fn all_three_artifacts_parse() {
        assert!(oracle_bytecode().is_ok());
        assert!(publisher_slot_bytecode().is_ok());
        assert!(ticker_bytecode().is_ok());
    }

    /// PublisherSlot bytecode is the largest (most logic).
    #[test]
    fn relative_sizes_make_sense() {
        let t = ticker_bytecode().unwrap().len();
        let o = oracle_bytecode().unwrap().len();
        let s = publisher_slot_bytecode().unwrap().len();
        assert!(t < o, "ticker {} < oracle {}", t, o);
        // Oracle and PublisherSlot are both substantial; either may be larger.
        assert!(s > 100);
    }
}
