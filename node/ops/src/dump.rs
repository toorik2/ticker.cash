//! `ticker-ops dump-state` — print deploy state + per-publisher state to stdout
//! as one JSON document. Useful for ops post-mortems and bootstrapping a manifest.

use serde_json::json;
use std::fs;
use std::path::PathBuf;

use ticker_core::cycle::state::PublisherState;
use ticker_core::identity::manifest::{load_manifest, ManifestError};

use crate::state::{load as load_deploy_state, DEFAULT_DEPLOY_STATE_PATH};

pub fn dump(state_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(state_dir);
    let manifest_path = dir.join("manifest.json");
    let deploy_path = dir.join(
        std::path::Path::new(DEFAULT_DEPLOY_STATE_PATH)
            .file_name()
            .unwrap_or_default(),
    );

    let manifest = match load_manifest(&manifest_path) {
        Ok(m) => {
            let slots_json: Vec<_> = m
                .slots
                .iter()
                .map(|s| {
                    json!({
                        "sourceId": s.source_id,
                        "sourceName": s.source_name,
                        "publisherPkhHex": s.publisher_pkh_hex,
                        "address": s.address,
                        "lockingBytecodeHex": s.locking_bytecode_hex,
                    })
                })
                .collect();
            Some(json!({
                "version": m.version,
                "network": format!("{:?}", m.network).to_lowercase(),
                "contracts": {
                    "ticker":  { "address": m.ticker.address,  "lockingBytecodeHex": m.ticker.locking_bytecode_hex },
                    "oracle":  { "address": m.oracle.address,  "lockingBytecodeHex": m.oracle.locking_bytecode_hex, "category": m.oracle.category },
                    "slotCategory": m.slot_category,
                    "slots": slots_json,
                },
                "publisherCount": m.slots.len(),
                "electrum": { "host": m.electrum.host, "port": m.electrum.port, "tls": m.electrum.tls },
            }))
        }
        Err(ManifestError::NotFound(_)) => None,
        Err(e) => return Err(Box::new(e)),
    };

    let deploy = load_deploy_state(&deploy_path).ok();

    // Publisher state files: .ticker/publisher-state-*.json
    let mut publishers = Vec::new();
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else { continue };
            let Some(rest) = name
                .strip_prefix("publisher-state-")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(slot) = rest.parse::<u8>() else { continue };
            let body = fs::read_to_string(entry.path()).unwrap_or_default();
            let s: PublisherState = serde_json::from_str(&body).unwrap_or_default();
            publishers.push(json!({
                "slot": slot,
                "lastCycleSeq": s.last_cycle_seq,
                "lastAttestTxid": s.last_attest_txid,
                "lastUpdateTxid": s.last_update_txid,
            }));
        }
    }
    publishers.sort_by_key(|v| v.get("slot").and_then(|x| x.as_u64()).unwrap_or(0));

    let payload = json!({
        "stateDir": state_dir,
        "manifest": manifest,
        "deploy": deploy,
        "publishers": publishers,
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}
