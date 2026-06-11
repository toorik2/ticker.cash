//! `ticker-ops setup-all` — generate per-slot install directories on the
//! coordinator's box from `seed.hex` + `deploy-state.json`.
//!
//! Publisher-only (notary tier was dropped in v13; reaffirmed in v15+). Each
//! slot gets `$home/.ticker-slot-N/` with its manifest.json and publisher.key.
//!
//! systemd units running `ticker-node` set `TICKER_HOME=$home/.ticker-slot-%i`
//! to pick up the right per-slot identity.
//!
//! v16: manifest schema reshaped — singular `contracts.slot` becomes
//! per-source `contracts.slots[]` with shared `contracts.slotCategory`. Each
//! slot entry carries its own cnHash, address, and locking bytecode.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde_json::json;
use ticker_core::chain::sources::SOURCES;
use ticker_core::identity::seed::{derive_wallet, load_seed};

use crate::state::load as load_state;

const PUBLISHER_COUNT: usize = 13;
const MANIFEST_VERSION_V16: u32 = 2;

pub fn setup_all(
    seed_path: &str,
    state_path: &str,
    out_base: &str,
    network: &str,
    electrum_host: &str,
    electrum_port: u16,
    electrum_tls: bool,
    electrum_fallbacks: &[(String, u16)],
) -> Result<(), Box<dyn std::error::Error>> {
    if network != "chipnet" && network != "mainnet" {
        return Err("--network must be 'chipnet' or 'mainnet'".into());
    }
    let seed = load_seed(seed_path)?;
    let deploy = load_state(state_path)?;

    // Required fields from deploy-state — refuse to proceed if any missing.
    let ticker_addr = deploy.ticker_address.ok_or("deploy-state missing tickerAddress")?;
    let ticker_lb = deploy
        .ticker_locking_bytecode_hex
        .ok_or("deploy-state missing tickerLockingBytecodeHex")?;
    let oracle_addr = deploy.oracle_address.ok_or("deploy-state missing oracleAddress")?;
    let oracle_lb = deploy
        .oracle_locking_bytecode_hex
        .ok_or("deploy-state missing oracleLockingBytecodeHex")?;
    let oracle_cat = deploy.oracle_category.ok_or("deploy-state missing oracleCategory")?;
    let slot_cat = deploy.slot_category.ok_or("deploy-state missing slotCategory")?;

    // v16: pull per-slot data from slots_minted[] (singular slot_address is
    // deprecated and set to None by v16 deploy.rs).
    if deploy.slots_minted.len() != PUBLISHER_COUNT {
        return Err(format!(
            "deploy-state.slots_minted has {} entries; expected {PUBLISHER_COUNT} for v16",
            deploy.slots_minted.len()
        )
        .into());
    }
    let publisher_pkhs: Vec<String> = (0..PUBLISHER_COUNT)
        .map(|i| derive_wallet(&seed, &format!("publisher-{i}")).map(|w| hex::encode(w.pkh)))
        .collect::<Result<_, _>>()?;

    // Fallback endpoints get serialized in the same shape as the primary so
    // operators can promote one by editing the manifest.
    let fallbacks_json: Vec<serde_json::Value> = electrum_fallbacks
        .iter()
        .map(|(h, p)| json!({ "host": h, "port": p, "tls": true }))
        .collect();

    // Per-slot entries built from slots_minted + SOURCES (zipped by index).
    let mut slots_json = Vec::with_capacity(PUBLISHER_COUNT);
    for (i, sm) in deploy.slots_minted.iter().enumerate() {
        let src = SOURCES.get(i).ok_or("slot index exceeds SOURCES")?;
        let address = sm
            .address
            .clone()
            .ok_or_else(|| format!("slots_minted[{i}] missing address (v15 state?)"))?;
        let locking_bytecode_hex = sm
            .locking_bytecode_hex
            .clone()
            .ok_or_else(|| format!("slots_minted[{i}] missing lockingBytecodeHex"))?;
        let cn_hash_hex = sm
            .cn_hash_hex
            .clone()
            .ok_or_else(|| format!("slots_minted[{i}] missing cnHashHex"))?;
        slots_json.push(json!({
            "sourceId": sm.source_id,
            "sourceName": src.name,
            "cnHashHex": cn_hash_hex,
            "publisherPkhHex": publisher_pkhs[i],
            "address": address,
            "lockingBytecodeHex": locking_bytecode_hex,
        }));
    }

    let manifest = json!({
        "version": MANIFEST_VERSION_V16,
        "network": network,
        "contracts": {
            "ticker": { "address": ticker_addr,  "lockingBytecodeHex": ticker_lb },
            "oracle": { "address": oracle_addr,  "lockingBytecodeHex": oracle_lb, "category": oracle_cat },
            "slotCategory": slot_cat,
            "slots": slots_json,
        },
        "electrum": {
            "host": electrum_host,
            "port": electrum_port,
            "tls": electrum_tls,
            "fallbacks": fallbacks_json,
        },
    });
    let manifest_text = serde_json::to_string_pretty(&manifest)?;

    let out_base = PathBuf::from(out_base);
    fs::create_dir_all(&out_base)?;

    println!("setup-all (v16): writing 13 per-slot dirs under {}", out_base.display());

    for slot in 0..PUBLISHER_COUNT {
        let slot_dir = out_base.join(format!(".ticker-slot-{slot}"));
        fs::create_dir_all(&slot_dir)?;

        // Manifest — same content for every slot (v16: each daemon reads
        // its own slot via manifest.slot_for(source_id)).
        let manifest_path = slot_dir.join("manifest.json");
        fs::write(&manifest_path, &manifest_text)?;
        // v24 P07 — manifest at 0o600 so the P07 F13 perm gate in the
        // daemon accepts it. Without this, freshly-written manifests
        // landed at umask-default 0o644 and tripped the new check.
        let mut mperms = fs::metadata(&manifest_path)?.permissions();
        mperms.set_mode(0o600);
        fs::set_permissions(&manifest_path, mperms)?;

        // Publisher key — every slot has one (slot N → publisher-N).
        let pub_w = derive_wallet(&seed, &format!("publisher-{slot}"))?;
        let pub_key_path = slot_dir.join("publisher.key");
        fs::write(&pub_key_path, hex::encode(pub_w.private_key))?;
        let mut perms = fs::metadata(&pub_key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&pub_key_path, perms)?;

        let src_id = SOURCES.get(slot).map(|s| s.id).unwrap_or(0);
        println!(
            "  slot {slot:>2} → {slot_dir} (source_id={src_id})",
            slot_dir = slot_dir.display(),
        );
    }

    println!("\nsetup-all done. Layout:");
    println!("  .ticker-slot-N/manifest.json    (identical across slots, v16 schema)");
    println!("  .ticker-slot-N/publisher.key    (slot N's publisher key, 0600)");
    println!("\nsystemd unit must set: Environment=TICKER_HOME=%h/.ticker-slot-%i");
    Ok(())
}
