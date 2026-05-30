//! `ticker-ops setup-all` — generate per-slot install directories on the
//! coordinator's box from `seed.hex` + `deploy-state.json`.
//!
//! v13: publisher-only. Each slot gets `$home/.ticker-slot-N/` with its
//! manifest.json and publisher.key. The v12 notary tier is gone — slots 0..6
//! no longer get a `notary.key` and the manifest no longer has `notaryPubkeys`.
//!
//! systemd units running `ticker-node` set `TICKER_HOME=$home/.ticker-slot-%i`
//! to pick up the right per-slot identity.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde_json::json;
use ticker_core::chain::sources::SOURCES;
use ticker_core::identity::seed::{derive_wallet, load_seed};

use crate::state::load as load_state;

const PUBLISHER_COUNT: usize = 13;

pub fn setup_all(
    seed_path: &str,
    state_path: &str,
    out_base: &str,
    network: &str,
    electrum_host: &str,
    electrum_port: u16,
    electrum_tls: bool,
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
    let slot_addr = deploy.slot_address.ok_or("deploy-state missing slotAddress")?;
    let slot_lb = deploy
        .slot_locking_bytecode_hex
        .ok_or("deploy-state missing slotLockingBytecodeHex")?;
    let slot_cat = deploy.slot_category.ok_or("deploy-state missing slotCategory")?;

    let publisher_pkhs: Vec<String> = (0..PUBLISHER_COUNT)
        .map(|i| {
            derive_wallet(&seed, &format!("publisher-{i}"))
                .map(|w| hex::encode(w.pkh))
        })
        .collect::<Result<_, _>>()?;

    // Single canonical manifest content shared across all 13 slot dirs.
    let manifest = json!({
        "version": 1,
        "network": network,
        "contracts": {
            "ticker": { "address": ticker_addr,  "lockingBytecodeHex": ticker_lb },
            "oracle": { "address": oracle_addr,  "lockingBytecodeHex": oracle_lb, "category": oracle_cat },
            "slot":   { "address": slot_addr,    "lockingBytecodeHex": slot_lb,   "category": slot_cat   },
        },
        "publisherPkhs": publisher_pkhs,
        "electrum": { "host": electrum_host, "port": electrum_port, "tls": electrum_tls },
    });
    let manifest_text = serde_json::to_string_pretty(&manifest)?;

    let out_base = PathBuf::from(out_base);
    fs::create_dir_all(&out_base)?;

    println!("setup-all: writing 13 per-slot dirs under {}", out_base.display());

    for slot in 0..PUBLISHER_COUNT {
        let slot_dir = out_base.join(format!(".ticker-slot-{slot}"));
        fs::create_dir_all(&slot_dir)?;

        // Manifest — same content for every slot.
        let manifest_path = slot_dir.join("manifest.json");
        fs::write(&manifest_path, &manifest_text)?;

        // Publisher key — every slot has one (slot N → publisher-N).
        let pub_w = derive_wallet(&seed, &format!("publisher-{slot}"))?;
        let pub_key_path = slot_dir.join("publisher.key");
        fs::write(&pub_key_path, hex::encode(pub_w.private_key))?;
        let mut perms = fs::metadata(&pub_key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&pub_key_path, perms)?;

        // Sources index sanity print — confirms slot N maps to source N+1.
        let src_id = SOURCES.get(slot).map(|s| s.id).unwrap_or(0);
        println!(
            "  slot {slot:>2} → {slot_dir} (source_id={src_id})",
            slot_dir = slot_dir.display(),
        );
    }

    println!("\nsetup-all done. Layout:");
    println!("  .ticker-slot-N/manifest.json    (identical across slots)");
    println!("  .ticker-slot-N/publisher.key    (slot N's publisher key, 0600)");
    println!("\nsystemd unit must set: Environment=TICKER_HOME=%h/.ticker-slot-%i");
    Ok(())
}
