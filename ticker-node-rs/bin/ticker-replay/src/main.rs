//! ticker-replay — read captured production cycles and replay through the
//! Rust tx builders, byte-diffing each rebuilt tx against the TS golden.
//!
//! Inputs:
//!   * A JSONL file produced by the TS daemon's `capture.ts` hook
//!     (`TICKER_CAPTURE_DIR=… tsx ticker-node.ts ...`).
//!   * The same seed.hex + manifest.json the daemon was running against.
//!   * The slot the captured publisher was running.
//!
//! For each record we recognize, we rebuild the corresponding tx with
//! `ticker-core::tx::build_attest_tx` or `build_oracle_update_tx`, then compare
//! the resulting bytes to the captured `raw` hex. Any mismatch is reported with
//! the byte-offset and a short hexdump around the first differing byte.
//!
//! Exit status:
//!   0 — every record matched.
//!   1 — at least one record mismatched (test failure).
//!   2 — input parse error / bad CLI args.

use std::fs;
use std::process;

use serde_json::Value;

use ticker_core::chain::oracle_commit::decode_oracle_commit;
use ticker_core::chain::slot_commit::{decode_slot_commit, SlotCommit};
use ticker_core::chain::sources::{packed_cn_hashes, SOURCES};
use ticker_core::covenant::{
    locking::p2sh32_locking_bytecode, redeem_oracle, redeem_publisher_slot, redeem_ticker,
};
use ticker_core::identity::manifest::load_manifest;
use ticker_core::identity::seed::{derive_wallet, load_seed};
use ticker_core::tx::attest::{
    build_attest_tx, AttestArgs, FunderUtxo, NotaryAttestation, SlotUtxo,
};
use ticker_core::tx::update::{
    build_oracle_update_tx, CycleSlotUtxo, OracleUtxo, UpdateArgs,
};

const DEFAULT_CAPTURE_FILE: &str = ".ticker/capture/cycle-LATEST.jsonl";
const DEFAULT_SEED: &str = ".ticker/seed.hex";
const DEFAULT_MANIFEST: &str = ".ticker/manifest.json";

fn main() {
    let mut args = pico_args::Arguments::from_env();
    let file: String = match args.opt_value_from_str("--file") {
        Ok(Some(v)) => v,
        Ok(None) => DEFAULT_CAPTURE_FILE.to_string(),
        Err(e) => {
            eprintln!("ticker-replay: bad --file: {e}");
            process::exit(2);
        }
    };
    let seed_path: String = args
        .opt_value_from_str("--seed")
        .unwrap_or(None)
        .unwrap_or_else(|| DEFAULT_SEED.to_string());
    let manifest_path: String = args
        .opt_value_from_str("--manifest")
        .unwrap_or(None)
        .unwrap_or_else(|| DEFAULT_MANIFEST.to_string());
    let slot: u8 = match args.value_from_str("--slot") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ticker-replay: missing --slot: {e}");
            process::exit(2);
        }
    };

    match run(&file, &seed_path, &manifest_path, slot) {
        Ok(0) => {
            println!("✓ all records matched");
            process::exit(0);
        }
        Ok(mismatched) => {
            println!("✗ {mismatched} mismatched record(s)");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("ticker-replay: {e}");
            process::exit(2);
        }
    }
}

/// Returns the count of mismatched records.
fn run(
    file: &str,
    seed_path: &str,
    manifest_path: &str,
    slot: u8,
) -> Result<usize, Box<dyn std::error::Error>> {
    let body = fs::read_to_string(file)?;
    let seed = load_seed(seed_path)?;
    let manifest = load_manifest(manifest_path)?;
    let publisher = derive_wallet(&seed, &format!("publisher-{slot}"))?;

    let source = SOURCES.get(slot as usize).ok_or("slot exceeds SOURCES length")?;

    // Build redeem scripts from manifest fields, just like the runtime daemon.
    let oracle_cat_be = hex::decode(&manifest.oracle.category)?;
    let mut oracle_cat_le: [u8; 32] = oracle_cat_be.as_slice().try_into()?;
    oracle_cat_le.reverse();
    let slot_cat_be = hex::decode(&manifest.slot.category)?;
    let mut slot_cat_le: [u8; 32] = slot_cat_be.as_slice().try_into()?;
    slot_cat_le.reverse();
    let ticker_lb: [u8; 35] = hex::decode(&manifest.ticker.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;
    let oracle_lb: [u8; 35] = hex::decode(&manifest.oracle.locking_bytecode_hex)?
        .as_slice()
        .try_into()?;
    let mut notary_pubkeys = [[0u8; 33]; 7];
    for (i, hx) in manifest.notary_pubkeys.iter().enumerate() {
        notary_pubkeys[i].copy_from_slice(&hex::decode(hx)?);
    }
    let oracle_redeem = redeem_oracle(&ticker_lb, &slot_cat_le)?;
    let slot_redeem = redeem_publisher_slot(
        &notary_pubkeys,
        &packed_cn_hashes(),
        &oracle_cat_le,
        &oracle_lb,
    )?;
    let ticker_redeem = redeem_ticker()?;
    let _ = p2sh32_locking_bytecode; // verify import resolves

    let mut mismatched = 0usize;
    let mut record_count = 0usize;

    // Sidecar: stash the most recent "input" record so attest/update replays
    // can read its fields if needed (today the attest/update records carry
    // everything they need on their own).
    let mut last_input: Option<Value> = None;

    for (lineno, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: Value = serde_json::from_str(line)?;
        let kind = rec
            .get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("line {}: missing kind", lineno + 1))?;
        record_count += 1;
        match kind {
            "input" => {
                last_input = Some(rec);
            }
            "attest" => {
                let r = replay_attest(
                    &rec,
                    &publisher,
                    &slot_redeem,
                    slot_cat_le,
                    source.id,
                )?;
                match r {
                    ReplayResult::Match { len } => {
                        println!("  attest line {}: ✓ {} bytes", lineno + 1, len);
                    }
                    ReplayResult::Mismatch { offset, ours, theirs } => {
                        mismatched += 1;
                        println!(
                            "  attest line {}: ✗ diff at offset {} (ours={}, theirs={})",
                            lineno + 1,
                            offset,
                            hex::encode(&ours),
                            hex::encode(&theirs)
                        );
                    }
                }
            }
            "update" => {
                let r = replay_update(
                    &rec,
                    &publisher,
                    &oracle_redeem,
                    &slot_redeem,
                    &ticker_redeem,
                    oracle_cat_le,
                    slot_cat_le,
                )?;
                match r {
                    ReplayResult::Match { len } => {
                        println!("  update line {}: ✓ {} bytes", lineno + 1, len);
                    }
                    ReplayResult::Mismatch { offset, ours, theirs } => {
                        mismatched += 1;
                        println!(
                            "  update line {}: ✗ diff at offset {} (ours={}, theirs={})",
                            lineno + 1,
                            offset,
                            hex::encode(&ours),
                            hex::encode(&theirs)
                        );
                    }
                }
            }
            other => {
                println!("  line {}: skipping unknown kind '{other}'", lineno + 1);
            }
        }
    }
    let _ = (manifest, last_input); // keep refs alive; both are part of replay context
    println!("\nreplay summary: {record_count} records, {mismatched} mismatches");
    Ok(mismatched)
}

enum ReplayResult {
    Match { len: usize },
    Mismatch { offset: usize, ours: Vec<u8>, theirs: Vec<u8> },
}

fn diff_bytes(ours: &[u8], theirs: &[u8]) -> ReplayResult {
    if ours == theirs {
        return ReplayResult::Match { len: ours.len() };
    }
    let min_len = ours.len().min(theirs.len());
    let mut offset = min_len;
    for i in 0..min_len {
        if ours[i] != theirs[i] {
            offset = i;
            break;
        }
    }
    let win = 8;
    let ours_slice = &ours[offset.saturating_sub(0)..offset.saturating_add(win).min(ours.len())];
    let theirs_slice =
        &theirs[offset.saturating_sub(0)..offset.saturating_add(win).min(theirs.len())];
    ReplayResult::Mismatch {
        offset,
        ours: ours_slice.to_vec(),
        theirs: theirs_slice.to_vec(),
    }
}

fn replay_attest(
    rec: &Value,
    publisher: &ticker_core::identity::seed::DerivedWallet,
    slot_redeem: &[u8],
    slot_cat_le: [u8; 32],
    source_id: u16,
) -> Result<ReplayResult, Box<dyn std::error::Error>> {
    let expected_hex = rec
        .get("raw")
        .and_then(|v| v.as_str())
        .ok_or("attest: missing raw")?;
    let expected = hex::decode(expected_hex)?;
    let attestation = rec.get("attestation").ok_or("attest: missing attestation")?;
    let price: u64 = attestation
        .get("price")
        .and_then(|v| v.as_str())
        .ok_or("attest: missing price")?
        .parse()?;
    let timestamp: u32 = attestation
        .get("timestamp")
        .and_then(|v| v.as_u64())
        .ok_or("attest: missing timestamp")? as u32;
    let server_name = attestation
        .get("serverName")
        .and_then(|v| v.as_str())
        .ok_or("attest: missing serverName")?
        .to_string();
    let notary_sig_hex = attestation
        .get("notarySig")
        .and_then(|v| v.as_str())
        .ok_or("attest: missing notarySig")?;
    let notary_sig_bytes = hex::decode(notary_sig_hex)?;
    if notary_sig_bytes.len() != 64 {
        return Err(format!("notarySig must be 64 B, got {}", notary_sig_bytes.len()).into());
    }
    let mut notary_sig = [0u8; 64];
    notary_sig.copy_from_slice(&notary_sig_bytes);
    let notary_idx = rec
        .get("notaryIdx")
        .and_then(|v| v.as_u64())
        .ok_or("attest: missing notaryIdx")? as u32;
    let new_cycle_seq = attestation
        .get("cycleSeq")
        .and_then(|v| v.as_u64())
        .ok_or("attest: missing cycleSeq")? as u32;

    let my_slot = rec.get("mySlot").ok_or("attest: missing mySlot")?;
    let slot_utxo = SlotUtxo {
        txid_be: txid_be(my_slot.get("txid"))?,
        vout: my_slot.get("vout").and_then(|v| v.as_u64()).ok_or("mySlot.vout")? as u32,
        satoshis: my_slot
            .get("satoshis")
            .and_then(|v| v.as_str())
            .ok_or("mySlot.satoshis")?
            .parse()?,
    };
    let funder_utxos_v = rec
        .get("funderUtxos")
        .and_then(|v| v.as_array())
        .ok_or("attest: missing funderUtxos")?;
    let funders: Vec<FunderUtxo> = funder_utxos_v
        .iter()
        .map(|u| -> Result<FunderUtxo, Box<dyn std::error::Error>> {
            Ok(FunderUtxo {
                txid_be: txid_be(u.get("txid"))?,
                vout: u.get("vout").and_then(|v| v.as_u64()).ok_or("funder.vout")? as u32,
                satoshis: u
                    .get("satoshis")
                    .and_then(|v| v.as_str())
                    .ok_or("funder.satoshis")?
                    .parse()?,
            })
        })
        .collect::<Result<_, _>>()?;

    let args = AttestArgs {
        slot_utxo,
        source_id,
        publisher_pkh: publisher.pkh,
        publisher_privkey: publisher.private_key,
        publisher_pubkey: publisher.public_key,
        funder_utxos: &funders,
        slot_category_wire_le: slot_cat_le,
        slot_redeem_script: slot_redeem,
        notary: NotaryAttestation {
            price,
            timestamp,
            server_name,
            notary_sig,
            notary_idx,
        },
        new_cycle_seq,
    };
    let rebuilt = build_attest_tx(&args)?;
    Ok(diff_bytes(&rebuilt, &expected))
}

fn replay_update(
    rec: &Value,
    publisher: &ticker_core::identity::seed::DerivedWallet,
    oracle_redeem: &[u8],
    slot_redeem: &[u8],
    ticker_redeem: &[u8],
    oracle_cat_le: [u8; 32],
    slot_cat_le: [u8; 32],
) -> Result<ReplayResult, Box<dyn std::error::Error>> {
    let expected_hex = rec
        .get("raw")
        .and_then(|v| v.as_str())
        .ok_or("update: missing raw")?;
    let expected = hex::decode(expected_hex)?;

    let oracle_utxo_v = rec.get("oracleUtxo").ok_or("update: missing oracleUtxo")?;
    let oracle_commit_hex = oracle_utxo_v
        .get("commitment")
        .and_then(|v| v.as_str())
        .ok_or("oracleUtxo.commitment")?;
    let oracle_commit_bytes = hex::decode(oracle_commit_hex)?;
    let prev_state = decode_oracle_commit(&oracle_commit_bytes)?;
    let oracle_utxo = OracleUtxo {
        txid_be: txid_be(oracle_utxo_v.get("txid"))?,
        vout: oracle_utxo_v.get("vout").and_then(|v| v.as_u64()).ok_or("oracleUtxo.vout")? as u32,
        satoshis: oracle_utxo_v
            .get("satoshis")
            .and_then(|v| v.as_str())
            .ok_or("oracleUtxo.satoshis")?
            .parse()?,
        prev_state,
    };

    let cycle_slots_v = rec
        .get("cycleSlots")
        .and_then(|v| v.as_array())
        .ok_or("update: missing cycleSlots")?;
    let mut cycle_slots: Vec<CycleSlotUtxo> = Vec::with_capacity(cycle_slots_v.len());
    for s in cycle_slots_v {
        let commitment_hex = s
            .get("commitment")
            .and_then(|v| v.as_str())
            .ok_or("slot.commitment")?;
        let commitment_bytes = hex::decode(commitment_hex)?;
        let SlotCommit { source_id: _, pkh, price, timestamp, cycle_seq: _ } =
            decode_slot_commit(&commitment_bytes).ok_or("bad slot commit")?;
        let mut commitment = [0u8; 39];
        commitment.copy_from_slice(&commitment_bytes);
        cycle_slots.push(CycleSlotUtxo {
            txid_be: txid_be(s.get("txid"))?,
            vout: s.get("vout").and_then(|v| v.as_u64()).ok_or("slot.vout")? as u32,
            satoshis: s.get("satoshis").and_then(|v| v.as_str()).ok_or("slot.sats")?.parse()?,
            pkh,
            price,
            timestamp,
            commitment,
        });
    }

    let funder_v = rec
        .get("updateFunder")
        .and_then(|v| v.as_array())
        .ok_or("update: missing updateFunder")?;
    let funders: Vec<FunderUtxo> = funder_v
        .iter()
        .map(|u| -> Result<FunderUtxo, Box<dyn std::error::Error>> {
            Ok(FunderUtxo {
                txid_be: txid_be(u.get("txid"))?,
                vout: u.get("vout").and_then(|v| v.as_u64()).ok_or("funder.vout")? as u32,
                satoshis: u.get("satoshis").and_then(|v| v.as_str()).ok_or("funder.sats")?.parse()?,
            })
        })
        .collect::<Result<_, _>>()?;

    let new_seq = prev_state.seq + 1;
    let args = UpdateArgs {
        oracle_utxo,
        cycle_slots: &cycle_slots,
        funder_utxos: &funders,
        publisher_pkh: publisher.pkh,
        publisher_privkey: publisher.private_key,
        publisher_pubkey: publisher.public_key,
        oracle_category_wire_le: oracle_cat_le,
        slot_category_wire_le: slot_cat_le,
        oracle_redeem_script: oracle_redeem,
        slot_redeem_script: slot_redeem,
        ticker_redeem_script: ticker_redeem,
        new_seq,
    };
    let rebuilt = build_oracle_update_tx(&args)?;
    Ok(diff_bytes(&rebuilt, &expected))
}

fn txid_be(v: Option<&Value>) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let s = v.and_then(|x| x.as_str()).ok_or("txid not a string")?;
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        return Err(format!("txid len {} != 32", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

