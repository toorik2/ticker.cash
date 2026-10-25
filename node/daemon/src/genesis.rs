//! Genesis: one transaction that mints the head NFT with the reserve and fixes the category.
//!
//! Reads `genesis.json` (network, electrum pool, the table rows), picks a coin of the operator key
//! whose output index is 0 (a CashTokens category genesis must spend such an outpoint; if none
//! exists a self-spend creates one first), builds the genesis transaction, broadcasts it, and
//! writes `manifest.json`. The head starts at the previous minute with price 0 and k 0.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use ticker_core::commit::current_minute;
use ticker_core::crypto::schnorr_sign;
use ticker_core::keyfile::load_key;
use ticker_core::manifest::{table_bytes, validate_rows, ElectrumEndpoint, Manifest, TableRow, MANIFEST_VERSION};
use ticker_core::tx::cashaddr::{encode_p2pkh_cashaddr, encode_p2sh32_cashaddr, AddressPrefix};
use ticker_core::tx::covenant::{oracle_lock, table_hash, ticker_lock};
use ticker_core::tx::encode::{encode_tx, Input, Output, Tx, TxOutpoint, SEQUENCE_FINAL};
use ticker_core::tx::script::{p2pkh_locking_script, push_data};
use ticker_core::tx::sighash::{sighash_digest, SpentOutput, SIGHASH_ALL_UTXOS_FORKID};
use ticker_core::tx::{build_genesis, P2pkhInput};
use ticker_core::log_info;

use crate::chain;

#[derive(Deserialize)]
struct GenesisSpec {
    network: String,
    table: Vec<TableRow>,
    electrum: Vec<ElectrumEndpoint>,
}

fn provisional_manifest(spec: GenesisSpec) -> Result<Manifest> {
    validate_rows(&spec.table).context("genesis table")?;
    let th = table_hash(&table_bytes(&spec.table));
    let m = Manifest {
        version: MANIFEST_VERSION,
        network: spec.network,
        category: "00".repeat(32),
        genesis_txid: String::new(),
        oracle_lock: hex::encode(oracle_lock()),
        ticker_lock: hex::encode(ticker_lock()),
        table_hash: hex::encode(th),
        table: spec.table,
        electrum: spec.electrum,
    };
    m.validate().context("genesis spec")?;
    Ok(m)
}

/// Print the locks, head address and table hash a genesis.json would produce (no network, no funds).
pub fn derive(home: &PathBuf) -> Result<()> {
    let spec: GenesisSpec = serde_json::from_str(&std::fs::read_to_string(home.join("genesis.json")).context("genesis.json")?)?;
    let prefix = AddressPrefix::from_network(&spec.network).ok_or_else(|| anyhow!("network must be chipnet or mainnet"))?;
    let m = provisional_manifest(spec)?;
    println!("oracle_lock  {}", m.oracle_lock);
    println!("ticker_lock  {}", m.ticker_lock);
    println!("head address {}", encode_p2sh32_cashaddr(&oracle_lock(), prefix));
    println!("table hash   {} ({} rows)", m.table_hash, m.table.len());
    Ok(())
}

pub fn genesis(home: &PathBuf, reserve: u64, dry_run: bool, prepare_only: bool) -> Result<()> {
    let spec: GenesisSpec = serde_json::from_str(&std::fs::read_to_string(home.join("genesis.json")).context("genesis.json")?)?;
    let prefix = AddressPrefix::from_network(&spec.network).ok_or_else(|| anyhow!("network must be chipnet or mainnet"))?;
    let key = load_key(home.join("operator.key"))?;
    let manifest_path = home.join("manifest.json");
    if manifest_path.exists() {
        bail!("{} exists; refusing to run genesis twice", manifest_path.display());
    }
    let mut m = provisional_manifest(spec)?;
    let th = m.table_hash_bytes();
    let lock = oracle_lock();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async {
        let coins = chain::find_coins(&m, key.pkh).await?;
        let total: u64 = coins.iter().map(|c| c.1).sum();
        log_info!("operator coins", "count" => coins.len(), "total" => total, "address" => encode_p2pkh_cashaddr(&key.pkh, prefix));
        let need = reserve + 2_000;
        let mut funding = coins.iter().find(|(op, v, _)| op.vout == 0 && *v >= need).map(|(op, v, _)| (*op, *v));
        if prepare_only {
            if let Some((op, v)) = funding {
                println!("category (future) {}  (existing vout-0 coin, {v} sats)", hex::encode(op.txid_be));
                return Ok(());
            }
        }
        if funding.is_none() {
            // make a vout-0 coin with a self-spend of the largest coin(s)
            let mut picked = Vec::new();
            let mut acc = 0u64;
            for (op, v, _) in &coins {
                picked.push((*op, *v));
                acc += v;
                if acc >= need + 1_000 {
                    break;
                }
            }
            if acc < need + 1_000 {
                bail!("operator key holds {acc} sats; genesis needs at least {}", need + 1_000);
            }
            let split = self_spend(&key, &picked, acc)?;
            if dry_run {
                println!("dry-run: would broadcast a {}-byte self-spend to create a vout-0 coin", split.1.len());
            } else {
                let txid = chain::broadcast(&m, split.1.clone()).await.context("broadcast self-spend")?;
                log_info!("self-spend posted", "txid" => &txid);
                funding = Some((TxOutpoint { txid_be: split.0, vout: 0 }, split.2));
                if prepare_only {
                    println!("category (future) {txid}");
                    println!("init the notaries with this category, then run genesis --reserve {reserve}");
                    return Ok(());
                }
            }
        }
        let (op, value) = funding.ok_or_else(|| anyhow!("no funding outpoint (dry run)"))?;
        let input = P2pkhInput { outpoint: op, value, private_key: key.private_key, public_key: key.public_key, pkh: key.pkh };
        let initial_seq = current_minute().saturating_sub(1);
        let built = build_genesis(&input, &th, reserve, initial_seq)?;
        m.category = hex::encode(op.txid_be);
        m.genesis_txid = hex::encode(built.txid);
        println!("category     {}", m.category);
        println!("genesis txid {}", m.genesis_txid);
        println!("head address {}", encode_p2sh32_cashaddr(&lock, prefix));
        println!("table hash   {}", m.table_hash);
        println!("reserve      {reserve} sats; tx {} B fee {} sats", built.size, built.fee);
        if dry_run {
            println!("dry-run: nothing broadcast, manifest not written");
            return Ok(());
        }
        let txid = chain::broadcast(&m, built.raw.clone()).await.context("broadcast genesis")?;
        if txid != m.genesis_txid {
            bail!("node returned txid {txid}, expected {}", m.genesis_txid);
        }
        std::fs::write(&manifest_path, serde_json::to_string_pretty(&m)?)?;
        log_info!("genesis posted", "txid" => &txid, "manifest" => manifest_path.display().to_string());
        Ok::<(), anyhow::Error>(())
    })
}

/// Spend `coins` into one output (index 0) back to the operator key. Returns (txid, raw, value).
fn self_spend(key: &ticker_core::keyfile::KeyMaterial, coins: &[(TxOutpoint, u64)], total: u64) -> Result<([u8; 32], Vec<u8>, u64)> {
    let lock = p2pkh_locking_script(&key.pkh).to_vec();
    let inputs: Vec<Input> = coins
        .iter()
        .map(|(op, _)| {
            let mut placeholder = Vec::new();
            push_data(&mut placeholder, &[0u8; 65]);
            push_data(&mut placeholder, &key.public_key);
            Input { prev: *op, unlock_script: placeholder, sequence: SEQUENCE_FINAL }
        })
        .collect();
    let mut tx = Tx::new(inputs, vec![Output { value: 0, locking_script: lock.clone(), token: None }]);
    let fee = encode_tx(&tx).len() as u64 + 1;
    tx.outputs[0].value = total - fee;
    let sources: Vec<SpentOutput> = coins.iter().map(|(_, v)| SpentOutput { value: *v, locking_script: lock.clone(), token: None }).collect();
    for i in 0..tx.inputs.len() {
        let digest = sighash_digest(&tx, i, &lock, &sources, SIGHASH_ALL_UTXOS_FORKID);
        let sig = schnorr_sign(&key.private_key, &digest)?;
        let mut sig_ht = sig.to_vec();
        sig_ht.push(SIGHASH_ALL_UTXOS_FORKID);
        let mut unlock = Vec::new();
        push_data(&mut unlock, &sig_ht);
        push_data(&mut unlock, &key.public_key);
        tx.inputs[i].unlock_script = unlock;
    }
    let raw = encode_tx(&tx);
    let txid = ticker_core::tx::encode::txid_be(&raw);
    Ok((txid, raw, total - fee))
}
