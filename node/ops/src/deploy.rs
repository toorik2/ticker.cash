//! `ticker-ops deploy` — v15 genesis ceremony.
//!
//! Mints the on-chain v15 deployment:
//!
//!   1. Computes Ticker P2SH-32 (no constructor args).
//!   2. Picks 2 master UTXOs (defaults to label "master" derived from seed.hex).
//!   3. Pre-computes Oracle + Slot CashTokens categories from those master
//!      UTXOs' txids — CHIP-2022-02: a new token category may be created in a
//!      tx whose input[0] consumes the category's "genesis outpoint", and the
//!      category id equals that input's previous-txid.
//!   4. Builds Oracle covenant redeem + P2SH-32 locking bytecode.
//!   5. Builds PublisherSlot covenant redeem + P2SH-32 locking bytecode
//!      (depends on Oracle's P2SH).
//!   6. Builds + broadcasts Oracle genesis tx: spends master UTXO #1 at input[0],
//!      emits 1 Oracle minting NFT (capability 0x02) at Oracle P2SH-32 with
//!      initial commit `0x65 | seq=0 | ts=0 | medianUsd=0 | activeCount=0`.
//!   7. Builds + broadcasts Slot genesis tx: spends master UTXO #2 at input[0],
//!      emits 13 mutable slot NFTs (capability 0x01) at Slot P2SH-32, one per
//!      publisher pkh, with initial commit `0x75 | sourceId(2) | pkh(20) | 0x00..(16)`.
//!   8. Writes the resulting addresses + txids to deploy-state.json.

use std::fs;
use std::time::Duration;

use ticker_core::chain::sources::{source_cn_hash, SOURCES};
use ticker_core::covenant::{
    locking::p2sh32_locking_bytecode, redeem_oracle, redeem_publisher_slot, redeem_ticker,
};
use ticker_core::crypto::{double_sha256, sign_ecdsa};
use ticker_core::electrum::{types::Utxo, ElectrumClient};
use ticker_core::identity::manifest::Network;
use ticker_core::identity::seed::{derive_wallet, load_seed};
use ticker_core::tx::cashaddr::{encode_p2sh32_cashaddr, encode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::encode::{
    encode_tx, Input, Output, TokenPrefix, Tx, TxOutpoint, DEFAULT_SEQUENCE, MINTING_CAPABILITY,
    MUTABLE_CAPABILITY,
};
use ticker_core::tx::script::{p2pkh_locking_script, push_data};
use ticker_core::tx::sighash::{p2pkh_sighash_preimage, SIGHASH_BIT};

use crate::state::DeployState;

const ELECTRUM_TIMEOUT_SEC: u64 = 30;
const ORACLE_DUST: u64 = 2_000;
const SLOT_DUST: u64 = 1_500;
const PUBLISHER_COUNT: usize = 13;

#[allow(clippy::too_many_arguments)]
pub fn deploy(
    seed_path: &str,
    state_path: &str,
    network: &str,
    electrum_host: &str,
    electrum_port: u16,
    broadcast: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if network != "chipnet" && network != "mainnet" {
        return Err("--network must be 'chipnet' or 'mainnet'".into());
    }
    let net = match network {
        "chipnet" => Network::Chipnet,
        _ => Network::Mainnet,
    };
    let prefix = match net {
        Network::Chipnet => AddressPrefix::Chipnet,
        Network::Mainnet => AddressPrefix::Mainnet,
    };

    // ── 1. Derive master + publisher identities ──────────────────────────
    let seed = load_seed(seed_path)?;
    let master = derive_wallet(&seed, "master")?;
    let master_addr = encode_p2pkh_cashaddr(&master.pkh, prefix);
    let publisher_pkhs: Vec<[u8; 20]> = (0..PUBLISHER_COUNT)
        .map(|i| derive_wallet(&seed, &format!("publisher-{i}")).map(|w| w.pkh))
        .collect::<Result<_, _>>()?;
    println!("master address: {master_addr}");

    // ── 2. Ticker P2SH-32 (no constructor args, deterministic) ───────────
    let ticker_redeem = redeem_ticker()?;
    let ticker_lb: [u8; 35] = p2sh32_locking_bytecode(&ticker_redeem);
    let ticker_addr = encode_p2sh32_cashaddr(&ticker_lb, prefix);
    let ticker_lb_hex = hex::encode(ticker_lb);
    println!("Ticker:");
    println!("  P2SH-32 LB: {ticker_lb_hex}");
    println!("  address:    {ticker_addr}");

    // ── 3. Pull master UTXOs from Fulcrum ────────────────────────────────
    let mut electrum = ElectrumClient::connect(
        electrum_host,
        electrum_port,
        Duration::from_secs(ELECTRUM_TIMEOUT_SEC),
    )?;
    let utxos = electrum.list_unspent(&master_addr)?;
    // CHIP-2022-02 §3.1: a category genesis input must be at vin[0] of the
    // tx AND its prev_out.n must be 0. Otherwise the new-token output is
    // rejected with `bad-txns-token-invalid-category`. Filter for vout=0
    // UTXOs only — empirically caught a v14 genesis attempt and re-surfaced
    // during v15 prep until this filter was added.
    let mut non_token: Vec<Utxo> = utxos
        .into_iter()
        .filter(|u| u.token_data.is_none() && u.tx_pos == 0)
        .collect();
    if non_token.len() < 2 {
        return Err(format!(
            "need ≥ 2 non-token master UTXOs at vout=0 for genesis \
             (CHIP-2022-02 category genesis input); have {}. \
             Bounce master→master twice to create fresh vout=0 outpoints.",
            non_token.len()
        )
        .into());
    }
    // The Oracle and Slot categories MUST be distinct, so the two genesis
    // inputs must come from different parent txs (different tx_hash values).
    // Pick the largest pair satisfying that constraint.
    non_token.sort_by(|a, b| b.value.cmp(&a.value));
    let oracle_genesis = non_token[0].clone();
    let slot_genesis = non_token
        .iter()
        .skip(1)
        .find(|u| u.tx_hash != oracle_genesis.tx_hash)
        .cloned()
        .ok_or_else(|| {
            "all non-token master UTXOs at vout=0 share the same parent txid; \
             bounce master→master once more to create a fresh distinct-parent vout=0 UTXO"
        })?;
    println!(
        "Oracle genesis input: {}:{} ({} sats)",
        oracle_genesis.tx_hash, oracle_genesis.tx_pos, oracle_genesis.value
    );
    println!(
        "Slot genesis input:   {}:{} ({} sats)",
        slot_genesis.tx_hash, slot_genesis.tx_pos, slot_genesis.value
    );

    // ── 4. Pre-compute Oracle + Slot categories ──────────────────────────
    // Per CHIP-2022-02: a tx that consumes outpoint (T, V) at input[0] may
    // create new token category id = T. The category id is the previous
    // txid (display order, BE). The wire representation in token prefix is
    // little-endian (the txid bytes reversed).
    let oracle_cat_be_hex = oracle_genesis.tx_hash.clone();
    let slot_cat_be_hex = slot_genesis.tx_hash.clone();
    let mut oracle_cat_le: [u8; 32] = hex::decode(&oracle_cat_be_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| "oracle category not 32 bytes")?;
    oracle_cat_le.reverse();
    let mut slot_cat_le: [u8; 32] = hex::decode(&slot_cat_be_hex)?
        .as_slice()
        .try_into()
        .map_err(|_| "slot category not 32 bytes")?;
    slot_cat_le.reverse();
    println!("Oracle category (display BE): {oracle_cat_be_hex}");
    println!("Slot   category (display BE): {slot_cat_be_hex}");

    // ── 5. Build Oracle redeem script + P2SH-32 LB ───────────────────────
    let oracle_redeem = redeem_oracle(&ticker_lb, &slot_cat_le)?;
    let oracle_lb: [u8; 35] = p2sh32_locking_bytecode(&oracle_redeem);
    let oracle_addr = encode_p2sh32_cashaddr(&oracle_lb, prefix);
    let oracle_lb_hex = hex::encode(oracle_lb);
    println!("Oracle:");
    println!("  redeem:     {} bytes", oracle_redeem.len());
    println!("  P2SH-32 LB: {oracle_lb_hex}");
    println!("  address:    {oracle_addr}");

    // ── 6. Build Slot redeems (v16 per-source) + P2SH-32 LBs ────────────
    // v16: each of the 13 sources compiles to a distinct redeem (its own
    // cnHash baked in) → distinct P2SH-32 address. v15 had one shared 625 B
    // redeem; v16 has 13 distinct 262 B redeems. See /tmp/slot-experiments/
    // v16-design.md for the rationale.
    struct PerSlotDeploy {
        source_id: u16,
        cn_hash: [u8; 20],
        lb: [u8; 35],
        address: String,
    }
    let mut per_slot: Vec<PerSlotDeploy> = Vec::with_capacity(PUBLISHER_COUNT);
    // v18: hash160(oracleCat) is the constructor arg.
    let oracle_cat_hash = ticker_core::crypto::hash160(&oracle_cat_le);
    println!("PublisherSlot (v18 per-source):");
    for s in SOURCES.iter() {
        let cn_hash = source_cn_hash(s);
        let redeem = redeem_publisher_slot(&cn_hash, &oracle_cat_hash)?;
        let lb: [u8; 35] = p2sh32_locking_bytecode(&redeem);
        let address = encode_p2sh32_cashaddr(&lb, prefix);
        println!(
            "  [{:>2}] {:>20} redeem:{}B  addr:{}",
            s.id,
            s.name,
            redeem.len(),
            address
        );
        per_slot.push(PerSlotDeploy {
            source_id: s.id,
            cn_hash,
            lb,
            address,
        });
    }
    // Sanity: all 13 addresses must be distinct.
    let mut sorted_addrs: Vec<&String> = per_slot.iter().map(|p| &p.address).collect();
    sorted_addrs.sort();
    sorted_addrs.dedup();
    if sorted_addrs.len() != PUBLISHER_COUNT {
        return Err(format!(
            "v16 invariant violation: 13 per-source slot addresses collapsed to {} \
             distinct values — check that SOURCES has 13 unique canonical_cn values",
            sorted_addrs.len()
        )
        .into());
    }

    // ── 7. Build Oracle genesis tx ───────────────────────────────────────
    // v20: 18-byte commit (no version byte). seq (4), lastTs (4), medianUsd
    // (8), activeCount (2) — all zeros at genesis.
    let oracle_initial_commit: [u8; 18] = [0u8; 18];
    let oracle_tx = build_p2pkh_to_token_tx(
        &oracle_genesis,
        &master.private_key,
        &master.public_key,
        &master.pkh,
        vec![Output {
            value: ORACLE_DUST,
            locking_script: oracle_lb.to_vec(),
            token: Some(TokenPrefix {
                category_le: oracle_cat_le,
                capability: MINTING_CAPABILITY,
                commitment: oracle_initial_commit.to_vec(),
                amount: 0,
            }),
        }],
    )?;
    println!("Oracle genesis tx: {} bytes", oracle_tx.len());

    // ── 8. Build Slot genesis tx (v16: each NFT to its OWN P2SH-32) ──────
    let mut slot_outputs = Vec::with_capacity(PUBLISHER_COUNT);
    for (slot_idx, pkh) in publisher_pkhs.iter().enumerate() {
        let pd = &per_slot[slot_idx];
        let commit = build_initial_slot_commit(pd.source_id, pkh);
        slot_outputs.push(Output {
            value: SLOT_DUST,
            locking_script: pd.lb.to_vec(),
            token: Some(TokenPrefix {
                category_le: slot_cat_le,
                capability: MUTABLE_CAPABILITY,
                commitment: commit.to_vec(),
                amount: 0,
            }),
        });
    }
    let slot_tx = build_p2pkh_to_token_tx(
        &slot_genesis,
        &master.private_key,
        &master.public_key,
        &master.pkh,
        slot_outputs,
    )?;
    println!("Slot genesis tx: {} bytes", slot_tx.len());

    // ── 9. Broadcast (or dry-run) ────────────────────────────────────────
    let oracle_txid = if broadcast {
        let txid = electrum.broadcast_raw(&oracle_tx)?;
        println!("Oracle genesis broadcast ok: {txid}");
        Some(txid)
    } else {
        println!("Oracle tx hex:");
        println!("{}", hex::encode(&oracle_tx));
        None
    };
    let slot_txid = if broadcast {
        let txid = electrum.broadcast_raw(&slot_tx)?;
        println!("Slot genesis broadcast ok: {txid}");
        Some(txid)
    } else {
        println!("Slot tx hex:");
        println!("{}", hex::encode(&slot_tx));
        None
    };

    // ── 10. Persist deploy-state.json (v16 per-source slot fields) ───────
    let state = DeployState {
        ticker_address: Some(ticker_addr.clone()),
        ticker_locking_bytecode_hex: Some(ticker_lb_hex.clone()),
        oracle_address: Some(oracle_addr.clone()),
        oracle_locking_bytecode_hex: Some(oracle_lb_hex.clone()),
        oracle_category: Some(oracle_cat_be_hex.clone()),
        oracle_mint_txid: oracle_txid,
        oracle_prep_txid: None,
        // v16: singular slot_* fields are deprecated. v15 readers will see None.
        // Per-slot data lives in slots_minted[] below.
        slot_address: None,
        slot_locking_bytecode_hex: None,
        slot_category: Some(slot_cat_be_hex.clone()),
        slot_mint_txid: slot_txid,
        slot_prep_txid: None,
        slots_minted: publisher_pkhs
            .iter()
            .enumerate()
            .map(|(i, pkh)| {
                let pd = &per_slot[i];
                crate::state::SlotMinted {
                    source_id: pd.source_id,
                    pkh_hex: hex::encode(pkh),
                    publisher_label: format!("publisher-{i}"),
                    address: Some(pd.address.clone()),
                    locking_bytecode_hex: Some(hex::encode(pd.lb)),
                    cn_hash_hex: Some(hex::encode(pd.cn_hash)),
                }
            })
            .collect(),
        init_last_ts: None,
        bootstrap_median_sats: None,
    };
    if let Some(parent) = std::path::Path::new(state_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(state_path, serde_json::to_vec_pretty(&state)?)?;
    println!("deploy-state.json written to {state_path}");

    if !broadcast {
        println!("\n(dry-run — pass --broadcast to send both genesis txs)");
    }
    Ok(())
}

/// Build the 36-byte v19 initial slot commit: `pkh(20) | 0x00..(16)`.
/// (v18 had a `0x75` version byte at offset 0; v19 dropped it as redundant.)
fn build_initial_slot_commit(_source_id: u16, pkh: &[u8; 20]) -> [u8; 36] {
    let mut c = [0u8; 36];
    c[0..20].copy_from_slice(pkh);
    // price (8), timestamp (4), cycleSeq (4) — all zeros at genesis
    c
}

/// Build + sign a tx that spends ONE P2PKH UTXO (at input[0]) and emits
/// the given outputs plus optional change back to the signer.
///
/// `outputs` may include CashTokens-bearing outputs — the encoder handles the
/// 0xef prefix. The input itself is plain P2PKH (no token data), so classic
/// BIP-143 sighash (0x41 = SIGHASH_ALL | FORKID) suffices for signing.
///
/// The genesis input MUST be at input index 0 (CHIP-2022-02 token category
/// derivation rule).
fn build_p2pkh_to_token_tx(
    genesis_utxo: &Utxo,
    privkey: &[u8; 32],
    pubkey: &[u8; 33],
    pkh: &[u8; 20],
    mut outputs: Vec<Output>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Reserve a fixed fee buffer; for genesis txs (always ≤ 2 KB) at 1 sat/byte
    // this is comfortable.
    const GENESIS_FEE_BUFFER: u64 = 3_000;

    let token_dust: u64 = outputs.iter().map(|o| o.value).sum();
    if genesis_utxo.value < token_dust + GENESIS_FEE_BUFFER {
        return Err(format!(
            "genesis UTXO {} sats can't cover {} token dust + {} fee buffer",
            genesis_utxo.value, token_dust, GENESIS_FEE_BUFFER
        )
        .into());
    }

    // Append a P2PKH change output back to master.
    let change = genesis_utxo.value - token_dust - GENESIS_FEE_BUFFER;
    if change >= 546 {
        outputs.push(Output {
            value: change,
            locking_script: p2pkh_locking_script(pkh).to_vec(),
            token: None,
        });
    }

    // Build the input.
    let mut txid_be = [0u8; 32];
    txid_be.copy_from_slice(&hex::decode(&genesis_utxo.tx_hash)?);
    let inputs = vec![Input {
        prev: TxOutpoint {
            txid_be,
            vout: genesis_utxo.tx_pos,
        },
        unlock_script: Vec::new(),
        sequence: DEFAULT_SEQUENCE,
    }];
    let mut tx = Tx::new(inputs, outputs);

    // Sign input[0] with classic BIP-143 sighash. The previous output's
    // locking script is plain P2PKH = OP_DUP OP_HASH160 <20> <pkh> OP_EQUALVERIFY OP_CHECKSIG.
    let locking = p2pkh_locking_script(pkh).to_vec();
    let preimage = p2pkh_sighash_preimage(&tx, 0, &locking, genesis_utxo.value);
    let digest = double_sha256(&preimage);
    let sig = sign_ecdsa(privkey, &digest)?;
    let mut sig_with_sighash = Vec::with_capacity(sig.len() + 1);
    sig_with_sighash.extend_from_slice(&sig);
    sig_with_sighash.push(SIGHASH_BIT);
    let mut unlock = Vec::with_capacity(100);
    push_data(&mut unlock, &sig_with_sighash);
    push_data(&mut unlock, pubkey);
    tx.inputs[0].unlock_script = unlock;

    let raw = encode_tx(&tx);

    // Sanity check: compute our own txid by double-sha256 of the encoded tx,
    // reverse to display order, and log it — useful for cross-checking that
    // Fulcrum's broadcast response matches what we expect.
    let mut our_txid = double_sha256(&raw);
    our_txid.reverse();
    println!(
        "  computed txid: {} (input value {})",
        hex::encode(our_txid),
        genesis_utxo.value
    );
    Ok(raw)
}
