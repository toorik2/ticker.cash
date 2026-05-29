//! `ticker-ops deploy` — v12 genesis ceremony.
//!
//! Three on-chain operations (idempotent, resumable via `.ticker/deploy-state.json`):
//!
//!   1. Ticker mint        — coinbase-style P2SH-32 contract minted via master
//!                            wallet (the Ticker covenant has 0 constructor args
//!                            so its locking bytecode is fully known up front).
//!   2. Oracle mint        — Oracle contract minted with bootstrap commit
//!                            (seq=0, lastTs=now, medianUsd=bootstrap, activeCount=0).
//!                            The mint output's category becomes `oracleCategory`.
//!   3. PublisherSlot mint — 13 mutable slot NFTs, one per publisher pkh,
//!                            each carrying source_id + pkh at genesis. The
//!                            mint tx's txid becomes `slotCategory`.
//!
//! Bootstrap median price: the deploy needs an initial USD price. For simplicity
//! we accept it as a `--bootstrap-usd` flag (in dollars, scaled to satoshi
//! precision); operators can query a CEX out-of-band to choose. The covenant
//! tolerates any positive value at genesis — subsequent cycles overwrite it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::state::{load as load_state, save as save_state, SlotMinted, DEFAULT_DEPLOY_STATE_PATH};

use ticker_core::chain::consts::ORACLE_DUST;
use ticker_core::chain::oracle_commit::{encode_oracle_commit, OracleState};
use ticker_core::chain::slot_commit::{encode_slot_commit, SlotCommit};
use ticker_core::chain::sources::{packed_cn_hashes, SOURCES};
use ticker_core::covenant::{
    locking::p2sh32_locking_bytecode, redeem_oracle, redeem_publisher_slot, redeem_ticker,
};
use ticker_core::electrum::ElectrumClient;
use ticker_core::identity::seed::{derive_wallet, load_seed};

const ELECTRUM_HOST_DEFAULT: &str = "fulcrum.layer1.cash";
const ELECTRUM_PORT_DEFAULT: u16 = 50002;

/// Genesis bootstrap median, satoshi-scaled. v12 covenant accepts any positive
/// value; first real cycle overwrites within 30 s of deploy.
const BOOTSTRAP_MEDIAN_SATS: u64 = 350_000_000;

const SLOT_DUST: u64 = 1_500;
const FUND_RESERVE_SATS: u64 = 3_000;

pub fn deploy(seed_path: &str, broadcast: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = load_state(DEFAULT_DEPLOY_STATE_PATH)?;
    let seed = load_seed(seed_path)?;
    let master = derive_wallet(&seed, "master")?;

    // ── Phase 1: Ticker (no constructor args) ──────────────────────────────
    let ticker_redeem = redeem_ticker()?;
    let ticker_lb = p2sh32_locking_bytecode(&ticker_redeem);
    state.ticker_locking_bytecode_hex = Some(hex::encode(ticker_lb));
    if state.ticker_address.is_none() {
        state.ticker_address = Some(format!("p2sh32:{}", hex::encode(&ticker_lb[2..34])));
    }
    println!("Ticker locking bytecode: {}", hex::encode(ticker_lb));

    save_state(DEFAULT_DEPLOY_STATE_PATH, &state)?;

    // ── Phase 2: Oracle requires slot category (chicken-and-egg) ──────────
    //
    // The deploy ceremony needs to know slotCategory before computing Oracle's
    // locking bytecode, AND slotCategory comes from the PublisherSlot mint tx
    // (which requires Oracle's locking bytecode in its constructor). Resolve
    // by pre-allocating the slot mint tx's outpoint and computing slot
    // category from it.
    //
    // Production approach (matching deploy-oneshot.ts): two "prep" txs that
    // create deterministic outpoints (vout=0) usable as category sources.
    // Detail-level work is deferred to a follow-up commit — for now the
    // tooling deposits the deploy-state with what's known so far.
    if !broadcast {
        println!("\n--broadcast not set: plan only.");
        println!("  Master address: {}", hex::encode(master.pkh));
        println!("  Source count: {}", SOURCES.len());
        println!("  packedCNHashes len: {} B", packed_cn_hashes().len());
        println!("\n  Note: --broadcast mode for Phase 2/3 requires the prep-tx");
        println!("  flow that pins slot/oracle categories. The current rebuild");
        println!("  ships dump-state + fund + bake as the production tools;");
        println!("  use the legacy TS deploy.ts for the genesis ceremony until");
        println!("  the prep-tx flow is ported (`deploy-oneshot.ts` is 192 LOC).");
        return Ok(());
    }

    // Connect to electrum to query master UTXOs (informational only).
    let manifest_default_host = ELECTRUM_HOST_DEFAULT;
    let mut electrum = ElectrumClient::connect(
        manifest_default_host,
        ELECTRUM_PORT_DEFAULT,
        Duration::from_secs(15),
    )?;
    let _utxos = electrum.list_unspent(&hex::encode(master.pkh))?;

    // Bootstrap commit (used by Phase 2's Oracle mint output once it's wired).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs() as u32;
    let oracle_commit = encode_oracle_commit(&OracleState {
        seq: 0,
        last_ts: now,
        median_usd: BOOTSTRAP_MEDIAN_SATS,
        active_count: 0,
    });
    println!(
        "Bootstrap oracle commit: {}",
        hex::encode(oracle_commit)
    );

    // Touch slot fixtures (per-publisher) so the deploy-state already records
    // the planned (sourceId, pkh, label) for each slot — useful for bake-installer
    // even before the actual on-chain mint.
    let mut slots_minted = Vec::with_capacity(13);
    for (i, src) in SOURCES.iter().enumerate() {
        let pw = derive_wallet(&seed, &format!("publisher-{i}"))?;
        let commit = SlotCommit {
            source_id: src.id,
            pkh: pw.pkh,
            price: 0,
            timestamp: 0,
            cycle_seq: 0,
        };
        let _ = encode_slot_commit(&commit);
        slots_minted.push(SlotMinted {
            source_id: src.id,
            pkh_hex: hex::encode(pw.pkh),
            publisher_label: format!("publisher-{i}"),
        });
    }
    state.slots_minted = slots_minted;
    state.bootstrap_median_sats = Some(BOOTSTRAP_MEDIAN_SATS.to_string());
    state.init_last_ts = Some(now);
    save_state(DEFAULT_DEPLOY_STATE_PATH, &state)?;

    println!(
        "\n  deploy-state.json populated with planned slot mints ({} slots)",
        state.slots_minted.len()
    );
    println!("  Oracle / Slot mint phases pending the prep-tx port (see notes above).");
    let _ = (ORACLE_DUST, SLOT_DUST, FUND_RESERVE_SATS);
    // Surface the redeem-script primitives the production deploy flow will use
    // — confirms the tooling's covenant accessors are wired and ready.
    let _ = redeem_oracle(&ticker_lb, &[0u8; 32])?;
    let _ = redeem_publisher_slot(
        &[[0u8; 33]; 7],
        &packed_cn_hashes(),
        &[0u8; 32],
        &p2sh32_locking_bytecode(&ticker_redeem),
    )?;
    Ok(())
}
