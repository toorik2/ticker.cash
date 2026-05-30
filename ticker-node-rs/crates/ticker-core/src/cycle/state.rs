//! `CycleState` enum + configuration + supporting data types.
//!
//! Variants correspond to natural restart points. If the daemon crashes anywhere,
//! the next process boot re-enters via [`CycleState::Idle`] and re-derives intent
//! from on-chain truth — see [`super::env::Env`] + the warm-start logic in the
//! orchestrator.

use crate::chain::oracle_commit::OracleState;
use crate::chain::slot_commit::SlotCommit;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 32-byte transaction id (big-endian display order).
pub type Txid = [u8; 32];

/// Captured chain truth for the cycle in progress.
#[derive(Debug, Clone)]
pub struct CycleSnapshot {
    /// Oracle UTXO outpoint + raw commitment.
    pub oracle_txid_be: Txid,
    pub oracle_vout: u32,
    pub oracle_satoshis: u64,
    pub oracle_commit: OracleState,
    /// `oracle_commit.seq + 1` — the value our slot rewrite must adopt.
    pub new_seq: u32,
    /// Snapshot of `oracle_commit.last_ts` — same as `oracle_commit.last_ts`,
    /// pinned in case future refactors decouple them.
    pub prev_ts: u32,
    /// Our PublisherSlot UTXO.
    pub mine_slot_txid_be: Txid,
    pub mine_slot_vout: u32,
    pub mine_slot_satoshis: u64,
    pub mine_slot_commit: SlotCommit,
    /// Raw 39-byte slot commitment as it sits on chain RIGHT NOW (before
    /// this cycle's attest rewrites it). Needed by the CashTokens sighash.
    pub mine_slot_commitment_raw: [u8; 39],
}

impl CycleSnapshot {
    /// Did our slot already advance to this cycleSeq (skip to quorum wait)?
    pub fn already_attested(&self) -> bool {
        self.mine_slot_commit.cycle_seq == self.new_seq
    }
}

/// Cycle state — where in the 4-phase loop we are.
#[derive(Debug, Clone)]
pub enum CycleState {
    Idle,
    Snapshotted {
        snap: CycleSnapshot,
    },
    /// We broadcast our `slot.attest` successfully and recorded the txid.
    Attested {
        snap: CycleSnapshot,
        attest_txid: Txid,
    },
    /// Our slot was already at `new_seq` on boot — skip phase 2.
    AlreadyAttested {
        snap: CycleSnapshot,
    },
    /// ≥ THR_FLOOR slots at `new_seq` have been observed, sorted by pkh LE-numeric.
    QuorumReached {
        snap: CycleSnapshot,
        /// Slots after dedupe + sort. Ready to feed `tx::update::build_oracle_update_tx`.
        cycle_slot_commits: Vec<SlotCommit>,
        /// Slot UTXO outpoints (parallel to commits).
        cycle_slot_utxos: Vec<(Txid, u32, u64)>,
    },
    /// Phase 4 done — cycle resets to `Idle` for the next iteration.
    Updated {
        new_seq: u32,
        update_txid: Option<Txid>,
    },
}

impl CycleState {
    pub fn name(&self) -> &'static str {
        match self {
            CycleState::Idle => "Idle",
            CycleState::Snapshotted { .. } => "Snapshotted",
            CycleState::Attested { .. } => "Attested",
            CycleState::AlreadyAttested { .. } => "AlreadyAttested",
            CycleState::QuorumReached { .. } => "QuorumReached",
            CycleState::Updated { .. } => "Updated",
        }
    }
}

/// Persisted advisory state — written to `.ticker/publisher-state-{slot}.json`.
/// Same field names as the TS daemon for migration compatibility.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublisherState {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lastCycleSeq")]
    pub last_cycle_seq: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lastAttestTxid")]
    pub last_attest_txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "lastUpdateTxid")]
    pub last_update_txid: Option<String>,
}

/// Per-cycle configuration — built once at startup from the manifest + CLI flags.
#[derive(Debug, Clone)]
pub struct CycleConfig {
    pub slot: u8,
    pub my_pkh: [u8; 20],
    pub publisher_privkey: [u8; 32],
    pub publisher_pubkey: [u8; 33],
    /// Source assigned to this publisher slot (from [`chain::sources::SOURCES`]).
    pub source_id: u16,
    /// Notary URLs (one per notary slot). Cycle counter % notary_urls.len() picks.
    pub notary_urls: Vec<String>,
    /// Wire-LE category bytes for Oracle (reverse of display txid).
    pub oracle_category_wire_le: [u8; 32],
    /// Wire-LE category bytes for PublisherSlot.
    pub slot_category_wire_le: [u8; 32],
    /// Oracle / Slot / Ticker redeem scripts (built once at startup).
    pub oracle_redeem_script: Vec<u8>,
    pub slot_redeem_script: Vec<u8>,
    pub ticker_redeem_script: Vec<u8>,
    /// Funder/publisher CashAddr — used to look up funder UTXOs.
    pub publisher_address: String,
    /// Oracle / Slot CashAddrs — used to look up the respective UTXO sets.
    pub oracle_address: String,
    pub slot_address: String,
    /// Pre-computed reversed-SHA-256 scripthashes for the Electrum
    /// `blockchain.scripthash.listunspent` method (lowercase hex).
    pub oracle_scripthash_hex: String,
    pub slot_scripthash_hex: String,
    pub publisher_scripthash_hex: String,
    /// 64-hex Oracle category (display order, big-endian).
    pub oracle_category_be_hex: String,
    /// 64-hex Slot category (display order, big-endian).
    pub slot_category_be_hex: String,
    /// Poll interval inside `QuorumReached` wait + after soft-error sleep. Default 3 s.
    pub poll_interval: Duration,
    /// Quorum wait timeout. Default 25 s.
    pub quorum_wait: Duration,
}
