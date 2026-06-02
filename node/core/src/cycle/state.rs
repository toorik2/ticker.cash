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
    /// Our PublisherSlot UTXO.
    pub mine_slot_txid_be: Txid,
    pub mine_slot_vout: u32,
    pub mine_slot_satoshis: u64,
    pub mine_slot_commit: SlotCommit,
    /// Raw 16-byte slot commitment as it sits on chain RIGHT NOW (before
    /// this cycle's attest rewrites it). Needed by the CashTokens sighash.
    pub mine_slot_commitment_raw: [u8; 16],
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
        /// Slot UTXO outpoints (parallel to commits): (txid_be, vout, satoshis, pkh).
        /// v22: pkh added as 4th tuple element since SlotCommit no longer carries it.
        cycle_slot_utxos: Vec<(Txid, u32, u64, [u8; 20])>,
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
    /// v17: hash160(canonical_cn) for THIS daemon's source. Used as the
    /// source-identifying field in the publisher signing digest (was the
    /// `source_id` field in v16).
    pub my_cn_hash20: [u8; 20],
    pub publisher_privkey: [u8; 32],
    pub publisher_pubkey: [u8; 33],
    /// Source assigned to this publisher slot (from [`chain::sources::SOURCES`]).
    pub source_id: u16,
    /// Wire-LE category bytes for Oracle (reverse of display txid).
    pub oracle_category_wire_le: [u8; 32],
    /// Wire-LE category bytes for PublisherSlot.
    pub slot_category_wire_le: [u8; 32],
    /// Oracle / Slot / Ticker redeem scripts (built once at startup).
    pub oracle_redeem_script: Vec<u8>,
    pub slot_redeem_script: Vec<u8>,
    pub ticker_redeem_script: Vec<u8>,
    /// Pre-computed reversed-SHA-256 scripthashes for the Electrum
    /// `blockchain.scripthash.listunspent` method (lowercase hex).
    pub oracle_scripthash_hex: String,
    /// THIS publisher's slot scripthash (used for subscriptions + identity).
    pub slot_scripthash_hex: String,
    /// v16: all 13 slot scripthashes (in source-id order) for quorum-aggregation
    /// queries. v15 used a single shared slot scripthash because all 13 NFTs
    /// lived at one address; v16 has per-source addresses so each slot has its
    /// own scripthash. Quorum aggregation must scan all 13.
    pub all_slot_scripthashes_hex: Vec<String>,
    /// v17: pkh→cnHash mapping for all 13 publisher slots. Used by Oracle.update
    /// to derive each consumed slot's redeem (the cnHash that's baked into the
    /// per-source redeem) from the slot commit's pkh field. v16 had sourceId
    /// in the commit; v17 dropped it, so we look up by pkh instead.
    pub all_pkh_to_cn_hash: Vec<([u8; 20], [u8; 20])>,
    /// v22: per-source pkhs in source-id order (parallel to all_slot_scripthashes_hex).
    /// Used to populate SlotInfo.pkh from the scripthash query result, since
    /// commit no longer carries pkh. Also used as the address→pkh lookup.
    pub all_slot_pkhs: Vec<[u8; 20]>,
    /// v22: per-source locking bytecodes (specialized P2S bodies) in source-id order.
    /// Each LB IS the slot's compiled body bytes (no P2SH-32 wrapper).
    /// Used as the slot input's covered-script for sighash computation and as
    /// the slot output's locking_script.
    pub all_slot_lockings: Vec<Vec<u8>>,
    /// v22: pkh → slot locking-bytecode lookup table built once at startup.
    /// Used by Oracle.update tx builder to construct per-slot outputs + sighashes.
    pub all_pkh_to_locking: Vec<([u8; 20], Vec<u8>)>,
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
