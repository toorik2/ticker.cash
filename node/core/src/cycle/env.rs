//! `Env` trait — abstracts every I/O point the cycle's `step` function touches.
//!
//! Real impl is wired up in the binary (Electrum + price fetcher + clock + file I/O).
//! Tests provide a `MockEnv` impl that returns canned UTXOs / responses without
//! talking to a network.

use std::time::Duration;

use crate::chain::oracle_commit::OracleState;
use crate::chain::slot_commit::SlotCommit;
use crate::cycle::error::CycleError;
use crate::cycle::state::{CycleConfig, PublisherState, Txid};

/// Oracle UTXO returned by Fulcrum.
#[derive(Debug, Clone)]
pub struct OracleInfo {
    pub txid_be: Txid,
    pub vout: u32,
    pub satoshis: u64,
    pub commit: OracleState,
}

/// PublisherSlot UTXO returned by Fulcrum.
#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub txid_be: Txid,
    pub vout: u32,
    pub satoshis: u64,
    pub commit: SlotCommit,
    /// Raw 36-byte commitment (v19) — copied verbatim into Oracle.update outputs.
    pub commitment_raw: [u8; 36],
}

/// P2PKH funder UTXO returned by Fulcrum.
#[derive(Debug, Clone)]
pub struct FunderInfo {
    pub txid_be: Txid,
    pub vout: u32,
    pub satoshis: u64,
}

/// Publisher's own price observation. v13: the publisher fetches directly
/// (no notary tier) — this struct is what a `PriceProver` returns.
#[derive(Debug, Clone)]
pub struct PriceObservation {
    pub price: u64,
    pub timestamp: u32,
    pub server_name: String,
}

/// Trait abstracting every I/O point the cycle touches.
///
/// The cycle's `step()` is generic over `Env` so tests can swap in a `MockEnv`
/// and assert state transitions without any real network or filesystem I/O.
pub trait Env {
    // ─── clock ──────────────────────────────────────────────────────────
    fn now_unix_sec(&self) -> u32;
    fn sleep(&self, d: Duration);

    // ─── chain reads ────────────────────────────────────────────────────
    fn get_oracle_utxo(
        &mut self,
        cfg: &CycleConfig,
    ) -> Result<Option<OracleInfo>, CycleError>;

    fn get_slot_utxos(&mut self, cfg: &CycleConfig) -> Result<Vec<SlotInfo>, CycleError>;

    fn get_funder_utxos(&mut self, cfg: &CycleConfig) -> Result<Vec<FunderInfo>, CycleError>;

    // ─── chain writes ───────────────────────────────────────────────────
    fn broadcast_attest(&mut self, raw: &[u8]) -> Result<Txid, CycleError>;
    fn broadcast_update(&mut self, raw: &[u8]) -> Result<Txid, CycleError>;

    // ─── price fetch (publisher's own observation in v13) ───────────────
    fn fetch_price(&mut self, source_id: u16) -> Result<PriceObservation, CycleError>;

    // ─── persistence ────────────────────────────────────────────────────
    fn load_state(&self, slot: u8) -> Result<PublisherState, CycleError>;
    fn save_state(&self, slot: u8, s: &PublisherState) -> Result<(), CycleError>;
}
