//! Pure cycle transition function.
//!
//! Takes `(state, env, cfg, cycle_counter)` → `Result<CycleState, CycleError>`.
//! All I/O passes through the [`Env`] trait so tests can stub it out and assert
//! transitions deterministically.

use std::time::Instant;

use crate::chain::consts::{
    BUDGET_PAD_LEN, MAX_ATTEST_FEE_HINT, MAX_UPDATE_FEE_HINT, STRIDE_FLOOR_SEC, THR_FLOOR,
    TICKER_DUST, TICKER_HEAD_COUNT,
};
use crate::cycle::env::Env;
use crate::cycle::error::CycleError;
use crate::cycle::state::{CycleConfig, CycleSnapshot, CycleState, PublisherState};
use crate::tx::attest::{build_attest_tx, AttestArgs, AttestError, FunderUtxo, NotaryAttestation, SlotUtxo};
use crate::tx::update::{
    build_oracle_update_tx, CycleSlotUtxo, OracleUtxo, UpdateArgs, UpdateError,
};

/// Advance the cycle state machine by one logical step.
///
/// The orchestrator is responsible for the outer `loop {}` plus error handling
/// per [`Severity`]. `cycle_counter` increments at the top of each cycle (when
/// transitioning out of `Idle`) and is used here only to round-robin the
/// notary URL in `Snapshotted`.
pub fn step<E: Env>(
    state: CycleState,
    env: &mut E,
    cfg: &CycleConfig,
    cycle_counter: u64,
) -> Result<CycleState, CycleError> {
    match state {
        CycleState::Idle => idle(env, cfg),
        CycleState::Snapshotted { snap } => attest(env, cfg, snap, cycle_counter),
        CycleState::AlreadyAttested { snap } => wait_for_quorum(env, cfg, snap),
        CycleState::Attested { snap, .. } => wait_for_quorum(env, cfg, snap),
        CycleState::QuorumReached {
            snap,
            cycle_slot_commits,
            cycle_slot_utxos,
        } => update_oracle(env, cfg, snap, cycle_slot_commits, cycle_slot_utxos),
        CycleState::Updated { .. } => Ok(CycleState::Idle),
    }
}

// ─── Phase 1 ───────────────────────────────────────────────────────────────

fn idle<E: Env>(env: &mut E, cfg: &CycleConfig) -> Result<CycleState, CycleError> {
    let oracle = env
        .get_oracle_utxo(cfg)?
        .ok_or_else(|| CycleError::OracleNotFound {
            scripthash: cfg.oracle_scripthash_hex.clone(),
        })?;

    let new_seq = oracle.commit.seq + 1;
    let now = env.now_unix_sec();
    if now < oracle.commit.last_ts + STRIDE_FLOOR_SEC {
        let wait_sec = (oracle.commit.last_ts + STRIDE_FLOOR_SEC) - now + 1;
        return Err(CycleError::StrideFloor { wait_sec });
    }

    let slots = env.get_slot_utxos(cfg)?;
    let mine = slots
        .iter()
        .find(|s| s.commit.pkh == cfg.my_pkh)
        .ok_or_else(|| CycleError::MySlotNotFound { count: slots.len() })?;

    if new_seq < mine.commit.cycle_seq {
        return Err(CycleError::SlotAheadOfNew {
            at: mine.commit.cycle_seq,
            new: new_seq,
        });
    }

    let snap = CycleSnapshot {
        oracle_txid_be: oracle.txid_be,
        oracle_vout: oracle.vout,
        oracle_satoshis: oracle.satoshis,
        oracle_commit: oracle.commit,
        new_seq,
        prev_ts: oracle.commit.last_ts,
        mine_slot_txid_be: mine.txid_be,
        mine_slot_vout: mine.vout,
        mine_slot_satoshis: mine.satoshis,
        mine_slot_commit: mine.commit,
        mine_slot_commitment_raw: mine.commitment_raw,
    };

    Ok(if snap.already_attested() {
        CycleState::AlreadyAttested { snap }
    } else {
        CycleState::Snapshotted { snap }
    })
}

// ─── Phase 2 ───────────────────────────────────────────────────────────────

fn attest<E: Env>(
    env: &mut E,
    cfg: &CycleConfig,
    snap: CycleSnapshot,
    cycle_counter: u64,
) -> Result<CycleState, CycleError> {
    if cfg.notary_urls.is_empty() {
        return Err(CycleError::Internal("no notary URLs configured".into()));
    }
    let notary_idx = (cycle_counter as usize) % cfg.notary_urls.len();
    let notary_url = cfg.notary_urls[notary_idx].clone();

    let attestation =
        env.request_notary_sign(&notary_url, cfg.source_id, snap.new_seq, &cfg.my_pkh)?;

    let all_funder = env.get_funder_utxos(cfg)?;
    let funder_balance: u64 = all_funder.iter().map(|u| u.satoshis).sum();
    if funder_balance < MAX_ATTEST_FEE_HINT {
        return Err(CycleError::InsufficientFunds {
            have: funder_balance,
            need: MAX_ATTEST_FEE_HINT,
        });
    }

    let funders: Vec<FunderUtxo> = all_funder
        .into_iter()
        .map(|u| FunderUtxo {
            txid_be: u.txid_be,
            vout: u.vout,
            satoshis: u.satoshis,
        })
        .collect();

    let args = AttestArgs {
        slot_utxo: SlotUtxo {
            txid_be: snap.mine_slot_txid_be,
            vout: snap.mine_slot_vout,
            satoshis: snap.mine_slot_satoshis,
            commitment_raw: snap.mine_slot_commitment_raw,
        },
        source_id: snap.mine_slot_commit.source_id,
        publisher_pkh: cfg.my_pkh,
        publisher_privkey: cfg.publisher_privkey,
        publisher_pubkey: cfg.publisher_pubkey,
        funder_utxos: &funders,
        slot_category_wire_le: cfg.slot_category_wire_le,
        slot_redeem_script: &cfg.slot_redeem_script,
        notary: NotaryAttestation {
            price: attestation.price,
            timestamp: attestation.timestamp,
            server_name: attestation.server_name,
            notary_sig: attestation.notary_sig,
            notary_idx: notary_idx as u32,
        },
        new_cycle_seq: snap.new_seq,
    };

    let raw = build_attest_tx(&args).map_err(map_attest_error)?;
    let attest_txid = env.broadcast_attest(&raw)?;

    let _ = env.save_state(
        cfg.slot,
        &PublisherState {
            last_attest_txid: Some(hex::encode(attest_txid)),
            last_cycle_seq: Some(snap.new_seq),
            last_update_txid: env
                .load_state(cfg.slot)
                .ok()
                .and_then(|s| s.last_update_txid),
        },
    );

    Ok(CycleState::Attested { snap, attest_txid })
}

fn map_attest_error(e: AttestError) -> CycleError {
    match e {
        AttestError::NotaryIdxOutOfRange(_) => CycleError::Internal(e.to_string()),
        AttestError::InsufficientFunds { have, need } => {
            CycleError::InsufficientFunds { have, need }
        }
        AttestError::Crypto(_) => CycleError::Internal(e.to_string()),
    }
}

// ─── Phase 3 ───────────────────────────────────────────────────────────────

fn wait_for_quorum<E: Env>(
    env: &mut E,
    cfg: &CycleConfig,
    snap: CycleSnapshot,
) -> Result<CycleState, CycleError> {
    let deadline = Instant::now() + cfg.quorum_wait;
    loop {
        env.sleep(cfg.poll_interval);
        let all = env.get_slot_utxos(cfg)?;
        let at_seq: Vec<_> = all
            .into_iter()
            .filter(|s| s.commit.cycle_seq == snap.new_seq)
            .collect();
        if at_seq.len() >= THR_FLOOR {
            // Dedupe by pkh + sort by LE-numeric pkh ascending.
            let mut seen = std::collections::HashSet::new();
            let mut deduped: Vec<_> = at_seq
                .into_iter()
                .filter(|s| seen.insert(s.commit.pkh))
                .collect();
            deduped.sort_by(|a, b| {
                for i in (0..20).rev() {
                    if a.commit.pkh[i] != b.commit.pkh[i] {
                        return a.commit.pkh[i].cmp(&b.commit.pkh[i]);
                    }
                }
                std::cmp::Ordering::Equal
            });
            let cycle_slot_commits: Vec<_> = deduped.iter().map(|s| s.commit).collect();
            let cycle_slot_utxos: Vec<_> =
                deduped.iter().map(|s| (s.txid_be, s.vout, s.satoshis)).collect();
            return Ok(CycleState::QuorumReached {
                snap,
                cycle_slot_commits,
                cycle_slot_utxos,
            });
        }
        if Instant::now() >= deadline {
            return Err(CycleError::QuorumTimeout {
                got: at_seq.len(),
                need: THR_FLOOR,
            });
        }
    }
}

// ─── Phase 4 ───────────────────────────────────────────────────────────────

fn update_oracle<E: Env>(
    env: &mut E,
    cfg: &CycleConfig,
    snap: CycleSnapshot,
    cycle_slot_commits: Vec<crate::chain::slot_commit::SlotCommit>,
    cycle_slot_utxos: Vec<(crate::cycle::state::Txid, u32, u64)>,
) -> Result<CycleState, CycleError> {
    let all_funder = env.get_funder_utxos(cfg)?;
    let funder_balance: u64 = all_funder.iter().map(|u| u.satoshis).sum();
    let min_update_funds = (TICKER_HEAD_COUNT as u64) * TICKER_DUST + MAX_UPDATE_FEE_HINT;
    if funder_balance < min_update_funds {
        return Err(CycleError::InsufficientFunds {
            have: funder_balance,
            need: min_update_funds,
        });
    }

    let funders: Vec<FunderUtxo> = all_funder
        .into_iter()
        .map(|u| FunderUtxo {
            txid_be: u.txid_be,
            vout: u.vout,
            satoshis: u.satoshis,
        })
        .collect();

    let cycle_slot_utxos_for_builder: Vec<CycleSlotUtxo> = cycle_slot_commits
        .iter()
        .zip(cycle_slot_utxos.iter())
        .map(|(commit, (txid_be, vout, sats))| {
            let raw = crate::chain::slot_commit::encode_slot_commit(commit);
            CycleSlotUtxo {
                txid_be: *txid_be,
                vout: *vout,
                satoshis: *sats,
                pkh: commit.pkh,
                price: commit.price,
                timestamp: commit.timestamp,
                commitment: raw,
            }
        })
        .collect();

    let args = UpdateArgs {
        oracle_utxo: OracleUtxo {
            txid_be: snap.oracle_txid_be,
            vout: snap.oracle_vout,
            satoshis: snap.oracle_satoshis,
            prev_state: snap.oracle_commit,
        },
        cycle_slots: &cycle_slot_utxos_for_builder,
        funder_utxos: &funders,
        publisher_pkh: cfg.my_pkh,
        publisher_privkey: cfg.publisher_privkey,
        publisher_pubkey: cfg.publisher_pubkey,
        oracle_category_wire_le: cfg.oracle_category_wire_le,
        slot_category_wire_le: cfg.slot_category_wire_le,
        oracle_redeem_script: &cfg.oracle_redeem_script,
        slot_redeem_script: &cfg.slot_redeem_script,
        ticker_redeem_script: &cfg.ticker_redeem_script,
        new_seq: snap.new_seq,
    };

    let raw = build_oracle_update_tx(&args).map_err(map_update_error)?;
    let update_txid = match env.broadcast_update(&raw) {
        Ok(t) => Some(t),
        Err(CycleError::UpdateRaceLostOk) => None,
        Err(e) => return Err(e),
    };

    if let Some(txid) = update_txid {
        let prior = env.load_state(cfg.slot).ok().unwrap_or_default();
        let _ = env.save_state(
            cfg.slot,
            &PublisherState {
                last_update_txid: Some(hex::encode(txid)),
                ..prior
            },
        );
    }

    Ok(CycleState::Updated {
        new_seq: snap.new_seq,
        update_txid,
    })
}

fn map_update_error(e: UpdateError) -> CycleError {
    match e {
        UpdateError::BelowQuorum { got, need } => CycleError::QuorumTimeout { got, need },
        UpdateError::DuplicatePkh(i) => CycleError::Internal(format!("duplicate pkh at {i}")),
        UpdateError::StrideFloor { new, prev, stride } => {
            CycleError::Internal(format!("stride floor: new={new} prev={prev} need {stride}"))
        }
        UpdateError::InsufficientFunds { have, need } => {
            CycleError::InsufficientFunds { have, need }
        }
        UpdateError::Crypto(_) => CycleError::Internal(e.to_string()),
    }
}

// Compile-time sanity: BUDGET_PAD_LEN is the documented value.
const _: () = assert!(BUDGET_PAD_LEN == 1024);

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use crate::chain::oracle_commit::OracleState;
    use crate::chain::slot_commit::SlotCommit;
    use crate::cycle::env::{FunderInfo, NotaryResponse, OracleInfo, SlotInfo};
    use std::cell::RefCell;

    /// Test env — records all calls + plays back canned responses.
    struct MockEnv {
        now: RefCell<u32>,
        oracle: RefCell<Option<OracleInfo>>,
        slots: RefCell<Vec<SlotInfo>>,
        funder: RefCell<Vec<FunderInfo>>,
        notary_response: RefCell<Option<NotaryResponse>>,
        notary_error: RefCell<Option<CycleError>>,
        broadcast_attest_outcome: RefCell<VecDeque<Result<crate::cycle::state::Txid, CycleError>>>,
        broadcast_update_outcome: RefCell<VecDeque<Result<crate::cycle::state::Txid, CycleError>>>,
        state_file: RefCell<Option<PublisherState>>,
        sleep_log: RefCell<Vec<std::time::Duration>>,
    }

    impl MockEnv {
        fn new() -> Self {
            Self {
                now: RefCell::new(1_780_000_100),
                oracle: RefCell::new(None),
                slots: RefCell::new(vec![]),
                funder: RefCell::new(vec![]),
                notary_response: RefCell::new(None),
                notary_error: RefCell::new(None),
                broadcast_attest_outcome: RefCell::new(VecDeque::new()),
                broadcast_update_outcome: RefCell::new(VecDeque::new()),
                state_file: RefCell::new(None),
                sleep_log: RefCell::new(vec![]),
            }
        }
    }

    impl Env for MockEnv {
        fn now_unix_sec(&self) -> u32 {
            *self.now.borrow()
        }
        fn sleep(&self, d: std::time::Duration) {
            self.sleep_log.borrow_mut().push(d);
            // Virtual time — skip ahead so quorum-wait loops don't spin forever.
            *self.now.borrow_mut() += d.as_secs() as u32;
        }
        fn get_oracle_utxo(
            &mut self,
            _cfg: &CycleConfig,
        ) -> Result<Option<OracleInfo>, CycleError> {
            Ok(self.oracle.borrow().clone())
        }
        fn get_slot_utxos(&mut self, _cfg: &CycleConfig) -> Result<Vec<SlotInfo>, CycleError> {
            Ok(self.slots.borrow().clone())
        }
        fn get_funder_utxos(&mut self, _cfg: &CycleConfig) -> Result<Vec<FunderInfo>, CycleError> {
            Ok(self.funder.borrow().clone())
        }
        fn broadcast_attest(&mut self, _raw: &[u8]) -> Result<crate::cycle::state::Txid, CycleError> {
            self.broadcast_attest_outcome
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok([0xaa; 32]))
        }
        fn broadcast_update(&mut self, _raw: &[u8]) -> Result<crate::cycle::state::Txid, CycleError> {
            self.broadcast_update_outcome
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok([0xbb; 32]))
        }
        fn request_notary_sign(
            &mut self,
            _url: &str,
            _source_id: u16,
            _cycle_seq: u32,
            _pkh: &[u8; 20],
        ) -> Result<NotaryResponse, CycleError> {
            if let Some(e) = self.notary_error.borrow_mut().take() {
                return Err(e);
            }
            self.notary_response
                .borrow()
                .clone()
                .ok_or_else(|| CycleError::Internal("mock notary_response unset".into()))
        }
        fn load_state(&self, _slot: u8) -> Result<PublisherState, CycleError> {
            Ok(self.state_file.borrow().clone().unwrap_or_default())
        }
        fn save_state(&self, _slot: u8, s: &PublisherState) -> Result<(), CycleError> {
            *self.state_file.borrow_mut() = Some(s.clone());
            Ok(())
        }
    }

    fn fixture_cfg() -> CycleConfig {
        CycleConfig {
            slot: 0,
            my_pkh: [0x42; 20],
            publisher_privkey: [0x11; 32],
            publisher_pubkey: [0x02; 33],
            source_id: 1,
            notary_urls: vec![
                "http://127.0.0.1:8081".to_string(),
                "http://127.0.0.1:8082".to_string(),
            ],
            oracle_category_wire_le: [0xcc; 32],
            slot_category_wire_le: [0xdd; 32],
            oracle_redeem_script: vec![0u8; 100],
            slot_redeem_script: vec![0u8; 100],
            ticker_redeem_script: vec![0u8; 100],
            publisher_address: "bchtest:qaaa".to_string(),
            oracle_address: "bchtest:qbbb".to_string(),
            slot_address: "bchtest:qccc".to_string(),
            oracle_scripthash_hex: "00".repeat(32),
            slot_scripthash_hex: "11".repeat(32),
            publisher_scripthash_hex: "22".repeat(32),
            oracle_category_be_hex: "00".repeat(32),
            slot_category_be_hex: "00".repeat(32),
            poll_interval: std::time::Duration::from_secs(3),
            quorum_wait: std::time::Duration::from_secs(25),
        }
    }

    fn oracle_info(seq: u32, last_ts: u32) -> OracleInfo {
        OracleInfo {
            txid_be: [0xaa; 32],
            vout: 0,
            satoshis: 2000,
            commit: OracleState {
                seq,
                last_ts,
                median_usd: 350_000_000,
                active_count: 10,
            },
        }
    }

    fn slot_info(pkh: [u8; 20], cycle_seq: u32, ts: u32, price: u64) -> SlotInfo {
        let commit = SlotCommit {
            source_id: 1,
            pkh,
            price,
            timestamp: ts,
            cycle_seq,
        };
        SlotInfo {
            txid_be: [pkh[0]; 32],
            vout: 0,
            satoshis: 1000,
            commit,
            commitment_raw: crate::chain::slot_commit::encode_slot_commit(&commit),
        }
    }

    #[test]
    fn idle_no_oracle_yields_oracle_not_found() {
        let mut env = MockEnv::new();
        let cfg = fixture_cfg();
        let r = step(CycleState::Idle, &mut env, &cfg, 1);
        assert!(matches!(r, Err(CycleError::OracleNotFound { .. })));
    }

    #[test]
    fn idle_stride_floor_returns_wait() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_780_000_100));
        // now < last_ts + 30 (now = 1_780_000_100 which is < 1_780_000_130)
        let cfg = fixture_cfg();
        let r = step(CycleState::Idle, &mut env, &cfg, 1);
        assert!(matches!(r, Err(CycleError::StrideFloor { .. })));
    }

    #[test]
    fn idle_my_slot_missing() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_700_000_000));
        env.slots.borrow_mut().push(slot_info([0x99; 20], 100, 1_700_000_100, 1000));
        let cfg = fixture_cfg();
        let r = step(CycleState::Idle, &mut env, &cfg, 1);
        assert!(matches!(r, Err(CycleError::MySlotNotFound { count: 1 })));
    }

    #[test]
    fn idle_my_slot_ahead_yields_slot_ahead() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_700_000_000));
        // mine at 200 > new_seq=101
        env.slots.borrow_mut().push(slot_info([0x42; 20], 200, 1_700_000_100, 1000));
        let cfg = fixture_cfg();
        let r = step(CycleState::Idle, &mut env, &cfg, 1);
        assert!(matches!(
            r,
            Err(CycleError::SlotAheadOfNew { at: 200, new: 101 })
        ));
    }

    #[test]
    fn idle_my_slot_already_at_new_seq_branches_to_already_attested() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_700_000_000));
        // mine at 101 == new_seq
        env.slots.borrow_mut().push(slot_info([0x42; 20], 101, 1_700_000_100, 1000));
        let cfg = fixture_cfg();
        let r = step(CycleState::Idle, &mut env, &cfg, 1).unwrap();
        assert!(matches!(r, CycleState::AlreadyAttested { .. }));
    }

    #[test]
    fn idle_my_slot_behind_branches_to_snapshotted() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_700_000_000));
        env.slots.borrow_mut().push(slot_info([0x42; 20], 100, 1_700_000_100, 1000));
        let cfg = fixture_cfg();
        let r = step(CycleState::Idle, &mut env, &cfg, 1).unwrap();
        assert!(matches!(r, CycleState::Snapshotted { .. }));
    }

    #[test]
    fn snapshotted_propagates_notary_unreachable() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_700_000_000));
        env.slots.borrow_mut().push(slot_info([0x42; 20], 100, 1_700_000_100, 1000));
        env.notary_error.borrow_mut().replace(CycleError::NotaryUnreachable {
            url: "http://127.0.0.1:8081".to_string(),
            reason: "connection refused".to_string(),
        });
        let cfg = fixture_cfg();
        let snap = match step(CycleState::Idle, &mut env, &cfg, 1).unwrap() {
            CycleState::Snapshotted { snap } => snap,
            _ => panic!("expected Snapshotted"),
        };
        let r = step(CycleState::Snapshotted { snap }, &mut env, &cfg, 1);
        assert!(matches!(r, Err(CycleError::NotaryUnreachable { .. })));
    }

    #[test]
    fn snapshotted_insufficient_funder_yields_error() {
        let mut env = MockEnv::new();
        env.oracle.borrow_mut().replace(oracle_info(100, 1_700_000_000));
        env.slots.borrow_mut().push(slot_info([0x42; 20], 100, 1_700_000_100, 1000));
        env.notary_response.borrow_mut().replace(NotaryResponse {
            price: 350_000_000,
            timestamp: 1_700_000_200,
            server_name: "api.kraken.com".to_string(),
            notary_sig: vec![0xee; 70],
        });
        env.funder.borrow_mut().push(FunderInfo {
            txid_be: [0x33; 32],
            vout: 0,
            satoshis: 100, // < MAX_ATTEST_FEE_HINT = 3000
        });
        let cfg = fixture_cfg();
        let snap = match step(CycleState::Idle, &mut env, &cfg, 1).unwrap() {
            CycleState::Snapshotted { snap } => snap,
            _ => panic!(),
        };
        let r = step(CycleState::Snapshotted { snap }, &mut env, &cfg, 1);
        assert!(matches!(
            r,
            Err(CycleError::InsufficientFunds { have: 100, need: 3000 })
        ));
    }
}
