//! Real `Env` impl wiring Electrum + in-process PriceProver + filesystem state.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ticker_core::chain::oracle_commit::decode_oracle_commit;
use ticker_core::chain::slot_commit::decode_slot_commit;
use ticker_core::chain::sources::SOURCES;
use ticker_core::cycle::env::{Env, FunderInfo, OracleInfo, PriceObservation, SlotInfo};
use ticker_core::cycle::error::CycleError;
use ticker_core::cycle::state::{CycleConfig, PublisherState, Txid};
use ticker_core::electrum::types::{NftCapability, Utxo};
use ticker_core::electrum::{ElectrumClient, ElectrumError};
use ticker_core::prover::{HttpsPlainProver, PriceProver};

/// Real Env — holds the Electrum client (behind Mutex for the cycle loop),
/// the `.ticker/` base path for state files, and an in-process price prover.
pub struct RealEnv {
    pub electrum: Mutex<ElectrumClient>,
    pub state_dir: PathBuf,
    pub prover: HttpsPlainProver,
}

impl RealEnv {
    fn map_electrum(&self, e: ElectrumError) -> CycleError {
        match &e {
            ElectrumError::Disconnected | ElectrumError::Io(_) | ElectrumError::Tcp { .. } => {
                CycleError::FulcrumDisconnected(e.to_string())
            }
            _ => CycleError::Internal(e.to_string()),
        }
    }

    fn classify_broadcast_attest(&self, e: ElectrumError) -> CycleError {
        let msg = e.to_string();
        if is_race_lost(&msg) {
            CycleError::AttestRaceLost
        } else if is_covenant_rejection(&msg) {
            CycleError::CovenantRejectedAttest { reason: msg }
        } else {
            self.map_electrum(e)
        }
    }

    fn classify_broadcast_update(&self, e: ElectrumError) -> CycleError {
        let msg = e.to_string();
        if is_race_lost(&msg) {
            CycleError::UpdateRaceLostOk
        } else if is_covenant_rejection(&msg) {
            CycleError::CovenantRejectedUpdate { reason: msg }
        } else {
            self.map_electrum(e)
        }
    }

    fn state_path(&self, slot: u8) -> PathBuf {
        self.state_dir
            .join(format!("publisher-state-{slot}.json"))
    }
}

/// BCHN/Fulcrum substrings that signal another publisher's broadcast won the
/// race (our tx is now competing with an already-mined or already-mempool tx).
/// Crucially `missingorspent` covers `bad-txns-inputs-missingorspent`, returned
/// when the input we tried to spend is already consumed.
fn is_race_lost(msg: &str) -> bool {
    msg.contains("txn-mempool-conflict")
        || msg.contains("txn-already-in-mempool")
        || msg.contains("txn-already-known")
        || msg.contains("missingorspent")
        || msg.contains("already spent")
        || msg.contains("duplicate")
}

/// Tight substrings indicating the BCHN script interpreter actually rejected
/// our transaction (i.e. the covenant disallowed it). Deliberately narrower
/// than "bad-txns" alone, which also matches the race-lost case above.
fn is_covenant_rejection(msg: &str) -> bool {
    msg.contains("mandatory-script-verify-flag-failed")
        || msg.contains("non-mandatory-script-verify-flag-failed")
        || msg.contains("blk-bad-inputs")
        || msg.contains("bad-txns-nonfinal")
}

fn parse_txid_be(hex_str: &str) -> Result<Txid, CycleError> {
    let v = hex::decode(hex_str)
        .map_err(|e| CycleError::Internal(format!("bad txid hex: {e}")))?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| CycleError::Internal("txid len != 32".to_string()))?;
    Ok(arr)
}

impl Env for RealEnv {
    fn now_unix_sec(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn get_oracle_utxo(&mut self, cfg: &CycleConfig) -> Result<Option<OracleInfo>, CycleError> {
        let utxos = self
            .electrum
            .lock()
            .unwrap()
            .list_unspent_by_scripthash(&cfg.oracle_scripthash_hex)
            .map_err(|e| self.map_electrum(e))?;
        for u in utxos {
            let Some(td) = &u.token_data else { continue };
            if td.category != cfg.oracle_category_be_hex {
                continue;
            }
            let Some(nft) = &td.nft else { continue };
            if nft.capability != NftCapability::Minting {
                continue;
            }
            let commit_bytes = hex::decode(&nft.commitment)
                .map_err(|e| CycleError::OracleCommitMalformed(format!("hex: {e}")))?;
            let commit = decode_oracle_commit(&commit_bytes)
                .map_err(|e| CycleError::OracleCommitMalformed(e.to_string()))?;
            return Ok(Some(OracleInfo {
                txid_be: parse_txid_be(&u.tx_hash)?,
                vout: u.tx_pos,
                satoshis: u.value,
                commit,
            }));
        }
        Ok(None)
    }

    fn get_slot_utxos(&mut self, cfg: &CycleConfig) -> Result<Vec<SlotInfo>, CycleError> {
        // v16: each of 13 slots has its OWN P2SH-32 address → its own
        // scripthash. Aggregate by iterating all 13. (v15 used a single
        // shared scripthash because all NFTs lived at one address.)
        let mut out = Vec::with_capacity(13);
        for sh in &cfg.all_slot_scripthashes_hex {
            let utxos = self
                .electrum
                .lock()
                .unwrap()
                .list_unspent_by_scripthash(sh)
                .map_err(|e| self.map_electrum(e))?;
            for u in utxos {
                let Some(td) = &u.token_data else { continue };
                if td.category != cfg.slot_category_be_hex {
                    continue;
                }
                let Some(nft) = &td.nft else { continue };
                if nft.capability != NftCapability::Mutable {
                    continue;
                }
                let raw = hex::decode(&nft.commitment).map_err(|_| {
                    CycleError::SlotCommitMalformed {
                        txid: u.tx_hash.clone(),
                        vout: u.tx_pos,
                    }
                })?;
                let Some(commit) = decode_slot_commit(&raw) else { continue };
                let mut commitment_raw = [0u8; 36];
                commitment_raw.copy_from_slice(&raw);
                out.push(SlotInfo {
                    txid_be: parse_txid_be(&u.tx_hash)?,
                    vout: u.tx_pos,
                    satoshis: u.value,
                    commit,
                    commitment_raw,
                });
            }
        }
        Ok(out)
    }

    fn get_funder_utxos(&mut self, cfg: &CycleConfig) -> Result<Vec<FunderInfo>, CycleError> {
        let utxos: Vec<Utxo> = self
            .electrum
            .lock()
            .unwrap()
            .list_unspent_by_scripthash(&cfg.publisher_scripthash_hex)
            .map_err(|e| self.map_electrum(e))?;
        let mut out = Vec::with_capacity(utxos.len());
        for u in utxos {
            if u.token_data.is_some() {
                continue;
            }
            out.push(FunderInfo {
                txid_be: parse_txid_be(&u.tx_hash)?,
                vout: u.tx_pos,
                satoshis: u.value,
            });
        }
        Ok(out)
    }

    fn broadcast_attest(&mut self, raw: &[u8]) -> Result<Txid, CycleError> {
        let txid_hex = self
            .electrum
            .lock()
            .unwrap()
            .broadcast_raw(raw)
            .map_err(|e| self.classify_broadcast_attest(e))?;
        parse_txid_be(&txid_hex)
    }

    fn broadcast_update(&mut self, raw: &[u8]) -> Result<Txid, CycleError> {
        let txid_hex = self
            .electrum
            .lock()
            .unwrap()
            .broadcast_raw(raw)
            .map_err(|e| self.classify_broadcast_update(e))?;
        parse_txid_be(&txid_hex)
    }

    fn fetch_price(&mut self, source_id: u16) -> Result<PriceObservation, CycleError> {
        let source = SOURCES
            .iter()
            .find(|s| s.id == source_id)
            .ok_or_else(|| CycleError::Internal(format!("unknown source_id {source_id}")))?;
        let proof = self
            .prover
            .prove(source)
            .map_err(|e| CycleError::PriceFetchFailed {
                source_id,
                reason: e.to_string(),
            })?;
        Ok(PriceObservation {
            price: proof.price,
            timestamp: proof.timestamp,
            server_name: proof.server_name,
        })
    }

    fn load_state(&self, slot: u8) -> Result<PublisherState, CycleError> {
        let path = self.state_path(slot);
        match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| CycleError::StateIo(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PublisherState::default()),
            Err(e) => Err(CycleError::StateIo(e.to_string())),
        }
    }

    fn save_state(&self, slot: u8, s: &PublisherState) -> Result<(), CycleError> {
        let path = self.state_path(slot);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let body = serde_json::to_vec_pretty(s).map_err(|e| CycleError::StateIo(e.to_string()))?;
        fs::write(&path, body).map_err(|e| CycleError::StateIo(e.to_string()))
    }
}
