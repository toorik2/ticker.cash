//! Real `Env` impl wiring Electrum + notary HTTP client + filesystem state.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ticker_core::chain::oracle_commit::decode_oracle_commit;
use ticker_core::chain::slot_commit::decode_slot_commit;
use ticker_core::cycle::env::{Env, FunderInfo, NotaryResponse, OracleInfo, SlotInfo};
use ticker_core::cycle::error::CycleError;
use ticker_core::cycle::state::{CycleConfig, PublisherState, Txid};
use ticker_core::electrum::types::{NftCapability, Utxo};
use ticker_core::electrum::{ElectrumClient, ElectrumError};

/// Real Env — holds the Electrum client (behind Mutex for the cycle loop)
/// plus the `.ticker/` base path for state files.
pub struct RealEnv {
    pub electrum: Mutex<ElectrumClient>,
    pub state_dir: PathBuf,
    pub notary_http_timeout: Duration,
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

fn is_race_lost(msg: &str) -> bool {
    msg.contains("txn-mempool-conflict")
        || msg.contains("already spent")
        || msg.contains("duplicate")
}

fn is_covenant_rejection(msg: &str) -> bool {
    msg.contains("bad-txns")
        || msg.contains("script") && msg.contains("failed")
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
        let utxos = self
            .electrum
            .lock()
            .unwrap()
            .list_unspent_by_scripthash(&cfg.slot_scripthash_hex)
            .map_err(|e| self.map_electrum(e))?;
        let mut out = Vec::with_capacity(utxos.len());
        for u in utxos {
            let Some(td) = &u.token_data else { continue };
            if td.category != cfg.slot_category_be_hex {
                continue;
            }
            let Some(nft) = &td.nft else { continue };
            if nft.capability != NftCapability::Mutable {
                continue;
            }
            let raw = hex::decode(&nft.commitment)
                .map_err(|e| CycleError::Internal(format!("slot hex: {e}")))?;
            let Some(commit) = decode_slot_commit(&raw) else { continue };
            let mut commitment_raw = [0u8; 39];
            commitment_raw.copy_from_slice(&raw);
            out.push(SlotInfo {
                txid_be: parse_txid_be(&u.tx_hash)?,
                vout: u.tx_pos,
                satoshis: u.value,
                commit,
                commitment_raw,
            });
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

    fn request_notary_sign(
        &mut self,
        url: &str,
        source_id: u16,
        cycle_seq: u32,
        pkh: &[u8; 20],
    ) -> Result<NotaryResponse, CycleError> {
        // Hand-rolled HTTP/1.0 POST. Notary URLs are loopback-only by default
        // (http://127.0.0.1:PORT) — no TLS for the local case.
        let (host, port, path_prefix) = parse_url(url).map_err(|e| CycleError::NotaryUnreachable {
            url: url.to_string(),
            reason: e,
        })?;
        let path = if path_prefix == "/" {
            "/sign".to_string()
        } else {
            format!("{path_prefix}/sign")
        };
        let body = serde_json::json!({
            "sourceId": source_id,
            "cycleSeq": cycle_seq,
            "pubkeyHash": hex::encode(pkh),
        })
        .to_string();
        let req = format!(
            "POST {path} HTTP/1.0\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect((host.as_str(), port)).map_err(|e| {
            CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: e.to_string(),
            }
        })?;
        let _ = stream.set_read_timeout(Some(self.notary_http_timeout));
        let _ = stream.set_write_timeout(Some(self.notary_http_timeout));
        stream
            .write_all(req.as_bytes())
            .map_err(|e| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: e.to_string(),
            })?;
        let mut resp = Vec::with_capacity(2048);
        let _ = stream.read_to_end(&mut resp);
        let body_start = resp
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(0);
        let body_str = std::str::from_utf8(&resp[body_start..]).map_err(|e| {
            CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: e.to_string(),
            }
        })?;
        let parsed: serde_json::Value =
            serde_json::from_str(body_str).map_err(|e| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: format!(
                    "parse: {e} | body_start={} resp_len={} preview={:?}",
                    body_start,
                    resp.len(),
                    std::str::from_utf8(&resp[..resp.len().min(80)])
                        .unwrap_or("<non-utf8>")
                ),
            })?;
        let price: u64 = parsed
            .get("price")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: "missing price".to_string(),
            })?
            .parse()
            .map_err(|e: std::num::ParseIntError| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: format!("price parse: {e}"),
            })?;
        let timestamp = parsed
            .get("timestamp")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: "missing timestamp".to_string(),
            })? as u32;
        let server_name = parsed
            .get("serverName")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: "missing serverName".to_string(),
            })?
            .to_string();
        let sig_hex = parsed
            .get("notarySig")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: "missing notarySig".to_string(),
            })?;
        let notary_sig = hex::decode(sig_hex).map_err(|e| CycleError::NotaryUnreachable {
            url: url.to_string(),
            reason: format!("sig hex: {e}"),
        })?;
        // ECDSA-DER signatures are 70-72 bytes typically; covenant `checkDataSig`
        // accepts any valid DER. We don't enforce a fixed length client-side.
        if notary_sig.len() < 64 || notary_sig.len() > 80 {
            return Err(CycleError::NotaryUnreachable {
                url: url.to_string(),
                reason: format!("notarySig length {} outside 64..80", notary_sig.len()),
            });
        }
        Ok(NotaryResponse {
            price,
            timestamp,
            server_name,
            notary_sig,
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

fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| "url must be http(s)://".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse().map_err(|_| format!("bad port {p:?}"))?,
        ),
        None => (
            authority.to_string(),
            if url.starts_with("https") { 443 } else { 80 },
        ),
    };
    Ok((host, port, path.to_string()))
}
