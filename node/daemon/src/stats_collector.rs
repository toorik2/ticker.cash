//! Real `/stats` collector — reads on-disk publisher-state-N.json files,
//! reports the notary identity if we're running one.

use std::path::PathBuf;

use ticker_core::cycle::orchestrator::CYCLE_ERROR_COUNT;
use ticker_core::cycle::state::PublisherState;
use ticker_core::notary::server::SIGN_REQUEST_COUNT;
use ticker_core::stats::{NotaryStats, PublisherStats, StatsCollector};

pub struct RealStatsCollector {
    pub state_dir: PathBuf,
    pub notary: Option<NotaryIdentity>,
}

#[derive(Debug, Clone)]
pub struct NotaryIdentity {
    pub slot: u8,
    pub port: u16,
    pub address: String,
    pub pubkey_hex: String,
}

impl StatsCollector for RealStatsCollector {
    fn notary(&self) -> Option<NotaryStats> {
        self.notary.as_ref().map(|n| NotaryStats {
            slot: n.slot,
            port: n.port,
            address: n.address.clone(),
            pubkey: n.pubkey_hex.clone(),
            mode: "operator-key",
            sign_requests_since_start: SIGN_REQUEST_COUNT
                .load(std::sync::atomic::Ordering::Relaxed),
        })
    }

    fn publishers(&self) -> Vec<PublisherStats> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&self.state_dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else { continue };
            let Some(rest) = name
                .strip_prefix("publisher-state-")
                .and_then(|s| s.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(slot) = rest.parse::<u8>() else { continue };
            let path = entry.path();
            let Ok(body) = std::fs::read_to_string(&path) else { continue };
            let Ok(state): Result<PublisherState, _> = serde_json::from_str(&body) else {
                continue;
            };
            out.push(PublisherStats {
                slot,
                last_attest_txid: state.last_attest_txid,
                last_update_txid: state.last_update_txid,
                last_cycle_seq: state.last_cycle_seq,
                errors_since_start: CYCLE_ERROR_COUNT
                    .load(std::sync::atomic::Ordering::Relaxed),
            });
        }
        out.sort_by_key(|p| p.slot);
        out
    }
}
