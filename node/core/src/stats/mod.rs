//! Opt-in `/stats` HTTP endpoint.
//!
//! Wire shape matches the TS daemon's `--stats-bind ADDR:PORT` response so the
//! community `stats.ticker.cash` aggregator can consume both implementations
//! interchangeably during the rollout.

use serde::Serialize;
use serde_json::json;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cycle::orchestrator::CYCLE_ERROR_COUNT;
use crate::notary::http::{read_request, write_json, write_response};
use crate::notary::server::SIGN_REQUEST_COUNT;

/// Notary identity portion of the stats response.
#[derive(Debug, Clone, Serialize)]
pub struct NotaryStats {
    pub slot: u8,
    pub port: u16,
    pub address: String,
    pub pubkey: String,
    pub mode: &'static str, // "operator-key" always (legacy seed-derived dropped)
    #[serde(rename = "signRequestsSinceStart")]
    pub sign_requests_since_start: u64,
}

/// Publisher per-slot summary.
#[derive(Debug, Clone, Serialize)]
pub struct PublisherStats {
    pub slot: u8,
    #[serde(rename = "lastAttestTxid")]
    pub last_attest_txid: Option<String>,
    #[serde(rename = "lastUpdateTxid")]
    pub last_update_txid: Option<String>,
    #[serde(rename = "lastCycleSeq")]
    pub last_cycle_seq: Option<u32>,
    #[serde(rename = "errorsSinceStart")]
    pub errors_since_start: u64,
}

/// Caller-supplied snapshot collector — the binary provides this since only it
/// knows where state files live and what notary identity is in scope.
pub trait StatsCollector: Send + Sync + 'static {
    fn notary(&self) -> Option<NotaryStats>;
    fn publishers(&self) -> Vec<PublisherStats>;
}

/// Start the /stats HTTP server. Blocks indefinitely.
pub fn run_stats<C: StatsCollector + 'static>(
    addr: &str,
    collector: Arc<C>,
    proc_start: SystemTime,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    crate::log_info!("stats server listening", "addr" => addr);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let c = collector.clone();
        std::thread::spawn(move || {
            let _ = serve_one(stream, c.as_ref(), proc_start);
        });
    }
    Ok(())
}

fn serve_one<C: StatsCollector>(
    mut stream: TcpStream,
    collector: &C,
    proc_start: SystemTime,
) -> std::io::Result<()> {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(_) => return write_response(&mut stream, 400, "Bad Request", "text/plain", b"bad"),
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("OPTIONS", _) => {
            write_response(&mut stream, 204, "No Content", "text/plain", b"")
        }
        ("GET", "/stats") => {
            let uptime = SystemTime::now()
                .duration_since(proc_start)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let fetched_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // Note: we don't currently consume CYCLE_ERROR_COUNT in the
            // publishers slice (each entry carries its own count from disk +
            // counter). Including the process-level total in a top-level field
            // would be a wire-shape add — left for a forward-compat extension.
            let _ = CYCLE_ERROR_COUNT.load(Ordering::Relaxed);
            let _ = SIGN_REQUEST_COUNT.load(Ordering::Relaxed); // implicitly used in notary snapshot
            let payload = json!({
                "uptimeSec": uptime,
                "fetchedAt": fetched_at,
                "notary": collector.notary(),
                "publishers": collector.publishers(),
            });
            write_json(&mut stream, 200, "OK", &payload.to_string())
        }
        _ => write_response(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}
