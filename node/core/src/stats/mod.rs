//! Opt-in `/stats` HTTP endpoint.
//!
//! Wire shape preserves backward compat with consumers (e.g. community
//! aggregators) — `notary` field stays in the response as `null` since v13
//! has no notary tier. Publishers carry the substantive data.

use serde::Serialize;
use serde_json::json;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cycle::orchestrator::CYCLE_ERROR_COUNT;
use crate::http::{read_request, write_json, write_response};

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
/// knows where state files live.
pub trait StatsCollector: Send + Sync + 'static {
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
            let _ = CYCLE_ERROR_COUNT.load(Ordering::Relaxed);
            // `notary` retained as `null` in the response for wire-shape
            // backward compatibility with aggregator consumers.
            let payload = json!({
                "uptimeSec": uptime,
                "fetchedAt": fetched_at,
                "notary": serde_json::Value::Null,
                "publishers": collector.publishers(),
            });
            write_json(&mut stream, 200, "OK", &payload.to_string())
        }
        _ => write_response(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}
