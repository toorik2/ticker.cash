//! Opt-in `/stats` HTTP endpoint.

use serde::Serialize;
use serde_json::json;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cycle::orchestrator::CYCLE_ERROR_COUNT;
use crate::http::{read_request, write_json, write_response};

/// Upper bound on concurrent in-flight `/stats` requests. The endpoint is cheap
/// (a few atomic loads + a JSON serialise) so we don't need many; this exists
/// to prevent slowloris / fork-bomb style resource exhaustion.
const MAX_CONCURRENT_REQUESTS: usize = 32;
/// Per-connection read+write socket timeout.
const STATS_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Publisher per-slot summary.
#[derive(Debug, Clone, Serialize)]
pub struct PublisherStats {
    pub slot: u8,
    #[serde(rename = "lastAttestTxid")]
    pub last_attest_txid: Option<String>,
    #[serde(rename = "lastUpdateTxid")]
    pub last_update_txid: Option<String>,
    #[serde(rename = "lastCycleSeq")]
    pub last_cycle_seq: Option<u64>,
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
    let inflight = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = stream.set_read_timeout(Some(STATS_SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(STATS_SOCKET_TIMEOUT));
        if inflight.load(Ordering::Relaxed) >= MAX_CONCURRENT_REQUESTS {
            let _ = write_response(&mut stream, 503, "Busy", "text/plain", b"busy");
            continue;
        }
        inflight.fetch_add(1, Ordering::Relaxed);
        let c = collector.clone();
        let inflight_c = inflight.clone();
        std::thread::spawn(move || {
            let _ = serve_one(stream, c.as_ref(), proc_start);
            inflight_c.fetch_sub(1, Ordering::Relaxed);
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
            let payload = json!({
                "uptimeSec": uptime,
                "fetchedAt": fetched_at,
                "publishers": collector.publishers(),
            });
            write_json(&mut stream, 200, "OK", &payload.to_string())
        }
        _ => write_response(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}
