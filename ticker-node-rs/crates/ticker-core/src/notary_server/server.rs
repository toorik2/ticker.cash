//! TCP listener + dispatch loop.
//!
//! `run_notary_server(addr, handler)` blocks until shutdown, accepting connections
//! and dispatching each to `handler` on a fresh thread. Per-conn lifetime is short:
//! read request → invoke handler → write response → close.

use serde_json::json;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::http::{read_request, write_json, write_response};
use super::wire::{SignRequest, SignResponse};

/// Process-lifetime sign-request counter — surfaced by /stats.
pub static SIGN_REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);

/// What the server invokes for each `POST /sign`.
pub trait NotaryHandler: Send + Sync + 'static {
    /// Should return the response payload, or an error string for a 400/500.
    fn sign(&self, req: SignRequest) -> Result<SignResponse, String>;

    /// Health body — JSON `{"ok": true, ...}` returned for `GET /health`.
    fn health(&self) -> serde_json::Value;
}

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error("bind {addr} failed: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
}

/// Run the notary server. Blocks indefinitely. Each accepted connection runs
/// on its own thread so a slow CEX upstream cannot stall other publishers.
pub fn run_notary_server<H: NotaryHandler + 'static>(
    addr: &str,
    handler: Arc<H>,
) -> Result<(), NotaryServerError> {
    let listener = TcpListener::bind(addr).map_err(|source| NotaryServerError::Bind {
        addr: addr.to_string(),
        source,
    })?;
    crate::log_info!("notary server listening", "addr" => addr);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                crate::log_warn!("notary accept error", "msg" => e.to_string());
                continue;
            }
        };
        let h = handler.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve_one(stream, h.as_ref()) {
                crate::log_warn!("notary conn error", "msg" => e.to_string());
            }
        });
    }
    Ok(())
}

fn serve_one<H: NotaryHandler>(mut stream: TcpStream, handler: &H) -> std::io::Result<()> {
    let req = match read_request(&mut stream) {
        Ok(r) => r,
        Err(e) => {
            let body = json!({"error": format!("bad request: {e}")}).to_string();
            return write_json(&mut stream, 400, "Bad Request", &body);
        }
    };
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/health") => {
            let body = handler.health().to_string();
            write_json(&mut stream, 200, "OK", &body)
        }
        ("POST", "/sign") => {
            let parsed: Result<SignRequest, _> = serde_json::from_slice(&req.body);
            match parsed {
                Ok(sign_req) => match handler.sign(sign_req) {
                    Ok(resp) => {
                        SIGN_REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);
                        let body = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
                        write_json(&mut stream, 200, "OK", &body)
                    }
                    Err(msg) => {
                        let body = json!({"error": msg}).to_string();
                        write_json(&mut stream, 500, "Internal Server Error", &body)
                    }
                },
                Err(e) => {
                    let body = json!({"error": format!("bad body: {e}")}).to_string();
                    write_json(&mut stream, 400, "Bad Request", &body)
                }
            }
        }
        ("OPTIONS", _) => write_response(&mut stream, 204, "No Content", "text/plain", b""),
        _ => write_response(&mut stream, 404, "Not Found", "text/plain", b"not found"),
    }
}
