//! TLS Electrum/Fulcrum JSON-RPC client with auto-reconnect + multi-endpoint
//! failover.
//!
//! Holds an ordered pool of endpoints (primary first, then fallbacks). Each
//! request goes to the currently-connected endpoint; on any I/O failure
//! (broken pipe, EOF, timeout, reset, …) the client transparently dials the
//! next endpoint in the pool and retries the same request once. Caller code
//! sees either a successful response or `AllEndpointsDown` after the full
//! pool has been tried.
//!
//! Reconnect/failover happens inside `call()` — callers do not need to catch
//! disconnect errors and recreate the client.

use super::tls::tls_client_config_from_env;
use super::types::Utxo;
use crate::log_warn;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::Serialize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ElectrumError {
    #[error("DNS resolution failed for {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP connect to {host}:{port} failed: {source}")]
    Tcp {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("TLS server name invalid for {0}")]
    InvalidServerName(String),
    #[error("Electrum disconnected")]
    Disconnected,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON-RPC: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Electrum error response: {0}")]
    Rpc(String),
    #[error("unexpected response shape")]
    BadShape,
    #[error("all {tried} endpoints unreachable: {last}")]
    AllEndpointsDown { tried: usize, last: String },
    #[error("electrum response line exceeded {0}-byte cap")]
    ResponseTooLarge(u64),
}

/// Hard cap on a single JSON-RPC response line. Realistic chipnet responses
/// are well under 100 KB; 8 MiB is a defensive ceiling against trickle-OOM.
const MAX_RESPONSE_LINE: u64 = 8 * 1024 * 1024;

/// One TLS-wrapped Fulcrum endpoint in the failover pool.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self { host: host.into(), port }
    }
}

type Stream = BufReader<StreamOwned<ClientConnection, TcpStream>>;

/// Blocking JSON-RPC client with an ordered endpoint pool.
pub struct ElectrumClient {
    endpoints: Vec<Endpoint>,
    /// Index of the currently-connected endpoint (when `conn.is_some()`).
    current: usize,
    timeout: Duration,
    conn: Option<Stream>,
    next_id: AtomicU64,
}

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

impl ElectrumClient {
    /// Single-endpoint convenience: dial one Fulcrum, no fallbacks. Kept for
    /// ops/* tools whose use is one-shot.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, ElectrumError> {
        Self::connect_pool(vec![Endpoint::new(host, port)], timeout)
    }

    /// Multi-endpoint constructor. Tries endpoints in order; the first one
    /// that dials successfully becomes the active connection. Errors with
    /// `AllEndpointsDown` if every endpoint fails.
    pub fn connect_pool(
        endpoints: Vec<Endpoint>,
        timeout: Duration,
    ) -> Result<Self, ElectrumError> {
        if endpoints.is_empty() {
            return Err(ElectrumError::AllEndpointsDown {
                tried: 0,
                last: "empty endpoint pool".to_string(),
            });
        }
        let mut last_err: Option<String> = None;
        for (idx, ep) in endpoints.iter().enumerate() {
            match Self::dial(&ep.host, ep.port, timeout) {
                Ok(conn) => {
                    return Ok(Self {
                        endpoints,
                        current: idx,
                        timeout,
                        conn: Some(conn),
                        next_id: AtomicU64::new(1),
                    });
                }
                Err(e) => {
                    log_warn!(
                        "electrum: endpoint dial failed",
                        "host" => &ep.host,
                        "port" => ep.port,
                        "err" => e.to_string(),
                    );
                    last_err = Some(e.to_string());
                }
            }
        }
        Err(ElectrumError::AllEndpointsDown {
            tried: endpoints.len(),
            last: last_err.unwrap_or_else(|| "no error captured".to_string()),
        })
    }

    /// Open a single TLS-wrapped connection. No state changes; pure factory.
    /// Tries each resolved IP in turn — a DNS-balanced host with one bad
    /// backend still connects so long as at least one IP is reachable.
    fn dial(host: &str, port: u16, timeout: Duration) -> Result<Stream, ElectrumError> {
        let addrs: Vec<_> = (host, port)
            .to_socket_addrs()
            .map_err(|source| ElectrumError::Dns {
                host: host.to_string(),
                source,
            })?
            .collect();
        if addrs.is_empty() {
            return Err(ElectrumError::Dns {
                host: host.to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no address"),
            });
        }
        let mut last_err: Option<std::io::Error> = None;
        let mut tcp: Option<TcpStream> = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, timeout) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| ElectrumError::Tcp {
            host: host.to_string(),
            port,
            source: last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "no addresses tried")
            }),
        })?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        let config = tls_client_config_from_env();
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| ElectrumError::InvalidServerName(host.to_string()))?;
        let conn = ClientConnection::new(config, server_name)?;
        Ok(BufReader::new(StreamOwned::new(conn, tcp)))
    }

    /// Send a request on the current connection; if it fails with a
    /// connection-fatal error, fail over through the endpoint pool starting
    /// at the next endpoint and retry the same wire bytes once. Returns the
    /// successful response, or `AllEndpointsDown` if every endpoint fails.
    fn call<P: Serialize>(&mut self, method: &str, params: P) -> Result<Value, ElectrumError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');

        // First attempt — current connection.
        match self.send_recv(&buf) {
            Ok(v) => return Ok(v),
            Err(e) if !is_connection_error(&e) => return Err(e),
            Err(e) => {
                log_warn!(
                    "electrum: request failed, will fail over",
                    "method" => method,
                    "host" => &self.endpoints[self.current].host,
                    "err" => e.to_string(),
                );
                self.conn = None;
            }
        }

        // Reconnect path: try every endpoint, starting from the one AFTER
        // the failing current (so we don't immediately re-hit the bad host).
        let n = self.endpoints.len();
        let mut last_err: Option<String> = None;
        for offset in 1..=n {
            let idx = (self.current + offset) % n;
            let ep = self.endpoints[idx].clone();
            match Self::dial(&ep.host, ep.port, self.timeout) {
                Ok(conn) => {
                    self.conn = Some(conn);
                    self.current = idx;
                    if idx != 0 {
                        log_warn!(
                            "electrum: failed over to fallback",
                            "host" => &ep.host,
                            "port" => ep.port,
                            "primary" => &self.endpoints[0].host,
                        );
                    }
                    // Retry the original request on the new connection.
                    return self.send_recv(&buf);
                }
                Err(e) => {
                    log_warn!(
                        "electrum: failover dial failed",
                        "host" => &ep.host,
                        "port" => ep.port,
                        "err" => e.to_string(),
                    );
                    last_err = Some(e.to_string());
                }
            }
        }
        Err(ElectrumError::AllEndpointsDown {
            tried: n,
            last: last_err.unwrap_or_else(|| "no error captured".to_string()),
        })
    }

    /// Wire-level send + receive on the current connection. No retry logic.
    /// Bounds the JSON-RPC response line at MAX_RESPONSE_LINE — a hostile
    /// or MITM'd Electrum cannot OOM us by trickling gigabytes without a
    /// newline. The bound goes through `Take<BufRead>` so that `read_line`
    /// still terminates at the newline (and reports EOF correctly), unlike
    /// `read_to_string` which only returns on close.
    fn send_recv(&mut self, buf: &[u8]) -> Result<Value, ElectrumError> {
        let reader = self.conn.as_mut().ok_or(ElectrumError::Disconnected)?;
        reader.get_mut().write_all(buf)?;
        let mut line = String::new();
        let n = reader.by_ref().take(MAX_RESPONSE_LINE).read_line(&mut line)?;
        if n == 0 {
            return Err(ElectrumError::Disconnected);
        }
        if !line.ends_with('\n') {
            // Hit the cap before seeing a newline — runaway response.
            return Err(ElectrumError::ResponseTooLarge(MAX_RESPONSE_LINE));
        }
        let resp: Value = serde_json::from_str(line.trim_end())?;
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                return Err(ElectrumError::Rpc(err.to_string()));
            }
        }
        resp.get("result").cloned().ok_or(ElectrumError::BadShape)
    }

    /// Returns `(host, port)` of the endpoint currently bearing traffic.
    /// Useful for diagnostics and tests.
    pub fn current_endpoint(&self) -> (&str, u16) {
        let ep = &self.endpoints[self.current];
        (&ep.host, ep.port)
    }

    /// `blockchain.address.listunspent` — BCH-Fulcrum extension returning UTXOs
    /// with CashTokens `token_data` attached.
    pub fn list_unspent(&mut self, address: &str) -> Result<Vec<Utxo>, ElectrumError> {
        let result = self.call("blockchain.address.listunspent", [address])?;
        Ok(serde_json::from_value(result)?)
    }

    /// `blockchain.scripthash.listunspent` with `include_tokens` hint —
    /// scripthash form is what Fulcrum honours for CashTokens-bearing addresses
    /// (the `address.listunspent` path returns empty for token-aware addresses
    /// against current chipnet servers).
    pub fn list_unspent_by_scripthash(
        &mut self,
        scripthash_hex: &str,
    ) -> Result<Vec<Utxo>, ElectrumError> {
        let result = self.call(
            "blockchain.scripthash.listunspent",
            [scripthash_hex, "include_tokens"],
        )?;
        Ok(serde_json::from_value(result)?)
    }

    /// `blockchain.transaction.broadcast` — submit a raw tx hex; returns txid.
    pub fn broadcast_raw_hex(&mut self, raw_hex: &str) -> Result<String, ElectrumError> {
        let result = self.call("blockchain.transaction.broadcast", [raw_hex])?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or(ElectrumError::BadShape)
    }

    /// Convenience: `blockchain.transaction.broadcast` over a raw byte buffer.
    pub fn broadcast_raw(&mut self, raw: &[u8]) -> Result<String, ElectrumError> {
        let hex_str = hex::encode(raw);
        self.broadcast_raw_hex(&hex_str)
    }
}

/// Classify an error as connection-fatal (warrants reconnect/failover) vs
/// caller-fatal (warrants bubbling up unchanged). I/O errors of any kind,
/// EOF (`Disconnected`), and JSON-parse errors (often a sign the response
/// was truncated mid-flight) trigger the reconnect path. RPC-level errors
/// (server understood and rejected the request) and shape errors stay.
fn is_connection_error(e: &ElectrumError) -> bool {
    matches!(
        e,
        ElectrumError::Disconnected
            | ElectrumError::Io(_)
            | ElectrumError::Json(_)
            | ElectrumError::Tcp { .. }
            | ElectrumError::Dns { .. }
            | ElectrumError::Tls(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct error variants without panicking — smoke-checks the error enum.
    #[test]
    fn error_construction_smoke() {
        let _ = ElectrumError::InvalidServerName("x".to_string());
        let _ = ElectrumError::Rpc("err".to_string());
        let _ = ElectrumError::AllEndpointsDown {
            tried: 3,
            last: "x".to_string(),
        };
    }

    /// Single-endpoint connect to a non-existent host fails with
    /// `AllEndpointsDown` (the new constructor wraps the underlying
    /// Dns/Tcp error).
    #[test]
    fn unreachable_host_fails_with_pool_error() {
        let r = ElectrumClient::connect(
            "this-host-does-not-exist.invalid",
            50002,
            Duration::from_millis(500),
        );
        assert!(matches!(r, Err(ElectrumError::AllEndpointsDown { tried: 1, .. })));
    }

    /// Pool of all-unreachable hosts reports `AllEndpointsDown` with
    /// `tried = pool_size`.
    #[test]
    fn pool_all_unreachable() {
        let pool = vec![
            Endpoint::new("nope-1.invalid", 50002),
            Endpoint::new("nope-2.invalid", 50002),
            Endpoint::new("nope-3.invalid", 50002),
        ];
        let r = ElectrumClient::connect_pool(pool, Duration::from_millis(300));
        match r {
            Err(ElectrumError::AllEndpointsDown { tried, .. }) => assert_eq!(tried, 3),
            Err(e) => panic!("expected AllEndpointsDown(3), got Err({e})"),
            Ok(_) => panic!("expected AllEndpointsDown(3), got Ok"),
        }
    }

    /// Empty pool rejected immediately.
    #[test]
    fn empty_pool_rejected() {
        let r = ElectrumClient::connect_pool(vec![], Duration::from_millis(100));
        assert!(matches!(r, Err(ElectrumError::AllEndpointsDown { tried: 0, .. })));
    }

    /// Connection-error classifier — sanity-check the matrix.
    #[test]
    fn classifier_matrix() {
        assert!(is_connection_error(&ElectrumError::Disconnected));
        assert!(is_connection_error(&ElectrumError::Io(std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        ))));
        assert!(!is_connection_error(&ElectrumError::Rpc("x".into())));
        assert!(!is_connection_error(&ElectrumError::BadShape));
        assert!(!is_connection_error(&ElectrumError::InvalidServerName("x".into())));
    }
}
