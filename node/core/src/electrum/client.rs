//! Blocking JSON-RPC client for Fulcrum with an ordered endpoint pool and transparent failover.
//!
//! Each endpoint is TLS or plain TCP (`tls: false`, for an operator's own Fulcrum on a private
//! network). On any connection-level failure the client dials the next endpoint and retries the
//! request once. The index of the last endpoint that answered is remembered process-wide, so a
//! dead endpoint costs one connect timeout per process, not one per call.

use super::tls::tls_client_config_from_env;
use super::types::Utxo;
use crate::log_warn;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::Serialize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ElectrumError {
    #[error("DNS resolution failed for {host}: {source}")]
    Dns { host: String, #[source] source: std::io::Error },
    #[error("TCP connect to {host}:{port} failed: {source}")]
    Tcp { host: String, port: u16, #[source] source: std::io::Error },
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

const MAX_RESPONSE_LINE: u64 = 8 * 1024 * 1024;
/// TCP connect budget; a healthy Fulcrum accepts in milliseconds, a dead address should not cost the I/O timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Index (into the pool as configured) of the endpoint that last answered.
static PREFERRED: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16, tls: bool) -> Self {
        Self { host: host.into(), port, tls }
    }
}

enum Stream {
    Tls(BufReader<StreamOwned<ClientConnection, TcpStream>>),
    Plain(BufReader<TcpStream>),
}

impl Stream {
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Stream::Tls(s) => s.get_mut().write_all(buf),
            Stream::Plain(s) => s.get_mut().write_all(buf),
        }
    }
    fn read_line_capped(&mut self, line: &mut String) -> std::io::Result<usize> {
        match self {
            Stream::Tls(s) => s.by_ref().take(MAX_RESPONSE_LINE).read_line(line),
            Stream::Plain(s) => s.by_ref().take(MAX_RESPONSE_LINE).read_line(line),
        }
    }
}

pub struct ElectrumClient {
    endpoints: Vec<Endpoint>,
    current: usize,
    timeout: Duration,
    conn: Option<Stream>,
    next_id: u64,
}

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: P,
}

impl ElectrumClient {
    pub fn connect_pool(endpoints: Vec<Endpoint>, timeout: Duration) -> Result<Self, ElectrumError> {
        if endpoints.is_empty() {
            return Err(ElectrumError::AllEndpointsDown { tried: 0, last: "empty endpoint pool".into() });
        }
        let mut last_err: Option<String> = None;
        let n = endpoints.len();
        let start = PREFERRED.load(Ordering::Relaxed) % n;
        for offset in 0..n {
            let idx = (start + offset) % n;
            let ep = &endpoints[idx];
            match Self::dial(ep, timeout) {
                Ok(conn) => {
                    PREFERRED.store(idx, Ordering::Relaxed);
                    return Ok(Self { endpoints, current: idx, timeout, conn: Some(conn), next_id: 1 });
                }
                Err(e) => {
                    log_warn!("electrum: endpoint dial failed", "host" => &ep.host, "port" => ep.port, "err" => e.to_string());
                    last_err = Some(e.to_string());
                }
            }
        }
        Err(ElectrumError::AllEndpointsDown { tried: endpoints.len(), last: last_err.unwrap_or_default() })
    }

    fn dial(ep: &Endpoint, timeout: Duration) -> Result<Stream, ElectrumError> {
        let addrs: Vec<_> = (ep.host.as_str(), ep.port)
            .to_socket_addrs()
            .map_err(|source| ElectrumError::Dns { host: ep.host.clone(), source })?
            .collect();
        let mut last_err: Option<std::io::Error> = None;
        let mut tcp: Option<TcpStream> = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, timeout.min(CONNECT_TIMEOUT)) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| ElectrumError::Tcp {
            host: ep.host.clone(),
            port: ep.port,
            source: last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address")),
        })?;
        tcp.set_read_timeout(Some(timeout))?;
        tcp.set_write_timeout(Some(timeout))?;
        tcp.set_nodelay(true)?;
        if ep.tls {
            let config = tls_client_config_from_env();
            let server_name = ServerName::try_from(ep.host.clone()).map_err(|_| ElectrumError::InvalidServerName(ep.host.clone()))?;
            let conn = ClientConnection::new(config, server_name)?;
            Ok(Stream::Tls(BufReader::new(StreamOwned::new(conn, tcp))))
        } else {
            Ok(Stream::Plain(BufReader::new(tcp)))
        }
    }

    fn call<P: Serialize>(&mut self, method: &str, params: P) -> Result<Value, ElectrumError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = RpcRequest { jsonrpc: "2.0", id, method, params };
        let mut buf = serde_json::to_vec(&req)?;
        buf.push(b'\n');
        match self.send_recv(&buf) {
            Ok(v) => return Ok(v),
            Err(e) if !is_connection_error(&e) => return Err(e),
            Err(e) => {
                log_warn!("electrum: request failed, failing over", "method" => method, "host" => &self.endpoints[self.current].host, "err" => e.to_string());
                self.conn = None;
            }
        }
        let n = self.endpoints.len();
        let mut last_err: Option<String> = None;
        for offset in 1..=n {
            let idx = (self.current + offset) % n;
            let ep = self.endpoints[idx].clone();
            match Self::dial(&ep, self.timeout) {
                Ok(conn) => {
                    self.conn = Some(conn);
                    self.current = idx;
                    PREFERRED.store(idx, Ordering::Relaxed);
                    return self.send_recv(&buf);
                }
                Err(e) => last_err = Some(e.to_string()),
            }
        }
        Err(ElectrumError::AllEndpointsDown { tried: n, last: last_err.unwrap_or_default() })
    }

    fn send_recv(&mut self, buf: &[u8]) -> Result<Value, ElectrumError> {
        let stream = self.conn.as_mut().ok_or(ElectrumError::Disconnected)?;
        stream.write_all(buf)?;
        let mut line = String::new();
        let n = stream.read_line_capped(&mut line)?;
        if n == 0 {
            return Err(ElectrumError::Disconnected);
        }
        if !line.ends_with('\n') {
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

    pub fn current_endpoint(&self) -> (&str, u16) {
        let ep = &self.endpoints[self.current];
        (&ep.host, ep.port)
    }

    /// `blockchain.scripthash.listunspent` with CashTokens data.
    pub fn list_unspent_by_scripthash(&mut self, scripthash_hex: &str) -> Result<Vec<Utxo>, ElectrumError> {
        let result = self.call("blockchain.scripthash.listunspent", [scripthash_hex, "include_tokens"])?;
        Ok(serde_json::from_value(result)?)
    }

    pub fn broadcast_raw(&mut self, raw: &[u8]) -> Result<String, ElectrumError> {
        let result = self.call("blockchain.transaction.broadcast", [hex::encode(raw)])?;
        result.as_str().map(str::to_string).ok_or(ElectrumError::BadShape)
    }

    /// Current tip height via `blockchain.headers.subscribe` (one-shot; we never read pushes).
    pub fn tip_height(&mut self) -> Result<u64, ElectrumError> {
        let result = self.call("blockchain.headers.subscribe", Vec::<String>::new())?;
        result.get("height").and_then(|h| h.as_u64()).ok_or(ElectrumError::BadShape)
    }

    pub fn transaction_hex(&mut self, txid_hex: &str) -> Result<String, ElectrumError> {
        let result = self.call("blockchain.transaction.get", [txid_hex])?;
        result.as_str().map(str::to_string).ok_or(ElectrumError::BadShape)
    }
}

fn is_connection_error(e: &ElectrumError) -> bool {
    matches!(e, ElectrumError::Disconnected | ElectrumError::Io(_) | ElectrumError::Json(_) | ElectrumError::Tcp { .. } | ElectrumError::Dns { .. } | ElectrumError::Tls(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_pool_reports_count() {
        let pool = vec![Endpoint::new("nope-1.invalid", 50002, true), Endpoint::new("nope-2.invalid", 50001, false)];
        match ElectrumClient::connect_pool(pool, Duration::from_millis(300)) {
            Err(ElectrumError::AllEndpointsDown { tried, .. }) => assert_eq!(tried, 2),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn classifier() {
        assert!(is_connection_error(&ElectrumError::Disconnected));
        assert!(!is_connection_error(&ElectrumError::Rpc("x".into())));
    }
}

impl std::fmt::Debug for ElectrumClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElectrumClient").field("endpoint", &self.current_endpoint()).finish()
    }
}
