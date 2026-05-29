//! TLS Electrum/Fulcrum JSON-RPC client (blocking I/O, single-thread).
//!
//! Connection lifecycle: on construction, dial TCP → wrap in TLS → ready.
//! Per request: append `{...}\n` to the wire, then `read_line` for the response.
//! Auto-reconnect on disconnect is the caller's responsibility (the cycle
//! orchestrator catches `Disconnected` and retries).

use super::tls::tls_client_config;
use super::types::Utxo;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::Serialize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
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
}

/// Blocking JSON-RPC client over a single persistent TLS socket.
pub struct ElectrumClient {
    reader: BufReader<StreamOwned<ClientConnection, TcpStream>>,
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
    /// Open a TLS-wrapped JSON-RPC connection to a Fulcrum server. Blocks until
    /// the TLS handshake completes (or fails). Read/write timeouts apply to
    /// every subsequent request via the underlying TCP socket.
    pub fn connect(host: &str, port: u16, read_timeout: Duration) -> Result<Self, ElectrumError> {
        let addrs: Vec<_> = (host, port)
            .to_socket_addrs_compat()
            .map_err(|source| ElectrumError::Dns {
                host: host.to_string(),
                source,
            })?
            .collect();
        let tcp = TcpStream::connect_timeout(
            addrs.first().ok_or_else(|| ElectrumError::Dns {
                host: host.to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no address"),
            })?,
            read_timeout,
        )
        .map_err(|source| ElectrumError::Tcp {
            host: host.to_string(),
            port,
            source,
        })?;
        tcp.set_read_timeout(Some(read_timeout))?;
        tcp.set_write_timeout(Some(read_timeout))?;

        let config = tls_client_config();
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| ElectrumError::InvalidServerName(host.to_string()))?;
        let conn = ClientConnection::new(config, server_name)?;
        let tls = StreamOwned::new(conn, tcp);
        Ok(ElectrumClient {
            reader: BufReader::new(tls),
            next_id: AtomicU64::new(1),
        })
    }

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
        self.reader.get_mut().write_all(&buf)?;

        let mut line = String::new();
        let n = self.reader.read_line(&mut line)?;
        if n == 0 {
            return Err(ElectrumError::Disconnected);
        }
        let resp: Value = serde_json::from_str(line.trim_end())?;
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                return Err(ElectrumError::Rpc(err.to_string()));
            }
        }
        resp.get("result")
            .cloned()
            .ok_or(ElectrumError::BadShape)
    }

    /// `blockchain.address.listunspent` — BCH-Fulcrum extension returning UTXOs
    /// with CashTokens `token_data` attached.
    pub fn list_unspent(&mut self, address: &str) -> Result<Vec<Utxo>, ElectrumError> {
        let result = self.call("blockchain.address.listunspent", [address])?;
        Ok(serde_json::from_value(result)?)
    }

    /// `blockchain.transaction.broadcast` — submit a raw tx hex; returns txid.
    pub fn broadcast_raw_hex(&mut self, raw_hex: &str) -> Result<String, ElectrumError> {
        let result = self.call("blockchain.transaction.broadcast", [raw_hex])?;
        result.as_str().map(str::to_string).ok_or(ElectrumError::BadShape)
    }

    /// Convenience: `blockchain.transaction.broadcast` over a raw byte buffer.
    pub fn broadcast_raw(&mut self, raw: &[u8]) -> Result<String, ElectrumError> {
        let hex_str = hex::encode(raw);
        self.broadcast_raw_hex(&hex_str)
    }
}

// std's ToSocketAddrs is in `std::net::ToSocketAddrs`, but the trait method
// is `to_socket_addrs(&self)` — give it a friendlier alias to avoid the import
// gymnastics in `connect`.
trait ToSocketAddrsCompat {
    fn to_socket_addrs_compat(self) -> std::io::Result<std::vec::IntoIter<std::net::SocketAddr>>;
}

impl ToSocketAddrsCompat for (&str, u16) {
    fn to_socket_addrs_compat(self) -> std::io::Result<std::vec::IntoIter<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let v: Vec<_> = self.to_socket_addrs()?.collect();
        Ok(v.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct error variants without panicking — smoke-checks the error enum.
    #[test]
    fn error_construction_smoke() {
        let _ = ElectrumError::InvalidServerName("x".to_string());
        let _ = ElectrumError::Rpc("err".to_string());
    }

    /// Connection to a non-existent host fails with `Dns` or `Tcp` — no panic.
    #[test]
    fn unreachable_host_fails_cleanly() {
        let r = ElectrumClient::connect(
            "this-host-does-not-exist.invalid",
            50002,
            Duration::from_millis(500),
        );
        assert!(matches!(
            r,
            Err(ElectrumError::Dns { .. }) | Err(ElectrumError::Tcp { .. })
        ));
    }
}
