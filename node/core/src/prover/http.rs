//! Tiny blocking HTTPS GET — TLS-only, HTTP/1.0 request, single round trip.
//!
//! Sized for the 13 CEX endpoints the publisher fetches once per cycle. ~120 LOC,
//! no keepalive, no redirects, no compression, no chunked-transfer-encoding
//! (none of the target endpoints use any of those for `/ticker`-style endpoints
//! over HTTPS in 2026).
//!
//! Caller responsibilities:
//!   * Provide a TLS-capable host (cleartext HTTP is intentionally unsupported).
//!   * Supply a sane timeout — applied both as a per-syscall budget AND as a
//!     wall-clock deadline so a slow-trickling endpoint cannot outrun it.

use crate::electrum::tls::tls_client_config;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Hard cap on the HTTPS response body we'll buffer. The CEX endpoints return
/// a few hundred bytes of JSON; this exists purely to bound RAM if a hostile
/// or buggy endpoint trickles unbounded data.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("URL parse failed: {0}")]
    BadUrl(String),
    #[error("DNS resolution for {host}: {source}")]
    Dns {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("TCP connect to {host}:{port}: {source}")]
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
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP non-2xx status: {0}")]
    Status(u16),
    #[error("response exceeded {0}-byte budget")]
    ResponseTooLarge(usize),
    #[error("deadline elapsed before response complete")]
    Deadline,
    #[error("malformed HTTP response")]
    Malformed,
}

/// Issue a single HTTPS GET. Returns `(status, body)`. `timeout` applies as
/// both a per-syscall budget AND a wall-clock deadline so a server that
/// trickles a few bytes per timeout-window cannot outrun the budget.
pub fn https_get(url: &str, timeout: Duration) -> Result<(u16, String), HttpError> {
    let deadline = Instant::now() + timeout;
    let (host, port, path) = parse_https_url(url)?;

    // Resolve every A/AAAA record and try each in turn until one connects.
    let addrs: Vec<_> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|source| HttpError::Dns {
            host: host.clone(),
            source,
        })?
        .collect();
    if addrs.is_empty() {
        return Err(HttpError::Dns {
            host: host.clone(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no address"),
        });
    }
    let mut last_err: Option<std::io::Error> = None;
    let mut tcp: Option<TcpStream> = None;
    for addr in &addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(addr, remaining) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| HttpError::Tcp {
        host: host.clone(),
        port,
        source: last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline before connect")
        }),
    })?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let config = tls_client_config();
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| HttpError::InvalidServerName(host.clone()))?;
    let conn = ClientConnection::new(config, server_name)?;
    let mut tls = StreamOwned::new(conn, tcp);
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: ticker-node-rs/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())?;
    tls.flush()?;
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err(HttpError::Deadline);
        }
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(HttpError::ResponseTooLarge(MAX_RESPONSE_BYTES));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => break,
            Err(e) => return Err(e.into()),
        }
    }
    parse_response(&buf)
}

fn parse_https_url(url: &str) -> Result<(String, u16, String), HttpError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| HttpError::BadUrl("not https://".to_string()))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse()
                .map_err(|_| HttpError::BadUrl(format!("bad port {p:?}")))?,
        ),
        None => (authority.to_string(), 443u16),
    };
    Ok((host, port, path.to_string()))
}

fn parse_response(buf: &[u8]) -> Result<(u16, String), HttpError> {
    let crlf2 = b"\r\n\r\n";
    let head_end = buf
        .windows(crlf2.len())
        .position(|w| w == crlf2)
        .ok_or(HttpError::Malformed)?;
    let head =
        std::str::from_utf8(&buf[..head_end]).map_err(|_| HttpError::Malformed)?;
    let body_start = head_end + crlf2.len();
    let body = String::from_utf8_lossy(&buf[body_start..]).into_owned();

    let status_line = head.lines().next().ok_or(HttpError::Malformed)?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next().ok_or(HttpError::Malformed)?;
    let status: u16 = parts
        .next()
        .ok_or(HttpError::Malformed)?
        .parse()
        .map_err(|_| HttpError::Malformed)?;
    if !(200..300).contains(&status) {
        return Err(HttpError::Status(status));
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_url_with_path() {
        let (h, p, path) = parse_https_url("https://api.example.com/v1/foo").unwrap();
        assert_eq!(h, "api.example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/v1/foo");
    }

    #[test]
    fn parse_https_url_with_port() {
        let (h, p, path) = parse_https_url("https://api.example.com:8443/x").unwrap();
        assert_eq!(h, "api.example.com");
        assert_eq!(p, 8443);
        assert_eq!(path, "/x");
    }

    #[test]
    fn parse_https_url_no_path() {
        let (h, p, path) = parse_https_url("https://api.example.com").unwrap();
        assert_eq!(h, "api.example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_https_url_rejects_plain_http() {
        assert!(matches!(
            parse_https_url("http://example.com"),
            Err(HttpError::BadUrl(_))
        ));
    }

    #[test]
    fn parse_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"foo\":1}";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "{\"foo\":1}");
    }

    #[test]
    fn parse_response_non_2xx_errors() {
        let raw = b"HTTP/1.1 503 Service Unavailable\r\n\r\nfail";
        assert!(matches!(parse_response(raw), Err(HttpError::Status(503))));
    }
}
