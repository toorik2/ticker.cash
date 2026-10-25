//! HTTPS GET for the notary's exchange fetch, and minimal HTTP/1.1 parsing.
//!
//! The notary opens its own TLS session to the pinned host, validates the certificate chain
//! against the Mozilla roots (rustls, TLS 1.2 or 1.3), sends one `GET`, reads to the end and
//! parses status and body (de-chunked, identity-encoded). No compression is requested, so none is
//! sent. The response is capped at one megabyte.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("DNS resolution failed for {0}")]
    Dns(String),
    #[error("TCP connect to {host}:443 failed: {err}")]
    Connect { host: String, err: String },
    #[error("TLS: {0}")]
    Tls(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("response exceeds {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("HTTP: {0}")]
    Http(#[from] HttpError),
}

/// `GET https://{host}{path}` with certificate validation; returns status and body.
pub fn fetch_https(host: &str, path: &str, timeout: Duration) -> Result<Response, FetchError> {
    let addrs: Vec<_> = (host, 443u16).to_socket_addrs().map_err(|e| FetchError::Dns(format!("{host}: {e}")))?.collect();
    let mut tcp = None;
    let mut last: Option<std::io::Error> = None;
    for a in &addrs {
        match TcpStream::connect_timeout(a, timeout) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| FetchError::Connect { host: host.to_string(), err: last.map(|e| e.to_string()).unwrap_or_else(|| "no address".into()) })?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true)?;
    let name = ServerName::try_from(host.to_string()).map_err(|_| FetchError::Tls(format!("invalid server name {host}")))?;
    let conn = ClientConnection::new(crate::electrum::tls::tls_client_config(), name).map_err(|e| FetchError::Tls(e.to_string()))?;
    let mut tls = StreamOwned::new(conn, tcp);
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ticker-notary/26\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).map_err(|e| FetchError::Tls(e.to_string()))?;
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 8192];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE_BYTES {
                    return Err(FetchError::TooLarge);
                }
            }
            // a peer that closes without close_notify still delivered a complete response
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(FetchError::Io(e)),
        }
    }
    Ok(parse_response(&buf)?)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpError {
    #[error("no header terminator")]
    NoHeaderEnd,
    #[error("malformed start line")]
    StartLine,
    #[error("status code is not numeric")]
    Status,
    #[error("malformed chunked body")]
    Chunked,
    #[error("body shorter than Content-Length")]
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

fn split_head(raw: &[u8]) -> Result<(&[u8], &[u8]), HttpError> {
    let pos = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or(HttpError::NoHeaderEnd)?;
    Ok((&raw[..pos], &raw[pos + 4..]))
}

fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

pub fn parse_request(raw: &[u8]) -> Result<Request, HttpError> {
    let (head, _) = split_head(raw)?;
    let text = std::str::from_utf8(head).map_err(|_| HttpError::StartLine)?;
    let first = text.lines().next().ok_or(HttpError::StartLine)?;
    let mut parts = first.split(' ');
    let method = parts.next().ok_or(HttpError::StartLine)?.to_string();
    let target = parts.next().ok_or(HttpError::StartLine)?.to_string();
    let host = header_value(head, "host").map(|h| h.to_ascii_lowercase());
    Ok(Request { method, target, host })
}

pub fn parse_response(raw: &[u8]) -> Result<Response, HttpError> {
    let (head, rest) = split_head(raw)?;
    let text = std::str::from_utf8(head).map_err(|_| HttpError::StartLine)?;
    let first = text.lines().next().ok_or(HttpError::StartLine)?;
    let status: u16 = first.split(' ').nth(1).ok_or(HttpError::StartLine)?.parse().map_err(|_| HttpError::Status)?;
    let chunked = header_value(head, "transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
    let body = if chunked {
        dechunk(rest)?
    } else if let Some(len) = header_value(head, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        if rest.len() < len {
            return Err(HttpError::Truncated);
        }
        rest[..len].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Response { status, body })
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::with_capacity(rest.len());
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n").ok_or(HttpError::Chunked)?;
        let size_line = std::str::from_utf8(&rest[..eol]).map_err(|_| HttpError::Chunked)?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| HttpError::Chunked)?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size + 2 {
            return Err(HttpError::Chunked);
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_and_host() {
        let r = parse_request(b"GET /v2/prices/BCH-USD/spot HTTP/1.1\r\nhost: API.coinbase.com\r\nconnection: close\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/v2/prices/BCH-USD/spot");
        assert_eq!(r.host.as_deref(), Some("api.coinbase.com"));
    }

    #[test]
    fn content_length_body() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5\r\n\r\n{\"a\":1}").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{\"a\":");
    }

    #[test]
    fn chunked_body_as_seen_from_okx_and_independent_reserve() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"{\"a\":1}");
    }

    #[test]
    fn no_length_takes_rest() {
        let r = parse_response(b"HTTP/1.1 404 Not Found\r\n\r\nnope").unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"nope");
    }

    #[test]
    fn malformed() {
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").unwrap_err(), HttpError::Truncated);
        assert_eq!(parse_response(b"garbage").unwrap_err(), HttpError::NoHeaderEnd);
        assert_eq!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").unwrap_err(), HttpError::Chunked);
    }
}
