//! Minimal HTTP/1.1 request parsing + response writing.
//!
//! Shared by the `/stats` server (the only HTTP server left after v13 dropped
//! the notary tier). Covers the subset we need:
//!   * Read request line + headers + (optional) `Content-Length`-bounded body.
//!   * Write a single response with status line + `Content-Type` + body.
//!
//! No chunked transfer encoding, no keep-alive (close after each response),
//! no compression. The endpoints are local with small responses.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

/// Parsed HTTP request — minimal fields we need to handle.
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("malformed request line")]
    BadRequestLine,
    #[error("invalid Content-Length: {0}")]
    BadContentLength(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Read + parse one HTTP/1.x request from `stream`.
pub fn read_request(stream: &mut TcpStream) -> Result<Request, HttpError> {
    // Wrap a copy of the stream for buffered reads.
    let read_stream = stream.try_clone()?;
    let mut reader = BufReader::new(read_stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpError::BadRequestLine)?.to_string();
    let path = parts.next().ok_or(HttpError::BadRequestLine)?.to_string();

    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        let n = reader.read_line(&mut header)?;
        if n == 0 || header == "\r\n" || header == "\n" {
            break;
        }
        let lower = header.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest
                .trim()
                .parse()
                .map_err(|_| HttpError::BadContentLength(rest.trim().to_string()))?;
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Request { method, path, body })
}

/// Write a single HTTP response.
pub fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {len}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        len = body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Convenience: write a JSON body.
pub fn write_json(stream: &mut TcpStream, status: u16, reason: &str, json: &str) -> std::io::Result<()> {
    write_response(stream, status, reason, "application/json", json.as_bytes())
}
