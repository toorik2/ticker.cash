//! Minimal HTTP/1.1 parsing for revealed TLS transcripts.
//!
//! The notary sees the raw bytes the prover sent and the raw bytes the server returned. It needs
//! four facts from them: the request line and `Host` header (to pin the endpoint), the response
//! status, and the response body (de-chunked, identity-encoded) for price extraction.

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
