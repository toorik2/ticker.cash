//! Tiny plain-HTTP GET client for the notaries' statement APIs (no TLS, no keep-alive).

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ticker_core::httpx::parse_response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// `base` is `http://host:port`; returns the body of a 200 response.
pub async fn get(base: &str, path: &str, timeout: Duration) -> Result<Vec<u8>> {
    get_opt(base, path, timeout).await?.ok_or_else(|| anyhow!("{base}{path}: HTTP 404"))
}

/// Like [`get`], but a 404 is `Ok(None)`: a notary that has issued nothing yet answers 404 to
/// `/v1/latest`, which is a state, not a failure.
pub async fn get_opt(base: &str, path: &str, timeout: Duration) -> Result<Option<Vec<u8>>> {
    let hp = base.strip_prefix("http://").ok_or_else(|| anyhow!("api base must start with http://: {base}"))?;
    let host = hp.split(':').next().unwrap_or(hp);
    let mut sock = tokio::time::timeout(timeout, TcpStream::connect(hp)).await.context("connect timeout")??;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n");
    sock.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(4096);
    tokio::time::timeout(timeout, sock.read_to_end(&mut buf)).await.context("read timeout")??;
    let resp = parse_response(&buf)?;
    match resp.status {
        200 => Ok(Some(resp.body)),
        404 => Ok(None),
        s => bail!("{base}{path}: HTTP {s}: {}", String::from_utf8_lossy(&resp.body)),
    }
}

pub async fn get_json<T: serde::de::DeserializeOwned>(base: &str, path: &str, timeout: Duration) -> Result<T> {
    let body = get(base, path, timeout).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// [`get_json`] with the 404 → `Ok(None)` rule of [`get_opt`].
pub async fn get_json_opt<T: serde::de::DeserializeOwned>(base: &str, path: &str, timeout: Duration) -> Result<Option<T>> {
    match get_opt(base, path, timeout).await? {
        Some(body) => Ok(Some(serde_json::from_slice(&body)?)),
        None => Ok(None),
    }
}
