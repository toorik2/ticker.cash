//! The prover: once a minute, open a TLSNotary session with each row's notary, fetch the
//! pinned endpoint through it, reveal everything, and let the notary sign. The prover holds no
//! key; a failed row is just a missing statement for that minute.

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use ticker_core::commit::current_minute;
use ticker_core::manifest::TableRow;
use ticker_core::sources::{source_by_id, Source};
use ticker_core::statement::Statement;
use ticker_core::{log_info, log_warn};
use tlsn::config::prove::ProveConfig;
use tlsn::config::prover::ProverConfig;
use tlsn::config::tls::TlsClientConfig;
use tlsn::config::tls_commit::mpc::MpcTlsConfig;
use tlsn::config::tls_commit::proxy::ProxyTlsConfig;
use tlsn::connection::{DnsName, ServerName};
use tlsn::webpki::RootCertStore;
use tlsn::Session;

use crate::api;
use crate::{sleep_until_next_minute, Ctx};

const SESSION_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_SENT: usize = 2048;
const MAX_RECV: usize = 8192;

#[derive(Deserialize)]
struct Info {
    mode: String,
    pubkey: String,
    row: u8,
}

#[derive(Deserialize)]
struct Reply {
    ok: bool,
    #[serde(default)]
    err: Option<String>,
}

pub async fn prove_loop(ctx: Arc<Ctx>, rows: Vec<u8>, once: bool) -> Result<()> {
    log_info!("prover start", "rows" => rows.len(), "mode" => &ctx.prover_mode);
    loop {
        sleep_until_next_minute(2).await;
        let seq = current_minute();
        let mut tasks = Vec::new();
        for &row in &rows {
            let Some(r) = ctx.manifest.table.get(row as usize).cloned() else { continue };
            let ctx = ctx.clone();
            tasks.push(tokio::spawn(async move {
                let t0 = Instant::now();
                match tokio::time::timeout(SESSION_TIMEOUT, prove_row(&ctx, &r, seq)).await {
                    Ok(Ok(st)) => log_info!("proved", "row" => row, "seq" => seq, "price" => st.price, "ms" => t0.elapsed().as_millis() as u64),
                    Ok(Err(e)) => log_warn!("prove failed", "row" => row, "seq" => seq, "err" => format!("{e:#}"), "ms" => t0.elapsed().as_millis() as u64),
                    Err(_) => log_warn!("prove timeout", "row" => row, "seq" => seq),
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
        if once {
            return Ok(());
        }
    }
}

/// Run one session for `row` at minute `seq`, then fetch the statement from the notary API and
/// verify it against the manifest pubkey.
pub async fn prove_row(ctx: &Ctx, r: &TableRow, seq: u32) -> Result<Statement> {
    let source = source_by_id(r.source).ok_or_else(|| anyhow!("row {} has unknown source {}", r.row, r.source))?;
    let info: Info = api::get_json(&r.api, "/v1/info", Duration::from_secs(5)).await.context("notary info")?;
    if info.row != r.row || !info.pubkey.eq_ignore_ascii_case(&r.pubkey) {
        bail!("notary at {} is row {} key {}, manifest says row {} key {}", r.api, info.row, info.pubkey, r.row, r.pubkey);
    }
    let use_proxy = match ctx.prover_mode.as_str() {
        "proxy" => true,
        "mpc" => false,
        _ => info.mode != "mpc",
    };
    if use_proxy && info.mode == "mpc" {
        bail!("notary runs mpc only");
    }
    if !use_proxy && info.mode == "proxy" {
        bail!("notary runs proxy only");
    }
    match session(r, source, seq, use_proxy).await {
        Ok(()) => {}
        Err(e) => {
            // "issued" means another prover got there first this minute: the statement exists.
            if !e.to_string().contains("issued") {
                return Err(e);
            }
        }
    }
    // the notary signs after the session closes; give it a moment
    let mut last = None;
    for _ in 0..20 {
        match api::get_json::<Statement>(&r.api, &format!("/v1/statement?seq={seq}"), Duration::from_secs(5)).await {
            Ok(st) => {
                let pk = r.pubkey_bytes().ok_or_else(|| anyhow!("bad manifest pubkey"))?;
                if !st.verify(&ctx.manifest.category_vm(), &pk) {
                    bail!("statement from row {} does not verify", r.row);
                }
                return Ok(st);
            }
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("statement never appeared")))
}

async fn read_line(sock: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(64);
    let mut b = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut b)).await.context("reply timeout")??;
        if n == 0 {
            bail!("notary closed before replying");
        }
        if b[0] == b'\n' {
            break;
        }
        buf.push(b[0]);
        if buf.len() > 512 {
            bail!("reply too long");
        }
    }
    Ok(String::from_utf8(buf)?)
}

async fn session(r: &TableRow, source: &Source, seq: u32, use_proxy: bool) -> Result<()> {
    let hp = r.notary.strip_prefix("tcp://").ok_or_else(|| anyhow!("notary endpoint must be tcp://host:port"))?;
    let mut sock = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(hp)).await.context("notary connect timeout")??;
    sock.set_nodelay(true)?;
    sock.write_all(format!("{{\"v\":25,\"row\":{},\"seq\":{}}}\n", r.row, seq).as_bytes()).await?;
    let reply: Reply = serde_json::from_str(&read_line(&mut sock).await?).context("reply json")?;
    if !reply.ok {
        bail!("notary refused: {}", reply.err.unwrap_or_default());
    }
    let session = Session::new(sock.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let tls_cfg = TlsClientConfig::builder()
        .server_name(ServerName::Dns(source.host.try_into()?))
        .root_store(RootCertStore::mozilla())
        .build()?;
    // origin-form request target: the notary pins "GET <path>" on "<host>"
    let build_req = || {
        Request::builder()
            .uri(source.path)
            .header("Host", source.host)
            .header("Connection", "close")
            .header("User-Agent", "ticker-node/25")
            .header("Accept", "application/json")
            .method("GET")
            .body(Empty::<Bytes>::new())
    };
    if use_proxy {
        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(ProxyTlsConfig::builder().server_name(DnsName::try_from(source.host)?).build()?)
            .await?;
        let (tls_connection, prover) = prover.connect(tls_cfg)?;
        let tls_connection = TokioIo::new(tls_connection.compat());
        let prover_task = tokio::spawn(prover.into_future());
        let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_connection).await?;
        tokio::spawn(conn);
        let resp = sender.send_request(build_req()?).await?;
        let status = resp.status();
        let _ = resp.into_body().collect().await?;
        let mut prover = prover_task.await??;
        let mut b = ProveConfig::builder(prover.transcript());
        b.server_identity();
        b.reveal_sent(&(0..prover.transcript().sent().len()))?;
        b.reveal_recv(&(0..prover.transcript().received().len()))?;
        let cfg = b.build()?;
        prover.prove(&cfg).await?;
        prover.close().await?;
        handle.close();
        driver_task.await??;
        if !status.is_success() {
            bail!("exchange answered {status}");
        }
    } else {
        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(MpcTlsConfig::builder().max_sent_data(MAX_SENT).max_recv_data(MAX_RECV).build()?)
            .await?;
        let addr: SocketAddr = tokio::net::lookup_host((source.host, 443u16)).await?.next().ok_or_else(|| anyhow!("dns {}", source.host))?;
        let upstream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await.context("exchange connect timeout")??;
        upstream.set_nodelay(true)?;
        let (tls_connection, prover) = prover.connect(tls_cfg, upstream.compat())?;
        let tls_connection = TokioIo::new(tls_connection.compat());
        let prover_task = tokio::spawn(prover.into_future());
        let (mut sender, conn) = hyper::client::conn::http1::handshake(tls_connection).await?;
        tokio::spawn(conn);
        let resp = sender.send_request(build_req()?).await?;
        let status = resp.status();
        let _ = resp.into_body().collect().await?;
        let mut prover = prover_task.await??;
        let mut b = ProveConfig::builder(prover.transcript());
        b.server_identity();
        b.reveal_sent(&(0..prover.transcript().sent().len()))?;
        b.reveal_recv(&(0..prover.transcript().received().len()))?;
        let cfg = b.build()?;
        prover.prove(&cfg).await?;
        prover.close().await?;
        handle.close();
        driver_task.await??;
        if !status.is_success() {
            bail!("exchange answered {status}");
        }
    }
    Ok(())
}
