//! ticker-notary — one table row of the v25 oracle.
//!
//! A notary is a TLSNotary *verifier* pinned to one exchange endpoint. A prover (anyone) opens
//! a session; the notary co-runs the TLS connection (MPC-TLS) or forwards it (proxy mode),
//! validates the exchange's certificate chain, requires the whole request and response to be
//! revealed, checks the request against the pin, parses the price, and signs the minute's
//! statement. It signs at most one statement per Unix minute, serves statements over HTTP, and
//! holds no funds.
//!
//! Files under `$TICKER_HOME` (default `~/.ticker-notary`):
//!   notary.json      row, source, listen/api addresses, mode, category, limits
//!   notary.key       32-byte hex private key, mode 0600
//!   statements.jsonl append-only log; reloaded at start so a restart cannot double-issue
//!
//! Wire protocol on the session port: the prover sends one JSON line
//! `{"v":25,"row":R,"seq":S}` and reads one JSON line back (`{"ok":true}` or
//! `{"ok":false,"err":"..."}`); the TLSNotary session then runs on the same socket. The
//! resulting statement is fetched from `GET /v1/statement?seq=S` on the API port.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::compat::TokioAsyncReadCompatExt;

use ticker_core::commit::current_minute;
use ticker_core::httpx::{parse_request, parse_response};
use ticker_core::keyfile::{generate_key_file, load_key, KeyMaterial};
use ticker_core::sources::{source_by_id, Source};
use ticker_core::statement::{category_vm_from_display_hex, Statement};
use ticker_core::{log_error, log_info, log_warn};
use tlsn::config::verifier::VerifierConfig;
use tlsn::connection::ServerName;
use tlsn::verifier::{VerifierCommitStart, VerifierOutput};
use tlsn::webpki::RootCertStore;
use tlsn::Session;

const DEFAULT_MAX_SENT: usize = 2048;
const DEFAULT_MAX_RECV: usize = 8192;
/// Accept a session for minute `seq` only within this window of wall time.
const SEQ_WINDOW_SECS: u64 = 90;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    row: u8,
    source: u8,
    /// Token category of the deployment, display-order hex.
    category: String,
    listen: String,
    api: String,
    /// "mpc", "proxy" or "both".
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default = "default_max_sent")]
    max_sent: usize,
    #[serde(default = "default_max_recv")]
    max_recv: usize,
    #[serde(default)]
    operator: String,
}

fn default_mode() -> String {
    "both".into()
}
fn default_max_sent() -> usize {
    DEFAULT_MAX_SENT
}
fn default_max_recv() -> usize {
    DEFAULT_MAX_RECV
}

struct Notary {
    cfg: Config,
    source: &'static Source,
    key: KeyMaterial,
    category_vm: [u8; 32],
    home: PathBuf,
    /// seq → statement; `None` while a session for that seq is in flight.
    issued: Mutex<HashMap<u32, Option<Statement>>>,
    started: Instant,
}

fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("TICKER_HOME") {
        return PathBuf::from(h);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".ticker-notary")
}

fn main() {
    let code = match real_main() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ticker-notary: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn real_main() -> Result<()> {
    let mut args = pico_args::Arguments::from_env();
    let home: PathBuf = args.opt_value_from_str::<&str, String>("--home")?.map(PathBuf::from).unwrap_or_else(home_dir);
    let sub = args.subcommand()?.unwrap_or_else(|| "help".into());
    match sub.as_str() {
        "init" => init(&home, &mut args),
        "run" => run(&home),
        "pubkey" => {
            let key = load_key(home.join("notary.key"))?;
            println!("{}", hex::encode(key.public_key));
            Ok(())
        }
        _ => {
            println!(
                "ticker-notary v25\n  init --row R --source S --category HEX --listen HOST:PORT --api HOST:PORT [--mode mpc|proxy|both] [--operator NAME]\n  run\n  pubkey\nFiles live in --home or $TICKER_HOME (default ~/.ticker-notary)"
            );
            Ok(())
        }
    }
}

fn init(home: &PathBuf, args: &mut pico_args::Arguments) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let cfg = Config {
        row: args.value_from_str("--row")?,
        source: args.value_from_str("--source")?,
        category: args.value_from_str("--category")?,
        listen: args.value_from_str("--listen")?,
        api: args.value_from_str("--api")?,
        mode: args.opt_value_from_str("--mode")?.unwrap_or_else(default_mode),
        max_sent: args.opt_value_from_str("--max-sent")?.unwrap_or(DEFAULT_MAX_SENT),
        max_recv: args.opt_value_from_str("--max-recv")?.unwrap_or(DEFAULT_MAX_RECV),
        operator: args.opt_value_from_str("--operator")?.unwrap_or_default(),
    };
    source_by_id(cfg.source).ok_or_else(|| anyhow!("unknown source id {}", cfg.source))?;
    category_vm_from_display_hex(&cfg.category).ok_or_else(|| anyhow!("category must be 64 hex chars"))?;
    if !matches!(cfg.mode.as_str(), "mpc" | "proxy" | "both") {
        bail!("mode must be mpc, proxy or both");
    }
    let cfg_path = home.join("notary.json");
    if cfg_path.exists() {
        bail!("{} exists; refusing to overwrite", cfg_path.display());
    }
    let key = generate_key_file(home.join("notary.key"))?;
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg)?)?;
    println!("row {} source {} pubkey {}", cfg.row, cfg.source, hex::encode(key.public_key));
    Ok(())
}

fn run(home: &PathBuf) -> Result<()> {
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(home.join("notary.json")).context("notary.json")?)?;
    let source = source_by_id(cfg.source).ok_or_else(|| anyhow!("unknown source id {}", cfg.source))?;
    let key = load_key(home.join("notary.key"))?;
    let category_vm = category_vm_from_display_hex(&cfg.category).ok_or_else(|| anyhow!("bad category"))?;
    let issued = load_issued(&home.join("statements.jsonl"));
    log_info!("notary start", "row" => cfg.row, "source" => source.name, "host" => source.host, "mode" => &cfg.mode, "pubkey" => hex::encode(key.public_key), "issued_loaded" => issued.len());
    let notary = Arc::new(Notary { cfg, source, key, category_vm, home: home.clone(), issued: Mutex::new(issued), started: Instant::now() });
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let session_listener = TcpListener::bind(&notary.cfg.listen).await.with_context(|| format!("bind {}", notary.cfg.listen))?;
        let api_listener = TcpListener::bind(&notary.cfg.api).await.with_context(|| format!("bind {}", notary.cfg.api))?;
        let n1 = notary.clone();
        let sessions = tokio::spawn(async move {
            loop {
                match session_listener.accept().await {
                    Ok((sock, peer)) => {
                        let n = n1.clone();
                        tokio::spawn(async move {
                            let t0 = Instant::now();
                            match handle_session(n, sock).await {
                                Ok(st) => log_info!("statement issued", "seq" => st.seq, "price" => st.price, "peer" => peer.to_string(), "ms" => t0.elapsed().as_millis() as u64),
                                Err(e) => log_warn!("session failed", "peer" => peer.to_string(), "err" => format!("{e:#}"), "ms" => t0.elapsed().as_millis() as u64),
                            }
                        });
                    }
                    Err(e) => {
                        log_error!("accept failed", "err" => e.to_string());
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
        let n2 = notary.clone();
        let api = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = api_listener.accept().await else { continue };
                let n = n2.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| api_handler(n.clone(), req));
                    if let Err(e) = http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(sock), svc).await {
                        log_warn!("api connection error", "err" => e.to_string());
                    }
                });
            }
        });
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm() => {}
            r = sessions => { r?; }
            r = api => { r?; }
        }
        log_info!("notary stop");
        Ok::<(), anyhow::Error>(())
    })
}

async fn sigterm() {
    #[cfg(unix)]
    {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await;
}

fn load_issued(path: &PathBuf) -> HashMap<u32, Option<Statement>> {
    let mut map = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            if let Ok(st) = serde_json::from_str::<Statement>(line) {
                map.insert(st.seq, Some(st));
            }
        }
    }
    map
}

#[derive(Deserialize)]
struct Hello {
    v: u32,
    row: u8,
    seq: u32,
}

async fn read_line_unbuffered(sock: &mut TcpStream, max: usize) -> Result<String> {
    let mut buf = Vec::with_capacity(64);
    let mut b = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut b)).await.context("hello timeout")??;
        if n == 0 {
            bail!("peer closed before hello");
        }
        if b[0] == b'\n' {
            break;
        }
        buf.push(b[0]);
        if buf.len() > max {
            bail!("hello too long");
        }
    }
    Ok(String::from_utf8(buf)?)
}

async fn reply(sock: &mut TcpStream, ok: bool, err: Option<&str>) -> Result<()> {
    let line = match err {
        Some(e) => format!("{{\"ok\":{ok},\"err\":{}}}\n", serde_json::to_string(e)?),
        None => format!("{{\"ok\":{ok}}}\n"),
    };
    sock.write_all(line.as_bytes()).await?;
    sock.flush().await?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

async fn handle_session(n: Arc<Notary>, mut sock: TcpStream) -> Result<Statement> {
    sock.set_nodelay(true)?;
    let hello: Hello = serde_json::from_str(&read_line_unbuffered(&mut sock, 256).await?).context("hello json")?;
    if hello.v != 25 || hello.row != n.cfg.row {
        reply(&mut sock, false, Some("wrong version or row")).await?;
        bail!("hello: version {} row {}", hello.v, hello.row);
    }
    let seq = hello.seq;
    let now = now_unix();
    let seq_start = seq as u64 * 60;
    if now.abs_diff(seq_start) > SEQ_WINDOW_SECS || seq > current_minute() {
        reply(&mut sock, false, Some("seq outside the current minute")).await?;
        bail!("seq {seq} outside window (now {now})");
    }
    {
        let mut issued = n.issued.lock().await;
        match issued.get(&seq) {
            Some(Some(_)) => {
                reply(&mut sock, false, Some("issued")).await?;
                bail!("seq {seq} already issued");
            }
            Some(None) => {
                reply(&mut sock, false, Some("busy")).await?;
                bail!("seq {seq} session in flight");
            }
            None => {
                issued.insert(seq, None);
            }
        }
    }
    let result = verify_session(&n, sock, seq).await;
    let mut issued = n.issued.lock().await;
    match result {
        Ok(st) => {
            issued.insert(seq, Some(st.clone()));
            drop(issued);
            append_statement(&n.home.join("statements.jsonl"), &st);
            Ok(st)
        }
        Err(e) => {
            issued.remove(&seq);
            Err(e)
        }
    }
}

async fn verify_session(n: &Notary, mut sock: TcpStream, seq: u32) -> Result<Statement> {
    reply(&mut sock, true, None).await?;
    // From here the socket belongs to the TLSNotary session.
    let stream = sock.compat();
    let session = Session::new(stream);
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(VerifierConfig::builder().root_store(RootCertStore::mozilla()).build()?)?;
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(v) => {
            if n.cfg.mode == "proxy" {
                v.reject(Some("this notary runs proxy mode only")).await?;
                bail!("mpc session refused by mode");
            }
            let (ms, mr) = { let c = v.config(); (c.max_sent_data(), c.max_recv_data()) };
            if ms > n.cfg.max_sent || mr > n.cfg.max_recv {
                v.reject(Some("transcript limits too large")).await?;
                bail!("limits {}/{} exceed {}/{}", ms, mr, n.cfg.max_sent, n.cfg.max_recv);
            }
            v.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(v) => {
            if n.cfg.mode == "mpc" {
                v.reject(Some("this notary runs mpc mode only")).await?;
                bail!("proxy session refused by mode");
            }
            let name = v.config().server_name().as_str().to_string();
            if !name.eq_ignore_ascii_case(n.source.host) {
                v.reject(Some("server name does not match this row's exchange")).await?;
                bail!("proxy target {name} is not {}", n.source.host);
            }
            // The notary resolves and dials the exchange itself: that is the network-path
            // assumption of proxy mode, and it must never be delegated to the prover.
            let addr: SocketAddr = tokio::net::lookup_host((n.source.host, 443u16)).await?.next().ok_or_else(|| anyhow!("dns {}", n.source.host))?;
            let upstream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await.context("exchange connect timeout")??;
            upstream.set_nodelay(true)?;
            v.accept().await?.run(upstream.compat()).await?
        }
    };
    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() {
        let v = verifier.reject(Some("server identity must be revealed")).await?;
        v.close().await?;
        bail!("prover did not reveal server identity");
    }
    let (VerifierOutput { server_name, transcript, .. }, verifier) = verifier.accept().await?;
    verifier.close().await?;
    handle.close();
    driver_task.await??;

    let ServerName::Dns(name) = server_name.ok_or_else(|| anyhow!("no server name"))?;
    if !name.as_str().eq_ignore_ascii_case(n.source.host) {
        bail!("session was with {}, not {}", name.as_str(), n.source.host);
    }
    let transcript = transcript.ok_or_else(|| anyhow!("no transcript revealed"))?;
    if !transcript.is_complete() {
        bail!("prover redacted part of the transcript; full disclosure is required");
    }
    let sent = transcript.sent_unsafe();
    let recv = transcript.received_unsafe();
    let req = parse_request(sent).context("request parse")?;
    let absolute = format!("https://{}{}", n.source.host, n.source.path);
    let target_ok = req.target == n.source.path || req.target.eq_ignore_ascii_case(&absolute);
    if req.method != "GET" || !target_ok || req.host.as_deref() != Some(n.source.host) {
        bail!("request {} {} host {:?} is not the pinned GET {} on {}", req.method, req.target, req.host, n.source.path, n.source.host);
    }
    let resp = parse_response(recv).context("response parse")?;
    if resp.status != 200 {
        bail!("exchange answered {}", resp.status);
    }
    let price = n.source.extract_price(&resp.body).context("price extraction")?;
    let st = Statement::sign(&n.key.private_key, &n.category_vm, n.cfg.row, n.cfg.source, seq, price)?;
    Ok(st)
}

fn append_statement(path: &PathBuf, st: &Statement) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        if let Ok(line) = serde_json::to_string(st) {
            let _ = writeln!(f, "{line}");
        }
    }
}

async fn api_handler(n: Arc<Notary>, req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let (status, body) = match path.as_str() {
        "/v1/info" => (
            StatusCode::OK,
            serde_json::json!({
                "version": 25,
                "row": n.cfg.row,
                "source": n.cfg.source,
                "source_name": n.source.name,
                "host": n.source.host,
                "path": n.source.path,
                "pubkey": hex::encode(n.key.public_key),
                "category": n.cfg.category,
                "mode": n.cfg.mode,
                "operator": n.cfg.operator,
                "listen": n.cfg.listen,
                "uptime_s": n.started.elapsed().as_secs(),
                "issued": n.issued.lock().await.values().filter(|v| v.is_some()).count(),
            })
            .to_string(),
        ),
        "/v1/statement" => {
            let seq = query.split('&').find_map(|kv| kv.strip_prefix("seq=")).and_then(|v| v.parse::<u32>().ok());
            match seq {
                None => (StatusCode::BAD_REQUEST, "{\"err\":\"seq required\"}".to_string()),
                Some(s) => match n.issued.lock().await.get(&s) {
                    Some(Some(st)) => (StatusCode::OK, serde_json::to_string(st).unwrap_or_default()),
                    Some(None) => (StatusCode::ACCEPTED, "{\"err\":\"in flight\"}".to_string()),
                    None => (StatusCode::NOT_FOUND, "{\"err\":\"not issued\"}".to_string()),
                },
            }
        }
        "/v1/latest" => {
            let issued = n.issued.lock().await;
            match issued.iter().filter_map(|(s, v)| v.as_ref().map(|st| (*s, st))).max_by_key(|(s, _)| *s) {
                Some((_, st)) => (StatusCode::OK, serde_json::to_string(st).unwrap_or_default()),
                None => (StatusCode::NOT_FOUND, "{\"err\":\"none yet\"}".to_string()),
            }
        }
        _ => (StatusCode::NOT_FOUND, "{\"err\":\"not found\"}".to_string()),
    };
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}
