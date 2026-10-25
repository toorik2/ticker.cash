//! ticker-notary — one row of the v26 oracle: a key and an exchange.
//!
//! Once a minute it fetches the pinned path from the pinned host over TLS (Mozilla roots), parses
//! the pinned JSON field and signs the minute's statement
//!   0x4e ‖ category(32, VM byte order) ‖ source(1) ‖ seq(4, u32 LE) ‖ price(8, u64 LE)
//! at most once per Unix minute, while that minute is current on its own clock. Statements are
//! served over a read-only HTTP API. The notary holds no funds.
//!
//! Files under `$TICKER_HOME` (default `~/.ticker-notary`):
//!   notary.json      source, category, api address, operator, timing
//!   notary.key       32-byte hex private key, mode 0600
//!   statements.jsonl append-only log; reloaded at start so a restart cannot double-issue
//!
//! `sign-rotate` prints a rotation approval for the operator to hand to whoever assembles the
//! rotation transaction (`ticker-node rotate`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ticker_core::commit::{current_minute, now_unix};
use ticker_core::httpx::fetch_https;
use ticker_core::keyfile::{generate_key_file, load_key, KeyMaterial};
use ticker_core::sources::{source_by_id, Source};
use ticker_core::statement::{category_vm_from_display_hex, Approval, Statement};
use ticker_core::{log_info, log_warn};

/// A statement for minute m is signed while `60m <= now < 60m + WINDOW_SECS` on this clock.
const WINDOW_SECS: u64 = 90;
/// No fetch starts after this second of the minute.
const LAST_ATTEMPT_SEC: u64 = 45;
const RETRY_SPACING: Duration = Duration::from_secs(6);
/// Statements kept in memory and served; everything stays in statements.jsonl.
const KEEP: usize = 2_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    source: u8,
    /// Token category of the deployment, display-order hex.
    category: String,
    /// Statement API listen address.
    api: String,
    #[serde(default)]
    operator: String,
    /// Milliseconds past the minute boundary at which the fetch starts.
    #[serde(default = "default_offset_ms")]
    offset_ms: u64,
    #[serde(default = "default_timeout_s")]
    timeout_s: u64,
    #[serde(default = "default_retries")]
    retries: u32,
}

fn default_offset_ms() -> u64 {
    2_000
}
fn default_timeout_s() -> u64 {
    12
}
fn default_retries() -> u32 {
    3
}

struct Notary {
    cfg: Config,
    source: &'static Source,
    key: KeyMaterial,
    category_vm: [u8; 32],
    home: PathBuf,
    issued: Mutex<BTreeMap<u32, Statement>>,
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
        "sign-rotate" => sign_rotate(&home, &mut args),
        _ => {
            println!(
                "ticker-notary v26\n  init --source S --category HEX --api HOST:PORT [--operator NAME] [--offset-ms 2000] [--timeout-s 12] [--retries 3]\n  run\n  pubkey\n  sign-rotate --old-table-hash HEX --next-lock HEX [--tail HEX]    print a rotation approval\nFiles live in --home or $TICKER_HOME (default ~/.ticker-notary)"
            );
            Ok(())
        }
    }
}

fn init(home: &PathBuf, args: &mut pico_args::Arguments) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let cfg = Config {
        source: args.value_from_str("--source")?,
        category: args.value_from_str("--category")?,
        api: args.value_from_str("--api")?,
        operator: args.opt_value_from_str("--operator")?.unwrap_or_default(),
        offset_ms: args.opt_value_from_str("--offset-ms")?.unwrap_or_else(default_offset_ms),
        timeout_s: args.opt_value_from_str("--timeout-s")?.unwrap_or_else(default_timeout_s),
        retries: args.opt_value_from_str("--retries")?.unwrap_or_else(default_retries),
    };
    source_by_id(cfg.source).ok_or_else(|| anyhow!("unknown source id {}", cfg.source))?;
    category_vm_from_display_hex(&cfg.category).ok_or_else(|| anyhow!("category must be 64 hex chars"))?;
    let cfg_path = home.join("notary.json");
    if cfg_path.exists() {
        bail!("{} exists; refusing to overwrite", cfg_path.display());
    }
    let key = generate_key_file(home.join("notary.key"))?;
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg)?)?;
    println!("source {} pubkey {}", cfg.source, hex::encode(key.public_key));
    Ok(())
}

fn sign_rotate(home: &PathBuf, args: &mut pico_args::Arguments) -> Result<()> {
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(home.join("notary.json")).context("notary.json")?)?;
    let key = load_key(home.join("notary.key"))?;
    let category_vm = category_vm_from_display_hex(&cfg.category).ok_or_else(|| anyhow!("bad category"))?;
    let old: String = args.value_from_str("--old-table-hash")?;
    let next: String = args.value_from_str("--next-lock")?;
    let tail: String = args.opt_value_from_str("--tail")?.unwrap_or_default();
    let old: [u8; 20] = hex::decode(&old)?.try_into().map_err(|_| anyhow!("old table hash must be 20 bytes"))?;
    let next = hex::decode(&next)?;
    let tail = hex::decode(&tail)?;
    let a = Approval::sign(&key.private_key, &key.public_key, &category_vm, &old, &next, &tail)?;
    println!("{}", serde_json::to_string_pretty(&a)?);
    Ok(())
}

fn run(home: &PathBuf) -> Result<()> {
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(home.join("notary.json")).context("notary.json")?)?;
    let source = source_by_id(cfg.source).ok_or_else(|| anyhow!("unknown source id {}", cfg.source))?;
    let key = load_key(home.join("notary.key"))?;
    let category_vm = category_vm_from_display_hex(&cfg.category).ok_or_else(|| anyhow!("bad category"))?;
    let issued = load_issued(&home.join("statements.jsonl"));
    log_info!("notary start", "source" => source.name, "host" => source.host, "pubkey" => hex::encode(key.public_key), "issued_loaded" => issued.len());
    let notary = Arc::new(Notary { cfg, source, key, category_vm, home: home.clone(), issued: Mutex::new(issued), started: Instant::now() });
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let api_listener = TcpListener::bind(&notary.cfg.api).await.with_context(|| format!("bind {}", notary.cfg.api))?;
        let n1 = notary.clone();
        let minutes = tokio::spawn(async move { minute_loop(n1).await });
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
            r = minutes => { r?; }
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

fn load_issued(path: &PathBuf) -> BTreeMap<u32, Statement> {
    let mut map = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            if let Ok(st) = serde_json::from_str::<Statement>(line) {
                map.insert(st.seq, st);
            }
        }
    }
    while map.len() > KEEP {
        let first = *map.keys().next().unwrap();
        map.remove(&first);
    }
    map
}

/// Each minute: fetch at the configured offset, retry a few times, sign once.
async fn minute_loop(n: Arc<Notary>) {
    // a restart inside a minute still serves that minute
    if now_unix() % 60 <= LAST_ATTEMPT_SEC {
        minute(&n, current_minute()).await;
    }
    loop {
        sleep_until_next_minute(n.cfg.offset_ms).await;
        minute(&n, current_minute()).await;
    }
}

async fn minute(n: &Arc<Notary>, seq: u32) {
    if n.issued.lock().await.contains_key(&seq) {
        return;
    }
    for attempt in 1..=n.cfg.retries.max(1) {
        let t0 = Instant::now();
        match attempt_once(n, seq).await {
            Ok(st) => {
                log_info!("statement issued", "seq" => seq, "price" => st.price, "attempt" => attempt, "ms" => t0.elapsed().as_millis() as u64);
                return;
            }
            Err(e) => log_warn!("fetch failed", "seq" => seq, "attempt" => attempt, "err" => format!("{e:#}"), "ms" => t0.elapsed().as_millis() as u64),
        }
        let now = now_unix();
        if now / 60 != seq as u64 || now % 60 + RETRY_SPACING.as_secs() > LAST_ATTEMPT_SEC {
            return;
        }
        tokio::time::sleep(RETRY_SPACING).await;
    }
}

async fn attempt_once(n: &Arc<Notary>, seq: u32) -> Result<Statement> {
    let (host, path, timeout) = (n.source.host, n.source.path, Duration::from_secs(n.cfg.timeout_s));
    let resp = tokio::task::spawn_blocking(move || fetch_https(host, path, timeout)).await??;
    if resp.status != 200 {
        bail!("exchange answered {}", resp.status);
    }
    let price = n.source.extract_price(&resp.body).context("price extraction")?;
    let now = now_unix();
    let start = seq as u64 * 60;
    if now < start || now >= start + WINDOW_SECS {
        bail!("minute {seq} is no longer current (now {now})");
    }
    let st = Statement::sign(&n.key.private_key, &n.category_vm, n.cfg.source, seq, price)?;
    let mut issued = n.issued.lock().await;
    if issued.contains_key(&seq) {
        bail!("minute {seq} already issued");
    }
    issued.insert(seq, st.clone());
    while issued.len() > KEEP {
        let first = *issued.keys().next().unwrap();
        issued.remove(&first);
    }
    drop(issued);
    append_statement(&n.home.join("statements.jsonl"), &st);
    Ok(st)
}

/// Sleep until `offset_ms` past the next minute boundary.
async fn sleep_until_next_minute(offset_ms: u64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    let next = (now / 60.0).floor() * 60.0 + 60.0 + offset_ms as f64 / 1000.0;
    tokio::time::sleep(Duration::from_secs_f64((next - now).max(0.0))).await;
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
        "/v1/info" => {
            let issued = n.issued.lock().await;
            let (count, latest_seq) = (issued.len(), issued.keys().next_back().copied());
            drop(issued);
            (
                StatusCode::OK,
                serde_json::json!({
                    "version": 26,
                    "source": n.cfg.source,
                    "source_name": n.source.name,
                    "host": n.source.host,
                    "path": n.source.path,
                    "pubkey": hex::encode(n.key.public_key),
                    "category": n.cfg.category,
                    "operator": n.cfg.operator,
                    "uptime_s": n.started.elapsed().as_secs(),
                    "issued": count,
                    "latest_seq": latest_seq,
                })
                .to_string(),
            )
        }
        "/v1/statement" => {
            let seq = query.split('&').find_map(|kv| kv.strip_prefix("seq=")).and_then(|v| v.parse::<u32>().ok());
            match seq {
                None => (StatusCode::BAD_REQUEST, "{\"err\":\"seq required\"}".to_string()),
                Some(s) => match n.issued.lock().await.get(&s) {
                    Some(st) => (StatusCode::OK, serde_json::to_string(st).unwrap_or_default()),
                    None => (StatusCode::NOT_FOUND, "{\"err\":\"not issued\"}".to_string()),
                },
            }
        }
        "/v1/latest" => match n.issued.lock().await.iter().next_back() {
            Some((_, st)) => (StatusCode::OK, serde_json::to_string(st).unwrap_or_default()),
            None => (StatusCode::NOT_FOUND, "{\"err\":\"none yet\"}".to_string()),
        },
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
