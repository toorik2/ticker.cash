//! The builder: every two seconds, read the head from Fulcrum; once the current minute has
//! statements from every row, or from at least seven rows by second twenty, post the update.
//! The same transaction recycles up to ten Tickers whose hour is up by median-time-past, so their
//! dust and tolls return to the reserve. Losing a first-seen race to another builder is normal;
//! the next poll sees the new head.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ticker_core::commit::{now_unix, HeadCommit};
use ticker_core::keyfile::load_key;
use ticker_core::statement::Statement;
use ticker_core::tx::build::keys_to_forge;
use ticker_core::tx::{build_update, P2pkhInput};
use ticker_core::{log_info, log_warn, FEE_CAP_BASE_SATS, FEE_CAP_PER_UNLOCK_BYTE, MAX_RECYCLE_PER_UPDATE, QUORUM, TICKER_LIFE_SECS, TICKER_SATS, TOLL_SATS};

fn usd(cents: u32) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

use crate::{api, chain, Ctx};

const POLL: Duration = Duration::from_secs(2);
/// Post with fewer than all rows only from this second of the minute on.
const POST_AT_SEC: u64 = 20;
const API_TIMEOUT: Duration = Duration::from_secs(3);

/// Statements for Unix minute `minute`: one per row, each verified against its row's key and source.
async fn collect(ctx: &Ctx, minute: u32) -> Vec<Statement> {
    let mut tasks = Vec::new();
    for r in ctx.manifest.table.iter().cloned() {
        tasks.push(tokio::spawn(async move {
            let res = api::get_json_opt::<Statement>(&r.api, &format!("/v1/statement?seq={minute}"), API_TIMEOUT).await;
            (r, res)
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        let Ok((row, res)) = t.await else { continue };
        match res {
            Ok(None) => {} // notary up, nothing for this minute yet
            Ok(Some(st)) => {
                let Some(pk) = row.pubkey_bytes() else { continue };
                if st.ts != minute * 60 || st.source != row.source || !st.verify(&pk) {
                    log_warn!("statement rejected", "row" => row.row, "reason" => "signature, source or minute mismatch");
                    continue;
                }
                out.push(st);
            }
            Err(e) => log_warn!("notary unreachable", "row" => row.row, "err" => format!("{e:#}")),
        }
    }
    out
}

pub async fn build_once(ctx: &Ctx, topup_sats: Option<u64>) -> Result<Option<String>> {
    let head = chain::find_head(&ctx.manifest).await?.ok_or_else(|| anyhow!("no head UTXO found for the manifest category"))?;
    if head.commit.table_hash != ctx.manifest.table_hash_bytes() {
        bail!("the head's table hash {} is not the manifest's; the table was rotated, rewrite manifest.json", hex::encode(head.commit.table_hash));
    }
    let now = now_unix();
    let minute = (now / 60) as u32;
    if head.commit.snapshot.ts >= minute * 60 {
        return Ok(None); // this minute is already on chain
    }
    let statements = collect(ctx, minute).await;
    let rows = ctx.manifest.table.len();
    if statements.len() < QUORUM {
        return Ok(None);
    }
    if statements.len() < rows && now % 60 < POST_AT_SEC {
        return Ok(None); // give the slower rows until second twenty
    }
    let table = ctx.manifest.table_bytes();
    let mtp = chain::median_time_past(&ctx.manifest).await.context("median-time-past")?;
    let recycled = chain::find_recyclable_tickers(&ctx.manifest, mtp, MAX_RECYCLE_PER_UPDATE).await?;
    let mut topups = Vec::new();
    if let Some(sats) = topup_sats {
        let key = load_key(ctx.home.join("operator.key"))?;
        let coins = chain::find_coins(&ctx.manifest, key.pkh).await?;
        let (op, value, _) = coins.into_iter().find(|(_, v, _)| *v >= sats + 1_000).ok_or_else(|| anyhow!("no operator coin with at least {sats} sats"))?;
        // the whole coin joins the reserve: no change output exists in an update
        log_info!("top-up coin selected", "value" => value);
        topups.push(P2pkhInput { outpoint: op, value, private_key: key.private_key, public_key: key.public_key, pkh: key.pkh });
    }
    let built = build_update(&head, &table, &statements, &recycled, &topups)?;
    let txid = chain::broadcast(&ctx.manifest, built.raw.clone()).await.context("broadcast update")?;
    let c = HeadCommit::decode(&built.tx.outputs[0].token.as_ref().unwrap().commitment)?;
    log_info!("update posted", "txid" => &txid, "ts" => c.snapshot.ts, "seq" => c.snapshot.seq, "k" => c.snapshot.k, "rows" => rows, "median" => usd(c.snapshot.price), "size" => built.size, "fee" => built.fee,
        "recycled" => recycled.len(), "recycled_sats" => recycled.iter().map(|t| t.value).sum::<u64>(), "topups" => topups.len(), "reserve_after" => built.tx.outputs[0].value, "locktime" => built.tx.locktime, "mtp" => mtp);
    Ok(Some(txid))
}

pub async fn build_loop(ctx: Arc<Ctx>, once: bool, topup_sats: Option<u64>) -> Result<()> {
    log_info!("builder start", "category" => &ctx.manifest.category, "rows" => ctx.manifest.table.len(), "table_hash" => &ctx.manifest.table_hash);
    loop {
        match build_once(&ctx, topup_sats).await {
            Ok(Some(_)) if once => return Ok(()),
            Ok(Some(_)) => {}
            Ok(None) => {
                if once && topup_sats.is_none() {
                    log_info!("nothing to post");
                    return Ok(());
                }
            }
            Err(e) => log_warn!("build failed", "err" => format!("{e:#}")),
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Machine-readable status for the dashboard: head, tip, median-time-past, every row's latest statement.
pub async fn status_json(ctx: &Ctx) -> serde_json::Value {
    let head = chain::find_head(&ctx.manifest).await.ok().flatten();
    let tip = chain::tip_height(&ctx.manifest).await.ok();
    let mtp = chain::median_time_past(&ctx.manifest).await.ok();
    let mut rows = Vec::new();
    let mut tasks = Vec::new();
    for r in ctx.manifest.table.iter().cloned() {
        tasks.push(tokio::spawn(async move {
            let info = api::get_json::<serde_json::Value>(&r.api, "/v1/info", Duration::from_secs(4)).await.ok();
            let latest = api::get_json_opt::<Statement>(&r.api, "/v1/latest", Duration::from_secs(4)).await.ok().flatten();
            (r, info, latest)
        }));
    }
    for t in tasks {
        if let Ok((r, info, latest)) = t.await {
            let source = ticker_core::sources::source_by_id(r.source);
            rows.push(serde_json::json!({
                "row": r.row, "source": r.source, "source_name": source.map(|s| s.name), "label": source.map(|s| s.label), "host": source.map(|s| s.host),
                "quote": source.map(|s| format!("{:?}", s.quote).to_lowercase()),
                "operator": r.operator, "pubkey": r.pubkey, "api": r.api,
                "up": info.is_some(),
                "uptime_s": info.as_ref().and_then(|i| i["uptime_s"].as_u64()),
                "issued": info.as_ref().and_then(|i| i["issued"].as_u64()),
                "latest": latest.map(|st| serde_json::json!({ "ts": st.ts, "minute": st.minute(), "price": st.price, "price_usd": usd(st.price) })),
            }));
        }
    }
    rows.sort_by_key(|r| r["row"].as_u64().unwrap_or(99));
    let manifest_hash = ctx.manifest.table_hash_bytes();
    serde_json::json!({
        "version": 27,
        "generated_at": now_unix(),
        "network": ctx.manifest.network, "category": ctx.manifest.category,
        "oracle_lock": ctx.manifest.oracle_lock, "ticker_lock": ctx.manifest.ticker_lock, "table_hash": ctx.manifest.table_hash,
        "quorum": QUORUM, "ticker_sats": TICKER_SATS, "toll_sats": TOLL_SATS, "ticker_life_secs": TICKER_LIFE_SECS,
        "fee_cap": { "base_sats": FEE_CAP_BASE_SATS, "per_unlock_byte": FEE_CAP_PER_UNLOCK_BYTE },
        "tip": tip, "mtp": mtp,
        "head": head.as_ref().map(|h| serde_json::json!({
            "ts": h.commit.snapshot.ts, "minute_start_unix": h.commit.snapshot.ts, "seq": h.commit.snapshot.seq,
            "price": h.commit.snapshot.price, "price_usd": usd(h.commit.snapshot.price),
            "k": h.commit.snapshot.k, "keys_to_forge": if h.commit.snapshot.k > 0 { keys_to_forge(h.commit.snapshot.k as usize) } else { 0 },
            "table_hash": hex::encode(h.commit.table_hash), "table_matches_manifest": h.commit.table_hash == manifest_hash,
            "reserve_sats": h.value, "txid": hex::encode(h.outpoint.txid_be), "vout": h.outpoint.vout,
        })),
        "rows": rows,
    })
}

/// Write manifest.json once per pass and status.json every `every` to `dir` (the web root).
pub async fn publish_loop(ctx: Arc<Ctx>, dir: std::path::PathBuf, every: Duration) -> Result<()> {
    std::fs::create_dir_all(&dir)?;
    log_info!("publishing status", "dir" => dir.display().to_string());
    loop {
        // the web build wipes its output directory, so the manifest is re-published every pass
        let _ = std::fs::create_dir_all(&dir);
        let manifest = dir.join("manifest.json");
        let _ = std::fs::write(&manifest, serde_json::to_string_pretty(&ctx.manifest)?);
        make_public(&manifest);
        let v = status_json(&ctx).await;
        let tmp = dir.join("status.json.tmp");
        if std::fs::write(&tmp, serde_json::to_string(&v)?).and_then(|_| std::fs::rename(&tmp, dir.join("status.json"))).is_err() {
            log_warn!("status write failed", "dir" => dir.display().to_string());
        }
        make_public(&dir.join("status.json"));
        tokio::time::sleep(every).await;
    }
}

/// The published files are public data; the daemon's umask (0077 under systemd) must not hide them
/// from the web server.
fn make_public(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
}

pub async fn status(ctx: Arc<Ctx>) -> Result<()> {
    let head = chain::find_head(&ctx.manifest).await?;
    let tip = chain::tip_height(&ctx.manifest).await.ok();
    let mtp = chain::median_time_past(&ctx.manifest).await.ok();
    match &head {
        Some(h) => {
            let s = h.commit.snapshot;
            println!(
                "head  ts {} ({}Z) seq {} price {} k {} ({} keys to forge) reserve {} sats (~{} updates at 2,400 B) outpoint {}:{}",
                s.ts,
                fmt_minute(s.ts / 60),
                s.seq,
                usd(s.price),
                s.k,
                if s.k > 0 { keys_to_forge(s.k as usize) } else { 0 },
                h.value,
                h.value / (2_401 + 2 * TICKER_SATS),
                hex::encode(h.outpoint.txid_be),
                h.outpoint.vout
            );
            println!("table {} ({})", hex::encode(h.commit.table_hash), if h.commit.table_hash == ctx.manifest.table_hash_bytes() { "matches manifest" } else { "DIFFERS from manifest: rotated?" });
        }
        None => println!("head  not found"),
    }
    println!("tip   {}  mtp {}", tip.map(|t| t.to_string()).unwrap_or_else(|| "?".into()), mtp.map(|t| t.to_string()).unwrap_or_else(|| "?".into()));
    println!("floor {QUORUM} rows; ticker {TICKER_SATS} sats, toll {TOLL_SATS}, life {TICKER_LIFE_SECS} s");
    for r in &ctx.manifest.table {
        let info = api::get(&r.api, "/v1/info", Duration::from_secs(4)).await;
        let latest = api::get_json_opt::<Statement>(&r.api, "/v1/latest", Duration::from_secs(4)).await;
        let name = ticker_core::sources::source_by_id(r.source).map(|s| s.label).unwrap_or("?");
        match (info, latest) {
            (Ok(_), Ok(Some(st))) => println!("row {:>2} {:<12} {:<16} ts {} price {}", r.row, name, r.operator, st.ts, usd(st.price)),
            (Ok(_), Ok(None)) => println!("row {:>2} {:<12} {:<16} up, no statement yet", r.row, name, r.operator),
            (Ok(_), Err(e)) => println!("row {:>2} {:<12} {:<16} up, bad answer ({e})", r.row, name, r.operator),
            (Err(e), _) => println!("row {:>2} {:<12} {:<16} DOWN ({e})", r.row, name, r.operator),
        }
    }
    Ok(())
}

fn fmt_minute(seq: u32) -> String {
    let secs = seq as u64 * 60;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // civil date from days since epoch (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}", rem / 3600, (rem % 3600) / 60)
}
