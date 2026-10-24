//! The builder and the sweeper.
//!
//! Builder: every few seconds, read the head from Fulcrum, ask every notary for its latest
//! statement, and if some minute newer than the head has a quorum, post the update. Losing a
//! first-seen race to another builder is normal; the next poll sees the new head.
//!
//! Sweeper: reclaim Tickers confirmed at least `min_age_blocks` ago (144 before Faster Blocks,
//! 1,440 after: the covenant's relative lock is 144 legacy units of 600 ticks).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ticker_core::keyfile::load_key;
use ticker_core::price::format_price_1e8;
use ticker_core::statement::Statement;
use ticker_core::tx::build::select_statements;
use ticker_core::tx::{build_sweep, build_update, P2pkhInput};
use ticker_core::{log_info, log_warn, QUORUM, RESERVE_CAP_SATS, TICKER_SATS};

use crate::{api, chain, Ctx};

const POLL: Duration = Duration::from_secs(4);
const SWEEP_EVERY: Duration = Duration::from_secs(600);
const SWEEP_BATCH: usize = 100;

/// Latest statement from each notary, grouped by minute.
async fn collect(ctx: &Ctx) -> HashMap<u32, Vec<Statement>> {
    let mut tasks = Vec::new();
    for r in ctx.manifest.table.iter().cloned() {
        tasks.push(tokio::spawn(async move { (r.row, api::get_json_opt::<Statement>(&r.api, "/v1/latest", Duration::from_secs(4)).await) }));
    }
    let cat_vm = ctx.manifest.category_vm();
    let mut by_seq: HashMap<u32, Vec<Statement>> = HashMap::new();
    for t in tasks {
        let Ok((row, res)) = t.await else { continue };
        match res {
            Ok(None) => {} // notary up, nothing issued yet
            Ok(Some(st)) => {
                let Some(r) = ctx.manifest.table.get(row as usize) else { continue };
                let Some(pk) = r.pubkey_bytes() else { continue };
                if st.row != row || !st.verify(&cat_vm, &pk) {
                    log_warn!("statement rejected", "row" => row, "reason" => "signature/row mismatch");
                    continue;
                }
                by_seq.entry(st.seq).or_default().push(st);
            }
            Err(e) => log_warn!("notary unreachable", "row" => row, "err" => format!("{e:#}")),
        }
    }
    by_seq
}

pub async fn build_once(ctx: &Ctx, topup_sats: Option<u64>) -> Result<Option<String>> {
    let head = chain::find_head(&ctx.manifest).await?.ok_or_else(|| anyhow!("no head UTXO found for the manifest category"))?;
    let by_seq = collect(ctx).await;
    let mut candidates: Vec<u32> = by_seq.iter().filter(|(s, v)| **s > head.commit.seq && v.len() >= QUORUM).map(|(s, _)| *s).collect();
    candidates.sort_unstable();
    let Some(seq) = candidates.pop() else {
        return Ok(None);
    };
    let statements = &by_seq[&seq];
    let table = ctx.manifest.table_bytes();
    let oracle_lock: [u8; 35] = hex::decode(&ctx.manifest.oracle_lock)?.try_into().map_err(|_| anyhow!("oracle_lock length"))?;
    let selected = select_statements(&head, &table, statements)?;
    let mut topups = Vec::new();
    if let Some(sats) = topup_sats {
        let key = load_key(ctx.home.join("operator.key"))?;
        let coins = chain::find_coins(&ctx.manifest, key.pkh).await?;
        let (op, value, _) = coins.into_iter().find(|(_, v, _)| *v >= sats + 1_000).ok_or_else(|| anyhow!("no operator coin with at least {sats} sats"))?;
        // the whole coin joins the reserve: no change output exists in an update
        log_info!("top-up coin selected", "value" => value);
        topups.push(P2pkhInput { outpoint: op, value, private_key: key.private_key, public_key: key.public_key, pkh: key.pkh });
    }
    let built = build_update(&head, &table, &oracle_lock, &selected, &topups)?;
    let txid = chain::broadcast(&ctx.manifest, built.raw.clone()).await.context("broadcast update")?;
    let median = ticker_core::commit::Commit::decode(&built.tx.outputs[0].token.as_ref().unwrap().commitment)?.price;
    log_info!("update posted", "txid" => &txid, "seq" => seq, "k" => selected.len(), "median" => format_price_1e8(median), "size" => built.size, "fee" => built.fee, "reserve_after" => built.tx.outputs[0].value, "topups" => topups.len());
    Ok(Some(txid))
}

pub async fn build_loop(ctx: Arc<Ctx>, once: bool, topup_sats: Option<u64>) -> Result<()> {
    log_info!("builder start", "oracle_lock" => &ctx.manifest.oracle_lock, "category" => &ctx.manifest.category);
    loop {
        match build_once(&ctx, topup_sats).await {
            Ok(Some(_)) if once => return Ok(()),
            Ok(Some(_)) => {}
            Ok(None) => {
                if once && topup_sats.is_some() {
                    // keep trying until a quorum for a new minute exists
                } else if once {
                    log_info!("nothing to post");
                    return Ok(());
                }
            }
            Err(e) => log_warn!("build failed", "err" => format!("{e:#}")),
        }
        tokio::time::sleep(POLL).await;
    }
}

pub async fn sweep_once(ctx: &Ctx) -> Result<Option<String>> {
    let key = load_key(ctx.home.join("operator.key"))?;
    let tickers = chain::find_sweepable_tickers(&ctx.manifest, ctx.min_age_blocks, SWEEP_BATCH).await?;
    if tickers.is_empty() {
        return Ok(None);
    }
    let built = build_sweep(&tickers, &key.pkh)?;
    let txid = chain::broadcast(&ctx.manifest, built.raw.clone()).await.context("broadcast sweep")?;
    log_info!("sweep posted", "txid" => &txid, "tickers" => tickers.len(), "reclaimed" => built.tx.outputs[0].value, "fee" => built.fee);
    Ok(Some(txid))
}

pub async fn sweep_loop(ctx: Arc<Ctx>, once: bool) -> Result<()> {
    log_info!("sweeper start", "min_age_blocks" => ctx.min_age_blocks);
    loop {
        match sweep_once(&ctx).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                if once {
                    log_info!("nothing to sweep");
                }
            }
            Err(e) => log_warn!("sweep failed", "err" => format!("{e:#}")),
        }
        if once {
            return Ok(());
        }
        tokio::time::sleep(SWEEP_EVERY).await;
    }
}

/// Machine-readable status for the dashboard: head, tip, and every row's latest statement.
pub async fn status_json(ctx: &Ctx) -> serde_json::Value {
    let head = chain::find_head(&ctx.manifest).await.ok().flatten();
    let tip = chain::tip_height(&ctx.manifest).await.ok();
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
                "row": r.row, "source": r.source, "source_name": source.map(|s| s.name), "host": source.map(|s| s.host),
                "quote": source.map(|s| format!("{:?}", s.quote).to_lowercase()),
                "operator": r.operator, "pubkey": r.pubkey, "api": r.api,
                "up": info.is_some(), "mode": info.as_ref().and_then(|i| i["mode"].as_str().map(str::to_string)),
                "uptime_s": info.as_ref().and_then(|i| i["uptime_s"].as_u64()),
                "issued": info.as_ref().and_then(|i| i["issued"].as_u64()),
                "latest": latest.map(|st| serde_json::json!({ "seq": st.seq, "price": st.price, "price_usd": format_price_1e8(st.price) })),
            }));
        }
    }
    rows.sort_by_key(|r| r["row"].as_u64().unwrap_or(99));
    serde_json::json!({
        "version": 25,
        "generated_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "network": ctx.manifest.network, "category": ctx.manifest.category,
        "oracle_lock": ctx.manifest.oracle_lock, "ticker_lock": ctx.manifest.ticker_lock,
        "quorum": QUORUM, "reserve_cap_sats": RESERVE_CAP_SATS, "ticker_sats": TICKER_SATS,
        "tip": tip,
        "head": head.as_ref().map(|h| serde_json::json!({
            "seq": h.commit.seq, "minute_start_unix": h.commit.minute_start_unix(), "price": h.commit.price,
            "price_usd": format_price_1e8(h.commit.price), "reserve_sats": h.value,
            "txid": hex::encode(h.outpoint.txid_be), "vout": h.outpoint.vout,
        })),
        "rows": rows,
    })
}

/// Write manifest.json once and status.json every `every` to `dir` (the web root).
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
    match &head {
        Some(h) => println!(
            "head  seq {} ({}Z) price {} reserve {} sats (~{} updates at k=13) outpoint {}:{}",
            h.commit.seq,
            fmt_minute(h.commit.seq),
            format_price_1e8(h.commit.price),
            h.value,
            h.value / (2_141 + 2 * TICKER_SATS),
            hex::encode(h.outpoint.txid_be),
            h.outpoint.vout
        ),
        None => println!("head  not found"),
    }
    println!("tip   {}", tip.map(|t| t.to_string()).unwrap_or_else(|| "?".into()));
    println!("cap   {RESERVE_CAP_SATS} sats per update; quorum {QUORUM}");
    for r in &ctx.manifest.table {
        let info = api::get(&r.api, "/v1/info", Duration::from_secs(4)).await;
        let latest = api::get_json_opt::<Statement>(&r.api, "/v1/latest", Duration::from_secs(4)).await;
        match (info, latest) {
            (Ok(_), Ok(Some(st))) => println!("row {:>2} {:<20} seq {} price {}", r.row, r.operator, st.seq, format_price_1e8(st.price)),
            (Ok(_), Ok(None)) => println!("row {:>2} {:<20} up, no statement yet", r.row, r.operator),
            (Ok(_), Err(e)) => println!("row {:>2} {:<20} up, bad answer ({e})", r.row, r.operator),
            (Err(e), _) => println!("row {:>2} {:<20} DOWN ({e})", r.row, r.operator),
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
