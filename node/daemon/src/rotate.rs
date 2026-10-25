//! Rotation: a majority of the current rows approves the head's next locking bytecode and
//! commitment tail; the operator assembles their approvals into one transaction.
//!
//!   approval-request  prints the fields each row signs with `ticker-notary sign-rotate`
//!   rotate            reads the approvals (one JSON file each), builds, broadcasts, and rewrites
//!                     manifest.json when the rotation is a table change
//!
//! A table change keeps the Oracle lock and sets the tail to the new table's hash160. A retirement
//! moves the head to a P2PKH with an empty tail; from there the key holder can do anything with it.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use ticker_core::manifest::{table_bytes, validate_rows, Manifest, TableRow};
use ticker_core::statement::Approval;
use ticker_core::tx::build_rotate;
use ticker_core::tx::cashaddr::{decode_p2pkh_cashaddr, AddressPrefix};
use ticker_core::tx::covenant::{oracle_lock, table_hash};
use ticker_core::tx::script::p2pkh_locking_script;
use ticker_core::log_info;

use crate::{chain, Ctx};

pub struct Plan {
    pub next_lock: Vec<u8>,
    pub tail: Vec<u8>,
    /// The new table when the rotation is a table change.
    pub rows: Option<Vec<TableRow>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TableFile {
    Rows(Vec<TableRow>),
    Spec { table: Vec<TableRow> },
}

pub fn load_rows(path: &PathBuf) -> Result<Vec<TableRow>> {
    let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let rows = match serde_json::from_str::<TableFile>(&raw)? {
        TableFile::Rows(r) => r,
        TableFile::Spec { table } => table,
    };
    validate_rows(&rows).context("new table")?;
    Ok(rows)
}

pub fn plan(manifest: &Manifest, table: Option<PathBuf>, retire_to: Option<String>) -> Result<Plan> {
    match (table, retire_to) {
        (Some(path), None) => {
            let rows = load_rows(&path)?;
            let th = table_hash(&table_bytes(&rows));
            if th == manifest.table_hash_bytes() {
                bail!("the new table is the current table");
            }
            Ok(Plan { next_lock: oracle_lock().to_vec(), tail: th.to_vec(), rows: Some(rows) })
        }
        (None, Some(addr)) => {
            let prefix = AddressPrefix::from_network(&manifest.network).ok_or_else(|| anyhow!("bad network in manifest"))?;
            let pkh = decode_p2pkh_cashaddr(&addr, prefix)?;
            Ok(Plan { next_lock: p2pkh_locking_script(&pkh).to_vec(), tail: Vec::new(), rows: None })
        }
        _ => bail!("give exactly one of --table FILE or --retire-to ADDRESS"),
    }
}

pub fn approval_request(manifest: &Manifest, plan: &Plan) -> Result<()> {
    let v = serde_json::json!({
        "category": manifest.category,
        "old_table_hash": manifest.table_hash,
        "next_lock": hex::encode(&plan.next_lock),
        "tail": hex::encode(&plan.tail),
        "rows_to_approve": manifest.table.len() / 2 + 1,
        "sign_with": format!("ticker-notary sign-rotate --old-table-hash {} --next-lock {} --tail {}", manifest.table_hash, hex::encode(&plan.next_lock), hex::encode(&plan.tail)),
    });
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

fn load_approvals(dir: &PathBuf) -> Result<Vec<Approval>> {
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(dir).with_context(|| dir.display().to_string())?.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.extension().map(|x| x == "json").unwrap_or(false)).collect();
    names.sort();
    for p in names {
        let a: Approval = serde_json::from_str(&std::fs::read_to_string(&p)?).with_context(|| p.display().to_string())?;
        out.push(a);
    }
    if out.is_empty() {
        bail!("no approvals (*.json) in {}", dir.display());
    }
    Ok(out)
}

pub async fn rotate(ctx: Arc<Ctx>, plan: Plan, approvals_dir: PathBuf, dry_run: bool) -> Result<()> {
    let approvals = load_approvals(&approvals_dir)?;
    let head = chain::find_head(&ctx.manifest).await?.ok_or_else(|| anyhow!("no head UTXO found for the manifest category"))?;
    if head.commit.table_hash != ctx.manifest.table_hash_bytes() {
        bail!("the head's table hash is not the manifest's; rewrite manifest.json first");
    }
    let table = ctx.manifest.table_bytes();
    let built = build_rotate(&head, &table, &plan.next_lock, &plan.tail, &approvals, &[])?;
    println!("rotation {} B, fee {} sats, {} approvals of {} rows, next lock {}, tail {}", built.size, built.fee, approvals.len(), ctx.manifest.table.len(), hex::encode(&plan.next_lock), hex::encode(&plan.tail));
    if dry_run {
        println!("dry-run: nothing broadcast");
        return Ok(());
    }
    let txid = chain::broadcast(&ctx.manifest, built.raw.clone()).await.context("broadcast rotation")?;
    log_info!("rotation posted", "txid" => &txid, "approvals" => approvals.len(), "tail" => hex::encode(&plan.tail));
    if let Some(rows) = plan.rows {
        let mut m = ctx.manifest.clone();
        m.set_table(rows)?;
        let path = ctx.home.join("manifest.json");
        std::fs::write(&path, serde_json::to_string_pretty(&m)?)?;
        println!("manifest.json rewritten: table hash {}", m.table_hash);
    } else {
        println!("the head left the Oracle covenant; this manifest describes a retired deployment");
    }
    println!("{txid}");
    Ok(())
}
