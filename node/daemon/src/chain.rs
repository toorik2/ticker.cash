//! Blocking Electrum calls wrapped for the async runtime, plus UTXO decoding against the
//! manifest. Fulcrum is untrusted: everything it returns is checked against the manifest's
//! locks, category and the commitment codecs before use.

use std::time::Duration;

use anyhow::{anyhow, Result};
use ticker_core::commit::{legacy, HeadCommit, Snapshot};
use ticker_core::electrum::{ElectrumClient, Endpoint, NftCapability, Utxo};
use ticker_core::manifest::Manifest;
use ticker_core::tx::covenant::{electrum_scripthash, legacy as legacy_scripts, ticker_lock};
use ticker_core::tx::encode::TxOutpoint;
use ticker_core::tx::script::p2pkh_locking_script;
use ticker_core::tx::{HeadUtxo, LegacyHeadUtxo, TickerUtxo};

const TIMEOUT: Duration = Duration::from_secs(20);

pub fn endpoints(m: &Manifest) -> Vec<Endpoint> {
    m.electrum.iter().map(|e| Endpoint::new(e.host.clone(), e.port, e.tls)).collect()
}

fn connect(m: &Manifest) -> Result<ElectrumClient> {
    Ok(ElectrumClient::connect_pool(endpoints(m), TIMEOUT)?)
}

fn outpoint(u: &Utxo) -> Result<TxOutpoint> {
    Ok(TxOutpoint { txid_be: u.txid_be().ok_or_else(|| anyhow!("bad txid {}", u.tx_hash))?, vout: u.tx_pos })
}

/// Minting NFTs of the manifest's category at `lock`, with their raw commitments.
fn minting_at(c: &mut ElectrumClient, m: &Manifest, lock: &[u8]) -> Result<Vec<(Utxo, Vec<u8>)>> {
    let sh = electrum_scripthash(lock);
    let mut out = Vec::new();
    for u in c.list_unspent_by_scripthash(&sh)? {
        let Some(td) = &u.token_data else { continue };
        if td.category != m.category {
            continue;
        }
        let Some(nft) = &td.nft else { continue };
        if nft.capability != NftCapability::Minting {
            continue;
        }
        let raw = hex::decode(&nft.commitment)?;
        out.push((u, raw));
    }
    Ok(out)
}

/// The current v27 head: the minting NFT of the manifest's category at the Oracle lock. Every
/// deployment shares the lock, so the category filter is what selects ours. When an unconfirmed
/// chain exists only the newest unspent head is returned by Fulcrum.
pub async fn find_head(m: &Manifest) -> Result<Option<HeadUtxo>> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<Option<HeadUtxo>> {
        let mut c = connect(&m)?;
        let mut best: Option<HeadUtxo> = None;
        for (u, raw) in minting_at(&mut c, &m, &hex::decode(&m.oracle_lock)?)? {
            let Ok(commit) = HeadCommit::decode(&raw) else { continue };
            let h = HeadUtxo { outpoint: outpoint(&u)?, value: u.value, commit, raw, category: m.category_bytes() };
            if best.as_ref().map(|b| h.commit.snapshot.seq > b.commit.snapshot.seq || (h.commit.snapshot.seq == b.commit.snapshot.seq && h.commit.snapshot.ts > b.commit.snapshot.ts)).unwrap_or(true) {
                best = Some(h);
            }
        }
        Ok(best)
    })
    .await?
}

/// The v26 head of the manifest's category, for the migration.
pub async fn find_legacy_head(m: &Manifest) -> Result<Option<LegacyHeadUtxo>> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<Option<LegacyHeadUtxo>> {
        let mut c = connect(&m)?;
        let mut best: Option<LegacyHeadUtxo> = None;
        for (u, raw) in minting_at(&mut c, &m, &legacy_scripts::oracle26_lock())? {
            let Ok(commit) = legacy::HeadCommit26::decode(&raw) else { continue };
            let h = LegacyHeadUtxo { outpoint: outpoint(&u)?, value: u.value, commit, raw, category: m.category_bytes() };
            if best.as_ref().map(|b| h.commit.snapshot.seq > b.commit.snapshot.seq).unwrap_or(true) {
                best = Some(h);
            }
        }
        Ok(best)
    })
    .await?
}

/// Tickers of the manifest's category, at the v27 lock and at the v26 lock, whose lifetime is up
/// by median-time-past `mtp`: oldest first, at most `max`. A transaction is final only while its
/// locktime is below the tip's MTP, so a Ticker qualifies when its recycle time is strictly below it.
pub async fn find_recyclable_tickers(m: &Manifest, mtp: u64, max: usize) -> Result<Vec<TickerUtxo>> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<Vec<TickerUtxo>> {
        let mut c = connect(&m)?;
        let mut out = Vec::new();
        for (lock, is_legacy) in [(ticker_lock(), false), (legacy_scripts::ticker26_lock(), true)] {
            let sh = electrum_scripthash(&lock);
            for u in c.list_unspent_by_scripthash(&sh)? {
                let Some(td) = &u.token_data else { continue };
                if td.category != m.category {
                    continue;
                }
                let Some(nft) = &td.nft else { continue };
                if nft.capability != NftCapability::None {
                    continue;
                }
                let raw = hex::decode(&nft.commitment)?;
                let t = if is_legacy {
                    let Ok(snap) = legacy::Snapshot26::decode(&raw) else { continue };
                    TickerUtxo::v26(outpoint(&u)?, u.value, snap)
                } else {
                    let Ok(snap) = Snapshot::decode(&raw) else { continue };
                    TickerUtxo::v27(outpoint(&u)?, u.value, snap, raw)
                };
                if t.recyclable_at < mtp {
                    out.push(t);
                }
            }
        }
        out.sort_by_key(|t| t.recyclable_at);
        out.truncate(max);
        Ok(out)
    })
    .await?
}

/// Plain P2PKH coins of the operator key (no tokens), largest first.
pub async fn find_coins(m: &Manifest, pkh: [u8; 20]) -> Result<Vec<(TxOutpoint, u64, i64)>> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<Vec<(TxOutpoint, u64, i64)>> {
        let mut c = connect(&m)?;
        let sh = electrum_scripthash(&p2pkh_locking_script(&pkh));
        let utxos = c.list_unspent_by_scripthash(&sh)?;
        let mut out = Vec::new();
        for u in utxos {
            if u.token_data.is_some() {
                continue;
            }
            out.push((outpoint(&u)?, u.value, u.height));
        }
        out.sort_by(|a, b| b.1.cmp(&a.1));
        Ok(out)
    })
    .await?
}

pub async fn broadcast(m: &Manifest, raw: Vec<u8>) -> Result<String> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<String> {
        let mut c = connect(&m)?;
        Ok(c.broadcast_raw(&raw)?)
    })
    .await?
}

pub async fn tip_height(m: &Manifest) -> Result<u64> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<u64> {
        let mut c = connect(&m)?;
        Ok(c.tip_height()?)
    })
    .await?
}

pub async fn median_time_past(m: &Manifest) -> Result<u64> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<u64> {
        let mut c = connect(&m)?;
        Ok(c.median_time_past()?)
    })
    .await?
}
