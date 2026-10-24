//! Blocking Electrum calls wrapped for the async runtime, plus UTXO decoding against the
//! manifest. Fulcrum is untrusted: everything it returns is checked against the manifest's
//! locks, category and the commitment codec before use.

use std::time::Duration;

use anyhow::{anyhow, Result};
use ticker_core::commit::Commit;
use ticker_core::electrum::{ElectrumClient, Endpoint, NftCapability, Utxo};
use ticker_core::manifest::Manifest;
use ticker_core::tx::covenant::electrum_scripthash;
use ticker_core::tx::encode::TxOutpoint;
use ticker_core::tx::script::p2pkh_locking_script;
use ticker_core::tx::{HeadUtxo, TickerUtxo};

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

/// The current head: the minting NFT of the manifest's category at the Oracle lock. When an
/// unconfirmed chain exists only the newest unspent head is returned by Fulcrum.
pub async fn find_head(m: &Manifest) -> Result<Option<HeadUtxo>> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<Option<HeadUtxo>> {
        let mut c = connect(&m)?;
        let sh = electrum_scripthash(&hex::decode(&m.oracle_lock)?);
        let utxos = c.list_unspent_by_scripthash(&sh)?;
        let mut best: Option<HeadUtxo> = None;
        for u in utxos {
            let Some(td) = &u.token_data else { continue };
            if td.category != m.category {
                continue;
            }
            let Some(nft) = &td.nft else { continue };
            if nft.capability != NftCapability::Minting {
                continue;
            }
            let Ok(commit) = Commit::decode(&hex::decode(&nft.commitment)?) else { continue };
            let h = HeadUtxo { outpoint: outpoint(&u)?, value: u.value, commit, category: m.category_bytes() };
            if best.as_ref().map(|b| h.commit.seq > b.commit.seq).unwrap_or(true) {
                best = Some(h);
            }
        }
        Ok(best)
    })
    .await?
}

/// Tickers of the manifest's category at the Ticker lock, confirmed at least `min_age` blocks
/// ago (height known and `tip - height >= min_age`).
pub async fn find_sweepable_tickers(m: &Manifest, min_age: i64, max: usize) -> Result<Vec<TickerUtxo>> {
    let m = m.clone();
    tokio::task::spawn_blocking(move || -> Result<Vec<TickerUtxo>> {
        let mut c = connect(&m)?;
        let tip = c.tip_height()? as i64;
        let sh = electrum_scripthash(&hex::decode(&m.ticker_lock)?);
        let utxos = c.list_unspent_by_scripthash(&sh)?;
        let mut out = Vec::new();
        for u in utxos {
            let Some(td) = &u.token_data else { continue };
            if td.category != m.category || u.height <= 0 || tip - u.height < min_age {
                continue;
            }
            let Some(nft) = &td.nft else { continue };
            if nft.capability != NftCapability::None {
                continue;
            }
            let Ok(commit) = Commit::decode(&hex::decode(&nft.commitment)?) else { continue };
            out.push(TickerUtxo { outpoint: outpoint(&u)?, value: u.value, commit });
            if out.len() >= max {
                break;
            }
        }
        Ok(out)
    })
    .await?
}

/// Plain P2PKH coins of the operator key (no tokens).
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
