//! The transactions v27 ever builds: genesis, update, rotate, and the one-time migration of a v26
//! head. Updates may carry Ticker inputs being recycled (v27 or leftover v26) and P2PKH inputs
//! topping the reserve up.
//!
//! Fee policy: exactly `size + 1` sat. Every transaction here is fixed-width before signing
//! (Schnorr signatures are 64 B, the Oracle input carries no transaction signature), so the size
//! is computed once from a fully laid-out draft and never estimated.

use crate::commit::{legacy, HeadCommit, Snapshot};
use crate::crypto::schnorr_sign;
use crate::statement::{Approval, Statement};
use crate::tx::covenant::{legacy as legacy_scripts, oracle_lock, oracle_redeem, table_entry, table_hash, table_rows, ticker_lock};
use crate::tx::encode::{encode_tx, Input, Output, TokenPrefix, Tx, TxOutpoint, MINTING_CAPABILITY, NO_CAPABILITY};
use crate::tx::script::{p2pkh_locking_script, push_data, push_int};
use crate::tx::sighash::{sighash_digest, SpentOutput, SIGHASH_ALL_UTXOS_FORKID};
use crate::{FEE_CAP_BASE_SATS, FEE_CAP_PER_UNLOCK_BYTE, MAX_ROWS, QUORUM, SEQUENCE_TIMELOCK, SEQ_AHEAD_SECS, TICKERS_PER_UPDATE, TICKER_SATS};

/// P2PKH dust floor.
pub const P2PKH_DUST: u64 = 546;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("need at least {QUORUM} statements, have {0}")]
    Quorum(usize),
    #[error("statements must share one timestamp (found {0} and {1})")]
    MixedTimestamp(u32, u32),
    #[error("timestamp {new} is not greater than the head's {old}")]
    StaleTimestamp { new: u32, old: u32 },
    #[error("no table row reads source {0}, or its signature does not verify")]
    NoRow(u8),
    #[error("two statements for table row {0}")]
    DuplicateRow(u8),
    #[error("table does not hash to the head's commitment")]
    TableHash,
    #[error("table has {0} rows; 1..={MAX_ROWS} allowed")]
    TableRows(usize),
    #[error("fee {fee} exceeds the covenant cap {cap}")]
    FeeCap { fee: u64, cap: u64 },
    #[error("inputs ({0} sats) cannot cover fee and tickers")]
    Insufficient(u64),
    #[error("{have} approvals is not a majority of {rows} rows")]
    NotMajority { have: usize, rows: usize },
    #[error("approval from {0} does not match a table row or does not verify")]
    Approval(String),
    #[error("signing failed: {0}")]
    Key(#[from] crate::crypto::KeyError),
    #[error("genesis funding input must be vout 0 (CashTokens category genesis)")]
    GenesisVout,
}

/// A v27 head. `raw` is the commitment exactly as it sits on chain: a head fresh from migration
/// carries v26 bytes in fields the decoder ignores, and `rotate()` compares those bytes verbatim.
#[derive(Debug, Clone)]
pub struct HeadUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub commit: HeadCommit,
    pub raw: Vec<u8>,
    /// Category in display order.
    pub category: [u8; 32],
}

/// A v26 head, spendable only into the v27 lock (`build_migration`).
#[derive(Debug, Clone)]
pub struct LegacyHeadUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub commit: legacy::HeadCommit26,
    pub raw: Vec<u8>,
    pub category: [u8; 32],
}

/// A Ticker being recycled, of either generation: its lock and commitment bytes for the sighash,
/// and the median-time-past from which the covenant lets it go.
#[derive(Debug, Clone)]
pub struct TickerUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub lock: Vec<u8>,
    pub commitment: Vec<u8>,
    pub recyclable_at: u64,
}

impl TickerUtxo {
    pub fn v27(outpoint: TxOutpoint, value: u64, snapshot: Snapshot, raw_commitment: Vec<u8>) -> Self {
        TickerUtxo { outpoint, value, lock: ticker_lock(), commitment: raw_commitment, recyclable_at: snapshot.recyclable_at() }
    }
    pub fn v26(outpoint: TxOutpoint, value: u64, snapshot: legacy::Snapshot26) -> Self {
        TickerUtxo { outpoint, value, lock: legacy_scripts::ticker26_lock(), commitment: snapshot.encode().to_vec(), recyclable_at: snapshot.recyclable_at() }
    }
}

/// A P2PKH coin plus the key that spends it (reserve top-ups, genesis funding).
#[derive(Clone)]
pub struct P2pkhInput {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub private_key: [u8; 32],
    pub public_key: [u8; 33],
    pub pkh: [u8; 20],
}

impl std::fmt::Debug for P2pkhInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pkhInput").field("outpoint", &self.outpoint).field("value", &self.value).finish()
    }
}

#[derive(Debug, Clone)]
pub struct BuiltTx {
    pub tx: Tx,
    pub raw: Vec<u8>,
    pub txid: [u8; 32],
    pub size: usize,
    pub fee: u64,
}

fn finish(tx: Tx, fee: u64) -> BuiltTx {
    let raw = encode_tx(&tx);
    let txid = crate::tx::encode::txid_be(&raw);
    let size = raw.len();
    BuiltTx { tx, raw, txid, size, fee }
}

fn category_le(category_display: &[u8; 32]) -> [u8; 32] {
    let mut c = *category_display;
    c.reverse();
    c
}

/// Lower median of the statement prices (unique for any k).
pub fn lower_median(prices: &[u32]) -> u32 {
    let mut s = prices.to_vec();
    s.sort_unstable();
    s[(s.len() - 1) / 2]
}

/// Keys needed to forge a minute that `k` rows signed: the lower median's rank plus one.
pub fn keys_to_forge(k: usize) -> usize {
    (k - 1) / 2 + 1
}

fn check_table(table: &[u8], table_hash_on_chain: &[u8; 20]) -> Result<usize, BuildError> {
    let n = table_rows(table);
    if n == 0 || n > MAX_ROWS || table.len() % crate::TABLE_ENTRY_LEN != 0 {
        return Err(BuildError::TableRows(n));
    }
    if table_hash(table) != *table_hash_on_chain {
        return Err(BuildError::TableHash);
    }
    Ok(n)
}

/// Place each statement on its table row (by source byte and signature), validate the set, and
/// return `(row, statement)` sorted by row.
pub fn select_statements(head: &HeadUtxo, table: &[u8], statements: &[Statement]) -> Result<Vec<(u8, Statement)>, BuildError> {
    let n = check_table(table, &head.commit.table_hash)?;
    if statements.len() < QUORUM {
        return Err(BuildError::Quorum(statements.len()));
    }
    let ts = statements[0].ts;
    if ts <= head.commit.snapshot.ts {
        return Err(BuildError::StaleTimestamp { new: ts, old: head.commit.snapshot.ts });
    }
    let mut placed: Vec<(u8, Statement)> = Vec::with_capacity(statements.len());
    for s in statements {
        if s.ts != ts {
            return Err(BuildError::MixedTimestamp(ts, s.ts));
        }
        let mut row = None;
        for r in 0..n as u8 {
            let (pk, source) = table_entry(table, r).unwrap();
            if source == s.source && s.verify(&pk) {
                row = Some(r);
                break;
            }
        }
        let r = row.ok_or(BuildError::NoRow(s.source))?;
        if placed.iter().any(|(pr, _)| *pr == r) {
            return Err(BuildError::DuplicateRow(r));
        }
        placed.push((r, s.clone()));
    }
    placed.sort_by_key(|(r, _)| *r);
    Ok(placed)
}

/// The locktime an update must carry: at least six hours before its minute, and past the recycle
/// time of every Ticker it spends.
pub fn update_locktime(ts: u32, recycled: &[TickerUtxo]) -> u32 {
    let mut lt = (ts as u64).saturating_sub(SEQ_AHEAD_SECS);
    for t in recycled {
        lt = lt.max(t.recyclable_at);
    }
    lt as u32
}

fn p2pkh_placeholder(public_key: &[u8; 33]) -> Vec<u8> {
    let mut placeholder = Vec::with_capacity(100);
    push_data(&mut placeholder, &[0u8; 65]);
    push_data(&mut placeholder, public_key);
    placeholder
}

fn sign_p2pkh_inputs(tx: &mut Tx, sources: &[SpentOutput], signers: &[(usize, &P2pkhInput)]) -> Result<(), BuildError> {
    for (idx, t) in signers {
        let script_code = p2pkh_locking_script(&t.pkh);
        let digest = sighash_digest(tx, *idx, &script_code, sources, SIGHASH_ALL_UTXOS_FORKID);
        let sig = schnorr_sign(&t.private_key, &digest)?;
        let mut sig_ht = sig.to_vec();
        sig_ht.push(SIGHASH_ALL_UTXOS_FORKID);
        let mut unlock = Vec::with_capacity(100);
        push_data(&mut unlock, &sig_ht);
        push_data(&mut unlock, &t.public_key);
        tx.inputs[*idx].unlock_script = unlock;
    }
    Ok(())
}

fn fee_cap(unlock_len: usize) -> u64 {
    FEE_CAP_BASE_SATS + FEE_CAP_PER_UNLOCK_BYTE * unlock_len as u64
}

/// Build the update transaction. `recycled` Tickers must already be old enough by median-time-past
/// (the caller checks the chain); `topups` are P2PKH coins whose whole value joins the reserve.
pub fn build_update(head: &HeadUtxo, table: &[u8], statements: &[Statement], recycled: &[TickerUtxo], topups: &[P2pkhInput]) -> Result<BuiltTx, BuildError> {
    let placed = select_statements(head, table, statements)?;
    let ts = placed[0].1.ts;
    let k = placed.len();
    let prices: Vec<u32> = placed.iter().map(|(_, s)| s.price).collect();
    let median = lower_median(&prices);

    // unlocking: push(median) push(sigs) push(prices) push(rows) push(ts) push(table) OP_0 push(redeem)
    let mut sigs = Vec::with_capacity(64 * k);
    let mut price_bytes = Vec::with_capacity(4 * k);
    let mut rows = Vec::with_capacity(k);
    for (r, s) in &placed {
        sigs.extend_from_slice(&s.sig_bytes().expect("validated"));
        price_bytes.extend_from_slice(&s.price.to_le_bytes());
        rows.push(*r);
    }
    let mut unlock = Vec::with_capacity(2000);
    push_data(&mut unlock, &median.to_le_bytes());
    push_data(&mut unlock, &sigs);
    push_data(&mut unlock, &price_bytes);
    push_data(&mut unlock, &rows);
    push_data(&mut unlock, &ts.to_le_bytes());
    push_data(&mut unlock, table);
    push_int(&mut unlock, 0);
    push_data(&mut unlock, &oracle_redeem());
    let unlock_len = unlock.len();

    let snapshot = Snapshot { ts, seq: head.commit.snapshot.seq + 1, price: median, k: k as u8 };
    let commit = HeadCommit { snapshot, table_hash: head.commit.table_hash };
    let cat_le = category_le(&head.category);
    let lock = oracle_lock().to_vec();

    let mut inputs = vec![Input { prev: head.outpoint, unlock_script: unlock, sequence: SEQUENCE_TIMELOCK }];
    let mut sources = vec![SpentOutput {
        value: head.value,
        locking_script: lock.clone(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: head.raw.clone(), amount: 0 }),
    }];
    let mut total = head.value;
    for t in recycled {
        let mut u = Vec::with_capacity(1);
        push_int(&mut u, 1); // Ticker.recycle, same selector in both generations
        inputs.push(Input { prev: t.outpoint, unlock_script: u, sequence: SEQUENCE_TIMELOCK });
        sources.push(SpentOutput {
            value: t.value,
            locking_script: t.lock.clone(),
            token: Some(TokenPrefix { category_le: cat_le, capability: NO_CAPABILITY, commitment: t.commitment.clone(), amount: 0 }),
        });
        total += t.value;
    }
    let mut signers = Vec::with_capacity(topups.len());
    for t in topups {
        signers.push((inputs.len(), t));
        inputs.push(Input { prev: t.outpoint, unlock_script: p2pkh_placeholder(&t.public_key), sequence: SEQUENCE_TIMELOCK });
        sources.push(SpentOutput { value: t.value, locking_script: p2pkh_locking_script(&t.pkh).to_vec(), token: None });
        total += t.value;
    }

    let mut outputs = vec![Output {
        value: 0, // set after sizing
        locking_script: lock,
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: commit.encode().to_vec(), amount: 0 }),
    }];
    for _ in 0..TICKERS_PER_UPDATE {
        outputs.push(Output {
            value: TICKER_SATS,
            locking_script: ticker_lock(),
            token: Some(TokenPrefix { category_le: cat_le, capability: NO_CAPABILITY, commitment: snapshot.encode().to_vec(), amount: 0 }),
        });
    }
    let mut tx = Tx::new(inputs, outputs);
    tx.locktime = update_locktime(ts, recycled);
    let size = encode_tx(&tx).len() as u64;
    let fee = size + 1;
    let cap = fee_cap(unlock_len);
    if fee > cap {
        return Err(BuildError::FeeCap { fee, cap });
    }
    let spend = fee + TICKER_SATS * TICKERS_PER_UPDATE as u64;
    if total < spend {
        return Err(BuildError::Insufficient(total));
    }
    tx.outputs[0].value = total - spend;
    sign_p2pkh_inputs(&mut tx, &sources, &signers)?;
    let built = finish(tx, fee);
    debug_assert_eq!(built.size as u64, size, "signed size must equal the sized draft");
    Ok(built)
}

/// Verify approvals against the table at `table_hash_on_chain` and return `(row, sig)` sorted.
fn place_approvals(table: &[u8], table_hash_on_chain: &[u8; 20], cat_vm: &[u8; 32], next_lock: &[u8], tail: &[u8], approvals: &[Approval]) -> Result<Vec<(u8, [u8; 64])>, BuildError> {
    let n = check_table(table, table_hash_on_chain)?;
    let mut placed: Vec<(u8, [u8; 64])> = Vec::with_capacity(approvals.len());
    for a in approvals {
        let pk = a.pubkey_bytes().ok_or_else(|| BuildError::Approval(a.pubkey.clone()))?;
        let row = (0..n as u8).find(|r| table_entry(table, *r).map(|(p, _)| p == pk).unwrap_or(false)).ok_or_else(|| BuildError::Approval(a.pubkey.clone()))?;
        if !a.verify(cat_vm, table_hash_on_chain, next_lock, tail) {
            return Err(BuildError::Approval(a.pubkey.clone()));
        }
        if placed.iter().any(|(r, _)| *r == row) {
            return Err(BuildError::DuplicateRow(row));
        }
        placed.push((row, a.sig_bytes().expect("verified")));
    }
    if placed.len() * 2 <= n {
        return Err(BuildError::NotMajority { have: placed.len(), rows: n });
    }
    placed.sort_by_key(|(r, _)| *r);
    Ok(placed)
}

/// The rotation transaction shared by both generations: input 0 the head under `redeem` and
/// `lock_in`, output 0 the head at `next_lock` with commitment `state ‖ tail`.
#[allow(clippy::too_many_arguments)]
fn rotate_generic(outpoint: TxOutpoint, value: u64, raw_commit: &[u8], state: &[u8], category: &[u8; 32], lock_in: &[u8], redeem: &[u8], table: &[u8], placed: &[(u8, [u8; 64])], next_lock: &[u8], tail: &[u8], topups: &[P2pkhInput]) -> Result<BuiltTx, BuildError> {
    // unlocking: push(sigs) push(rows) push(table) OP_1 push(redeem)
    let mut sigs = Vec::with_capacity(64 * placed.len());
    let mut rows = Vec::with_capacity(placed.len());
    for (r, s) in placed {
        sigs.extend_from_slice(s);
        rows.push(*r);
    }
    let mut unlock = Vec::with_capacity(1500);
    push_data(&mut unlock, &sigs);
    push_data(&mut unlock, &rows);
    push_data(&mut unlock, table);
    push_int(&mut unlock, 1);
    push_data(&mut unlock, redeem);
    let unlock_len = unlock.len();

    let cat_le = category_le(category);
    let mut commitment = state.to_vec();
    commitment.extend_from_slice(tail);
    let mut inputs = vec![Input { prev: outpoint, unlock_script: unlock, sequence: SEQUENCE_TIMELOCK }];
    let mut sources = vec![SpentOutput {
        value,
        locking_script: lock_in.to_vec(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: raw_commit.to_vec(), amount: 0 }),
    }];
    let mut total = value;
    let mut signers = Vec::with_capacity(topups.len());
    for t in topups {
        signers.push((inputs.len(), t));
        inputs.push(Input { prev: t.outpoint, unlock_script: p2pkh_placeholder(&t.public_key), sequence: SEQUENCE_TIMELOCK });
        sources.push(SpentOutput { value: t.value, locking_script: p2pkh_locking_script(&t.pkh).to_vec(), token: None });
        total += t.value;
    }
    let outputs = vec![Output {
        value: 0,
        locking_script: next_lock.to_vec(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment, amount: 0 }),
    }];
    let mut tx = Tx::new(inputs, outputs);
    let size = encode_tx(&tx).len() as u64;
    let fee = size + 1;
    let cap = fee_cap(unlock_len);
    if fee > cap {
        return Err(BuildError::FeeCap { fee, cap });
    }
    if total < fee + P2PKH_DUST {
        return Err(BuildError::Insufficient(total));
    }
    tx.outputs[0].value = total - fee;
    sign_p2pkh_inputs(&mut tx, &sources, &signers)?;
    Ok(finish(tx, fee))
}

/// Build a rotation of a v27 head: it moves to `next_lock` with commitment `snapshot ‖ tail`,
/// approved by a majority of the current rows. Same lock and a new table hash as tail is a table
/// change; a P2PKH with an empty tail is retirement.
pub fn build_rotate(head: &HeadUtxo, table: &[u8], next_lock: &[u8], tail: &[u8], approvals: &[Approval], topups: &[P2pkhInput]) -> Result<BuiltTx, BuildError> {
    let cat_vm = category_le(&head.category);
    let placed = place_approvals(table, &head.commit.table_hash, &cat_vm, next_lock, tail, approvals)?;
    rotate_generic(head.outpoint, head.value, &head.raw, &head.raw[..crate::commit::SNAPSHOT_LEN], &head.category, &oracle_lock(), &oracle_redeem(), table, &placed, next_lock, tail, topups)
}

/// The tail a v26 head migrates with: four filler bytes so that the table hash lands where the
/// v27 covenant reads it, at bytes 17..37. The v26 price's high dword then sits where v27 reads
/// its counter, so the first v27 update continues the counter from there.
pub fn migration_tail(table_hash_on_chain: &[u8; 20]) -> Vec<u8> {
    let mut tail = vec![0u8; 4];
    tail.extend_from_slice(table_hash_on_chain);
    tail
}

/// Build the one-time migration: a v26 head rotates into the v27 lock under the v26 rules.
pub fn build_migration(head: &LegacyHeadUtxo, table: &[u8], approvals: &[Approval], topups: &[P2pkhInput]) -> Result<BuiltTx, BuildError> {
    let cat_vm = category_le(&head.category);
    let next_lock = oracle_lock();
    let tail = migration_tail(&head.commit.table_hash);
    let placed = place_approvals(table, &head.commit.table_hash, &cat_vm, &next_lock, &tail, approvals)?;
    rotate_generic(head.outpoint, head.value, &head.raw, &head.raw[..legacy::SNAPSHOT_LEN], &head.category, &legacy_scripts::oracle26_lock(), &legacy_scripts::oracle26_redeem(), table, &placed, &next_lock, &tail, topups)
}

/// Genesis: spend `funding` (which must be output 0 of its transaction, so its txid becomes the
/// category) into the head with `reserve` sats and the table's hash, and return change. The
/// counter starts at 0 so the first update writes dataSequence 1.
pub fn build_genesis(funding: &P2pkhInput, table_hash: &[u8; 20], reserve: u64, initial_ts: u32) -> Result<BuiltTx, BuildError> {
    if funding.outpoint.vout != 0 {
        return Err(BuildError::GenesisVout);
    }
    let category = funding.outpoint.txid_be;
    let cat_le = category_le(&category);
    let commit = HeadCommit { snapshot: Snapshot { ts: initial_ts, seq: 0, price: 0, k: 0 }, table_hash: *table_hash };
    let inputs = vec![Input { prev: funding.outpoint, unlock_script: p2pkh_placeholder(&funding.public_key), sequence: SEQUENCE_TIMELOCK }];
    let outputs = vec![
        Output { value: reserve, locking_script: oracle_lock().to_vec(), token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: commit.encode().to_vec(), amount: 0 }) },
        Output { value: 0, locking_script: p2pkh_locking_script(&funding.pkh).to_vec(), token: None },
    ];
    let mut tx = Tx::new(inputs, outputs);
    let size = encode_tx(&tx).len() as u64;
    let fee = size + 1;
    if funding.value < reserve + fee + P2PKH_DUST {
        return Err(BuildError::Insufficient(funding.value));
    }
    tx.outputs[1].value = funding.value - reserve - fee;
    let sources = vec![SpentOutput { value: funding.value, locking_script: p2pkh_locking_script(&funding.pkh).to_vec(), token: None }];
    sign_p2pkh_inputs(&mut tx, &sources, &[(0, funding)])?;
    Ok(finish(tx, fee))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_pubkey, hash160};

    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../contracts/test/v27-vectors.json")).unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn head_from(v: &serde_json::Value) -> (HeadUtxo, Vec<u8>) {
        let table = hex::decode(v["table"].as_str().unwrap()).unwrap();
        let h = &v["head"];
        let commit = HeadCommit {
            snapshot: Snapshot { ts: h["ts"].as_u64().unwrap() as u32, seq: h["seq"].as_u64().unwrap() as u32, price: h["price"].as_u64().unwrap() as u32, k: h["k"].as_u64().unwrap() as u8 },
            table_hash: table_hash(&table),
        };
        let head = HeadUtxo {
            outpoint: TxOutpoint { txid_be: hex32(h["txid"].as_str().unwrap()), vout: h["vout"].as_u64().unwrap() as u32 },
            value: h["value"].as_str().unwrap().parse().unwrap(),
            raw: commit.encode().to_vec(),
            commit,
            category: hex32(v["category"].as_str().unwrap()),
        };
        (head, table)
    }

    fn statements_from(v: &serde_json::Value) -> Vec<Statement> {
        v.as_array().unwrap().iter().map(|s| Statement { source: s["source"].as_u64().unwrap() as u8, ts: s["ts"].as_u64().unwrap() as u32, price: s["price"].as_u64().unwrap() as u32, sig: s["sig"].as_str().unwrap().to_string() }).collect()
    }

    fn p2pkh_from(v: &serde_json::Value) -> P2pkhInput {
        let sk = hex32(v["private_key"].as_str().unwrap());
        let pk = derive_pubkey(&sk).unwrap();
        P2pkhInput { outpoint: TxOutpoint { txid_be: hex32(v["txid"].as_str().unwrap()), vout: v["vout"].as_u64().unwrap() as u32 }, value: v["value"].as_str().unwrap().parse().unwrap(), private_key: sk, public_key: pk, pkh: hash160(&pk) }
    }

    fn keys_from(v: &serde_json::Value) -> Vec<[u8; 32]> {
        v["keys"].as_array().unwrap().iter().map(|k| hex32(k.as_str().unwrap())).collect()
    }

    #[test]
    fn vectors_keys_and_statements_are_ours() {
        let v = vectors();
        let (_head, table) = head_from(&v);
        let keys = keys_from(&v);
        for (i, st) in statements_from(&v["update_k13"]["statements"]).iter().enumerate() {
            let (pk, source) = table_entry(&table, i as u8).unwrap();
            assert_eq!(derive_pubkey(&keys[i]).unwrap(), pk);
            assert_eq!(source, st.source);
            assert!(st.verify(&pk));
            let ours = Statement::sign(&keys[i], st.source, st.ts, st.price).unwrap();
            assert_eq!(&ours, st, "row {i}: RFC 6979 nonce must match libauth");
        }
    }

    #[test]
    fn update_k13_matches_sdk_vector() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let st = statements_from(&v["update_k13"]["statements"]);
        let b = build_update(&head, &table, &st, &[], &[]).unwrap();
        assert_eq!(b.size, v["update_k13"]["size"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(&b.raw), v["update_k13"]["tx"].as_str().unwrap());
        assert_eq!(b.fee, b.size as u64 + 1);
        let c = HeadCommit::decode(&b.tx.outputs[0].token.as_ref().unwrap().commitment).unwrap();
        assert_eq!(c.snapshot, Snapshot { ts: 1_792_200_060, seq: 1001, price: 29_000, k: 13 });
        assert!(Snapshot::is_canonical(&b.tx.outputs[1].token.as_ref().unwrap().commitment));
        assert_eq!(b.tx.locktime, 1_792_200_060 - 21_600);
    }

    /// A day-old v27 Ticker carrying tolls, an hour-old v26 Ticker at the legacy lock, and a
    /// P2PKH top-up: exercises both Ticker generations in one update plus the sighash.
    #[test]
    fn update_with_recycle_and_topup_matches_sdk_vector() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let u = &v["update_recycle_topup"];
        let st = statements_from(&u["statements"]);
        let mut recycled = Vec::new();
        for t in u["recycled_v27"].as_array().unwrap() {
            let snap = Snapshot { ts: t["ts"].as_u64().unwrap() as u32, seq: t["seq"].as_u64().unwrap() as u32, price: t["price"].as_u64().unwrap() as u32, k: t["k"].as_u64().unwrap() as u8 };
            recycled.push(TickerUtxo::v27(TxOutpoint { txid_be: hex32(t["txid"].as_str().unwrap()), vout: t["vout"].as_u64().unwrap() as u32 }, t["value"].as_str().unwrap().parse().unwrap(), snap, snap.encode().to_vec()));
        }
        for t in u["recycled_v26"].as_array().unwrap() {
            let snap = legacy::Snapshot26 { seq: t["seq"].as_u64().unwrap() as u32, price: t["price"].as_str().unwrap().parse().unwrap(), k: t["k"].as_u64().unwrap() as u8 };
            recycled.push(TickerUtxo::v26(TxOutpoint { txid_be: hex32(t["txid"].as_str().unwrap()), vout: t["vout"].as_u64().unwrap() as u32 }, t["value"].as_str().unwrap().parse().unwrap(), snap));
        }
        let topup = p2pkh_from(&u["topup"]);
        let b = build_update(&head, &table, &st, &recycled, &[topup]).unwrap();
        assert_eq!(b.size, u["size"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(&b.raw), u["tx"].as_str().unwrap());
        assert_eq!(b.tx.locktime as u64, recycled.iter().map(|t| t.recyclable_at).max().unwrap());
        assert!(b.tx.outputs[0].value > head.value);
    }

    #[test]
    fn rotate_matches_sdk_vector() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let r = &v["rotate"];
        let new_table = hex::decode(r["new_table"].as_str().unwrap()).unwrap();
        let tail = table_hash(&new_table);
        let lock = oracle_lock();
        let keys = keys_from(&v);
        let cat_vm = category_le(&head.category);
        let approvals: Vec<Approval> = r["signers"].as_array().unwrap().iter().zip(r["approvals"].as_array().unwrap()).map(|(s, sig)| {
            let i = s.as_u64().unwrap() as usize;
            let a = Approval::sign(&keys[i], &derive_pubkey(&keys[i]).unwrap(), &cat_vm, &head.commit.table_hash, &lock, &tail).unwrap();
            assert_eq!(a.sig, sig.as_str().unwrap(), "approval signature must match libauth");
            a
        }).collect();
        let b = build_rotate(&head, &table, &lock, &tail, &approvals, &[]).unwrap();
        assert_eq!(b.size, r["size"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(&b.raw), r["tx"].as_str().unwrap());
        assert_eq!(build_rotate(&head, &table, &lock, &tail, &approvals[..6], &[]).unwrap_err(), BuildError::NotMajority { have: 6, rows: 13 });
        let bad = Approval::sign(&keys[0], &derive_pubkey(&keys[0]).unwrap(), &cat_vm, &head.commit.table_hash, &[0x76], &tail).unwrap();
        assert!(matches!(build_rotate(&head, &table, &lock, &tail, &[bad], &[]).unwrap_err(), BuildError::Approval(_)));
    }

    /// The live path: the v26 head rotates into the v27 lock under the v26 covenant.
    #[test]
    fn migration_matches_sdk_vector() {
        let v = vectors();
        let table = hex::decode(v["table"].as_str().unwrap()).unwrap();
        let m = &v["migrate"];
        let h = &m["head26"];
        let commit = legacy::HeadCommit26 { snapshot: legacy::Snapshot26 { seq: h["seq"].as_u64().unwrap() as u32, price: h["price"].as_str().unwrap().parse().unwrap(), k: h["k"].as_u64().unwrap() as u8 }, table_hash: table_hash(&table) };
        let head = LegacyHeadUtxo {
            outpoint: TxOutpoint { txid_be: hex32(h["txid"].as_str().unwrap()), vout: 0 },
            value: h["value"].as_str().unwrap().parse().unwrap(),
            raw: commit.encode().to_vec(),
            commit,
            category: hex32(v["category"].as_str().unwrap()),
        };
        let tail = migration_tail(&commit.table_hash);
        assert_eq!(hex::encode(&tail), m["tail"].as_str().unwrap());
        let keys = keys_from(&v);
        let cat_vm = category_le(&head.category);
        let approvals: Vec<Approval> = m["signers"].as_array().unwrap().iter().zip(m["approvals"].as_array().unwrap()).map(|(s, sig)| {
            let i = s.as_u64().unwrap() as usize;
            let a = Approval::sign(&keys[i], &derive_pubkey(&keys[i]).unwrap(), &cat_vm, &commit.table_hash, &oracle_lock(), &tail).unwrap();
            assert_eq!(a.sig, sig.as_str().unwrap());
            a
        }).collect();
        let b = build_migration(&head, &table, &approvals, &[]).unwrap();
        assert_eq!(b.size, m["size"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(&b.raw), m["tx"].as_str().unwrap());
        // the result decodes as a v27 head whose counter continues from the v26 price's high dword
        let out = &b.tx.outputs[0];
        assert_eq!(out.locking_script, oracle_lock().to_vec());
        let migrated = HeadCommit::decode(&out.token.as_ref().unwrap().commitment).unwrap();
        assert_eq!(migrated.snapshot.seq, (27_257_000_000u64 >> 32) as u32);
        assert_eq!(migrated.table_hash, commit.table_hash);
    }

    #[test]
    fn selection_errors() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let st = statements_from(&v["update_k13"]["statements"]);
        assert_eq!(build_update(&head, &table, &st[..6], &[], &[]).unwrap_err(), BuildError::Quorum(6));
        let mut stale = head.clone();
        stale.commit.snapshot.ts = 1_792_200_060;
        assert_eq!(build_update(&stale, &table, &st, &[], &[]).unwrap_err(), BuildError::StaleTimestamp { new: 1_792_200_060, old: 1_792_200_060 });
        let mut t = st.clone();
        t[3].price += 1;
        assert_eq!(build_update(&head, &table, &t, &[], &[]).unwrap_err(), BuildError::NoRow(16));
        let mut t = st.clone();
        t[7] = t[6].clone();
        assert_eq!(build_update(&head, &table, &t, &[], &[]).unwrap_err(), BuildError::DuplicateRow(6));
        let mut other = head.clone();
        other.commit.table_hash = [0u8; 20];
        assert_eq!(build_update(&other, &table, &st, &[], &[]).unwrap_err(), BuildError::TableHash);
    }

    #[test]
    fn lower_median_rule_and_forgery_threshold() {
        assert_eq!(lower_median(&[5, 1, 3]), 3);
        assert_eq!(lower_median(&[4, 1, 3, 2]), 2);
        assert_eq!(keys_to_forge(7), 4);
        assert_eq!(keys_to_forge(11), 6);
        assert_eq!(keys_to_forge(13), 7);
    }

    #[test]
    fn genesis_shape() {
        let v = vectors();
        let g = p2pkh_from(&v["genesis"]);
        let th = table_hash(&hex::decode(v["table"].as_str().unwrap()).unwrap());
        let b = build_genesis(&g, &th, 50_000_000, 1_792_200_000).unwrap();
        let tp = b.tx.outputs[0].token.as_ref().unwrap();
        assert_eq!(tp.capability, MINTING_CAPABILITY);
        let c = HeadCommit::decode(&tp.commitment).unwrap();
        assert_eq!(c, HeadCommit { snapshot: Snapshot { ts: 1_792_200_000, seq: 0, price: 0, k: 0 }, table_hash: th });
        assert_eq!(b.tx.outputs[1].value, 100_000_000 - 50_000_000 - b.fee);
        let bad = P2pkhInput { outpoint: TxOutpoint { txid_be: g.outpoint.txid_be, vout: 1 }, ..g };
        assert_eq!(build_genesis(&bad, &th, 5_000_000, 1).unwrap_err(), BuildError::GenesisVout);
    }
}
