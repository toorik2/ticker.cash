//! The three transactions v26 ever builds: genesis, update, rotate. Updates may carry Ticker
//! inputs being recycled and P2PKH inputs topping the reserve up.
//!
//! Fee policy: exactly `size + 1` sat. Every transaction here is fixed-width before signing
//! (Schnorr signatures are 64 B, the Oracle input carries no transaction signature), so the size
//! is computed once from a fully laid-out draft and never estimated.

use crate::commit::{HeadCommit, Snapshot};
use crate::crypto::schnorr_sign;
use crate::statement::{Approval, Statement};
use crate::tx::covenant::{oracle_lock, oracle_redeem, table_entry, table_hash, table_rows, ticker_lock};
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
    #[error("statements must share one seq (found {0} and {1})")]
    MixedSeq(u32, u32),
    #[error("seq {new} is not greater than the head's {old}")]
    StaleSeq { new: u32, old: u32 },
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

#[derive(Debug, Clone)]
pub struct HeadUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub commit: HeadCommit,
    /// Category in display order.
    pub category: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TickerUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub snapshot: Snapshot,
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
pub fn lower_median(prices: &[u64]) -> u64 {
    let mut s = prices.to_vec();
    s.sort_unstable();
    s[(s.len() - 1) / 2]
}

/// Keys needed to forge a minute that `k` rows signed: the lower median's rank plus one.
pub fn keys_to_forge(k: usize) -> usize {
    (k - 1) / 2 + 1
}

fn check_table(head: &HeadUtxo, table: &[u8]) -> Result<usize, BuildError> {
    let n = table_rows(table);
    if n == 0 || n > MAX_ROWS || table.len() % crate::TABLE_ENTRY_LEN != 0 {
        return Err(BuildError::TableRows(n));
    }
    if table_hash(table) != head.commit.table_hash {
        return Err(BuildError::TableHash);
    }
    Ok(n)
}

/// Place each statement on its table row (by source byte and signature), validate the set, and
/// return `(row, statement)` sorted by row.
pub fn select_statements(head: &HeadUtxo, table: &[u8], statements: &[Statement]) -> Result<Vec<(u8, Statement)>, BuildError> {
    let n = check_table(head, table)?;
    if statements.len() < QUORUM {
        return Err(BuildError::Quorum(statements.len()));
    }
    let seq = statements[0].seq;
    if seq <= head.commit.snapshot.seq {
        return Err(BuildError::StaleSeq { new: seq, old: head.commit.snapshot.seq });
    }
    let cat_vm = category_le(&head.category);
    let mut placed: Vec<(u8, Statement)> = Vec::with_capacity(statements.len());
    for s in statements {
        if s.seq != seq {
            return Err(BuildError::MixedSeq(seq, s.seq));
        }
        let mut row = None;
        for r in 0..n as u8 {
            let (pk, source) = table_entry(table, r).unwrap();
            if source == s.source && s.verify(&cat_vm, &pk) {
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
pub fn update_locktime(seq: u32, recycled: &[TickerUtxo]) -> u32 {
    let mut lt = (seq as u64 * 60).saturating_sub(SEQ_AHEAD_SECS);
    for t in recycled {
        lt = lt.max(t.snapshot.recyclable_at());
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
    let seq = placed[0].1.seq;
    let k = placed.len();
    let prices: Vec<u64> = placed.iter().map(|(_, s)| s.price).collect();
    let median = lower_median(&prices);

    // unlocking: push(median) push(sigs) push(prices) push(rows) push(seq) push(table) OP_0 push(redeem)
    let mut sigs = Vec::with_capacity(64 * k);
    let mut price_bytes = Vec::with_capacity(8 * k);
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
    push_data(&mut unlock, &seq.to_le_bytes());
    push_data(&mut unlock, table);
    push_int(&mut unlock, 0);
    push_data(&mut unlock, &oracle_redeem());
    let unlock_len = unlock.len();

    let snapshot = Snapshot { seq, price: median, k: k as u8 };
    let commit = HeadCommit { snapshot, table_hash: head.commit.table_hash };
    let cat_le = category_le(&head.category);
    let lock = oracle_lock().to_vec();

    let mut inputs = vec![Input { prev: head.outpoint, unlock_script: unlock, sequence: SEQUENCE_TIMELOCK }];
    let mut sources = vec![SpentOutput {
        value: head.value,
        locking_script: lock.clone(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: head.commit.encode().to_vec(), amount: 0 }),
    }];
    let mut total = head.value;
    for t in recycled {
        let mut u = Vec::with_capacity(1);
        push_int(&mut u, 1); // Ticker.recycle
        inputs.push(Input { prev: t.outpoint, unlock_script: u, sequence: SEQUENCE_TIMELOCK });
        sources.push(SpentOutput {
            value: t.value,
            locking_script: ticker_lock(),
            token: Some(TokenPrefix { category_le: cat_le, capability: NO_CAPABILITY, commitment: t.snapshot.encode().to_vec(), amount: 0 }),
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
    tx.locktime = update_locktime(seq, recycled);
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

/// Build a rotation: the head moves to `next_lock` with commitment `snapshot ‖ tail`, approved by
/// a majority of the current rows. Same lock and a new table hash as tail is a table change.
pub fn build_rotate(head: &HeadUtxo, table: &[u8], next_lock: &[u8], tail: &[u8], approvals: &[Approval], topups: &[P2pkhInput]) -> Result<BuiltTx, BuildError> {
    let n = check_table(head, table)?;
    let cat_vm = category_le(&head.category);
    let mut placed: Vec<(u8, [u8; 64])> = Vec::with_capacity(approvals.len());
    for a in approvals {
        let pk = a.pubkey_bytes().ok_or_else(|| BuildError::Approval(a.pubkey.clone()))?;
        let row = (0..n as u8).find(|r| table_entry(table, *r).map(|(p, _)| p == pk).unwrap_or(false)).ok_or_else(|| BuildError::Approval(a.pubkey.clone()))?;
        if !a.verify(&cat_vm, &head.commit.table_hash, next_lock, tail) {
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

    // unlocking: push(sigs) push(rows) push(table) OP_1 push(redeem)
    let mut sigs = Vec::with_capacity(64 * placed.len());
    let mut rows = Vec::with_capacity(placed.len());
    for (r, s) in &placed {
        sigs.extend_from_slice(s);
        rows.push(*r);
    }
    let mut unlock = Vec::with_capacity(1500);
    push_data(&mut unlock, &sigs);
    push_data(&mut unlock, &rows);
    push_data(&mut unlock, table);
    push_int(&mut unlock, 1);
    push_data(&mut unlock, &oracle_redeem());
    let unlock_len = unlock.len();

    let cat_le = category_le(&head.category);
    let mut commitment = head.commit.snapshot.encode().to_vec();
    commitment.extend_from_slice(tail);
    let mut inputs = vec![Input { prev: head.outpoint, unlock_script: unlock, sequence: SEQUENCE_TIMELOCK }];
    let mut sources = vec![SpentOutput {
        value: head.value,
        locking_script: oracle_lock().to_vec(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: head.commit.encode().to_vec(), amount: 0 }),
    }];
    let mut total = head.value;
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

/// Genesis: spend `funding` (which must be output 0 of its transaction, so its txid becomes the
/// category) into the head with `reserve` sats and the table's hash, and return change.
pub fn build_genesis(funding: &P2pkhInput, table_hash: &[u8; 20], reserve: u64, initial_seq: u32) -> Result<BuiltTx, BuildError> {
    if funding.outpoint.vout != 0 {
        return Err(BuildError::GenesisVout);
    }
    let category = funding.outpoint.txid_be;
    let cat_le = category_le(&category);
    let commit = HeadCommit { snapshot: Snapshot { seq: initial_seq, price: 0, k: 0 }, table_hash: *table_hash };
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
        serde_json::from_str(include_str!("../../../../contracts/test/v26-vectors.json")).unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn head_from(v: &serde_json::Value) -> (HeadUtxo, Vec<u8>) {
        let table = hex::decode(v["table"].as_str().unwrap()).unwrap();
        let h = &v["head"];
        let head = HeadUtxo {
            outpoint: TxOutpoint { txid_be: hex32(h["txid"].as_str().unwrap()), vout: h["vout"].as_u64().unwrap() as u32 },
            value: h["value"].as_str().unwrap().parse().unwrap(),
            commit: HeadCommit {
                snapshot: Snapshot { seq: h["seq"].as_u64().unwrap() as u32, price: h["price"].as_str().unwrap().parse().unwrap(), k: h["k"].as_u64().unwrap() as u8 },
                table_hash: table_hash(&table),
            },
            category: hex32(v["category"].as_str().unwrap()),
        };
        (head, table)
    }

    fn statements_from(v: &serde_json::Value) -> Vec<Statement> {
        v.as_array().unwrap().iter().map(|s| Statement { source: s["source"].as_u64().unwrap() as u8, seq: s["seq"].as_u64().unwrap() as u32, price: s["price"].as_str().unwrap().parse().unwrap(), sig: s["sig"].as_str().unwrap().to_string() }).collect()
    }

    fn p2pkh_from(v: &serde_json::Value) -> P2pkhInput {
        let sk = hex32(v["private_key"].as_str().unwrap());
        let pk = derive_pubkey(&sk).unwrap();
        P2pkhInput { outpoint: TxOutpoint { txid_be: hex32(v["txid"].as_str().unwrap()), vout: v["vout"].as_u64().unwrap() as u32 }, value: v["value"].as_str().unwrap().parse().unwrap(), private_key: sk, public_key: pk, pkh: hash160(&pk) }
    }

    /// Our signatures must verify, so the SDK vectors' keys must derive the table's pubkeys and
    /// the statements must be the ones our signer would produce (deterministic nonces).
    #[test]
    fn vectors_keys_and_statements_are_ours() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let cat_vm = category_le(&head.category);
        let keys: Vec<[u8; 32]> = v["keys"].as_array().unwrap().iter().map(|k| hex32(k.as_str().unwrap())).collect();
        for (i, st) in statements_from(&v["update_k13"]["statements"]).iter().enumerate() {
            let (pk, source) = table_entry(&table, i as u8).unwrap();
            assert_eq!(derive_pubkey(&keys[i]).unwrap(), pk);
            assert_eq!(source, st.source);
            assert!(st.verify(&cat_vm, &pk));
            let ours = Statement::sign(&keys[i], &cat_vm, st.source, st.seq, st.price).unwrap();
            assert_eq!(&ours, st, "row {i}: RFC 6979 nonce must match libauth");
        }
    }

    /// The whole update transaction, byte for byte, against the cashscript SDK.
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
        assert_eq!(c.snapshot.k, 13);
        assert_eq!(c.snapshot.seq, 29_870_001);
        let prices: Vec<u64> = st.iter().map(|s| s.price).collect();
        assert_eq!(c.snapshot.price, lower_median(&prices));
        assert_eq!(b.tx.locktime, 29_870_001 * 60 - 21_600);
    }

    /// With a recycled Ticker and a top-up: exercises Ticker inputs, the locktime rule and the
    /// P2PKH sighash (SIGHASH_ALL | UTXOS | FORKID, Schnorr) against libauth's signer.
    #[test]
    fn update_with_recycle_and_topup_matches_sdk_vector() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let u = &v["update_recycle_topup"];
        let st = statements_from(&u["statements"]);
        let recycled: Vec<TickerUtxo> = u["recycled"].as_array().unwrap().iter().map(|t| TickerUtxo {
            outpoint: TxOutpoint { txid_be: hex32(t["txid"].as_str().unwrap()), vout: t["vout"].as_u64().unwrap() as u32 },
            value: t["value"].as_str().unwrap().parse().unwrap(),
            snapshot: Snapshot { seq: t["seq"].as_u64().unwrap() as u32, price: t["price"].as_str().unwrap().parse().unwrap(), k: t["k"].as_u64().unwrap() as u8 },
        }).collect();
        let topup = p2pkh_from(&u["topup"]);
        let b = build_update(&head, &table, &st, &recycled, &[topup]).unwrap();
        assert_eq!(b.size, u["size"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(&b.raw), u["tx"].as_str().unwrap());
        assert_eq!(b.tx.locktime, (29_870_000 - 120) * 60 + 3_600);
        assert!(b.tx.outputs[0].value > head.value, "recycled dust and the top-up join the reserve");
    }

    #[test]
    fn rotate_matches_sdk_vector() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let r = &v["rotate"];
        let new_table = hex::decode(r["new_table"].as_str().unwrap()).unwrap();
        let tail = table_hash(&new_table);
        let lock = oracle_lock();
        let keys: Vec<[u8; 32]> = v["keys"].as_array().unwrap().iter().map(|k| hex32(k.as_str().unwrap())).collect();
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
        // six approvals are not a majority of thirteen
        assert_eq!(build_rotate(&head, &table, &lock, &tail, &approvals[..6], &[]).unwrap_err(), BuildError::NotMajority { have: 6, rows: 13 });
        // an approval for another next lock is refused before anything is built
        let bad = Approval::sign(&keys[0], &derive_pubkey(&keys[0]).unwrap(), &cat_vm, &head.commit.table_hash, &[0x76], &tail).unwrap();
        assert!(matches!(build_rotate(&head, &table, &lock, &tail, &[bad], &[]).unwrap_err(), BuildError::Approval(_)));
    }

    #[test]
    fn selection_errors() {
        let v = vectors();
        let (head, table) = head_from(&v);
        let st = statements_from(&v["update_k13"]["statements"]);
        assert_eq!(build_update(&head, &table, &st[..6], &[], &[]).unwrap_err(), BuildError::Quorum(6));
        let mut stale = head.clone();
        stale.commit.snapshot.seq = 29_870_001;
        assert_eq!(build_update(&stale, &table, &st, &[], &[]).unwrap_err(), BuildError::StaleSeq { new: 29_870_001, old: 29_870_001 });
        let mut t = st.clone();
        t[3].price += 1; // breaks the signature: no row verifies it
        assert_eq!(build_update(&head, &table, &t, &[], &[]).unwrap_err(), BuildError::NoRow(16));
        let mut t = st.clone();
        t[7] = t[6].clone();
        assert_eq!(build_update(&head, &table, &t, &[], &[]).unwrap_err(), BuildError::DuplicateRow(6));
        let mut t = st.clone();
        t[2].seq += 1;
        assert!(matches!(build_update(&head, &table, &t, &[], &[]).unwrap_err(), BuildError::MixedSeq(..) | BuildError::NoRow(_)));
        let mut other = head.clone();
        other.commit.table_hash = [0u8; 20];
        assert_eq!(build_update(&other, &table, &st, &[], &[]).unwrap_err(), BuildError::TableHash);
    }

    #[test]
    fn lower_median_rule_and_forgery_threshold() {
        assert_eq!(lower_median(&[5, 1, 3]), 3);
        assert_eq!(lower_median(&[4, 1, 3, 2]), 2);
        assert_eq!(lower_median(&[9]), 9);
        assert_eq!(keys_to_forge(7), 4);
        assert_eq!(keys_to_forge(11), 6);
        assert_eq!(keys_to_forge(13), 7);
    }

    #[test]
    fn genesis_shape() {
        let v = vectors();
        let g = p2pkh_from(&v["genesis"]);
        let th = table_hash(&hex::decode(v["table"].as_str().unwrap()).unwrap());
        let b = build_genesis(&g, &th, 50_000_000, 29_870_000).unwrap();
        let tp = b.tx.outputs[0].token.as_ref().unwrap();
        assert_eq!(tp.capability, MINTING_CAPABILITY);
        let mut expect_cat = g.outpoint.txid_be;
        expect_cat.reverse();
        assert_eq!(tp.category_le, expect_cat);
        let c = HeadCommit::decode(&tp.commitment).unwrap();
        assert_eq!(c, HeadCommit { snapshot: Snapshot { seq: 29_870_000, price: 0, k: 0 }, table_hash: th });
        assert_eq!(b.tx.outputs[1].value, 100_000_000 - 50_000_000 - b.fee);
        assert_eq!(b.tx.outputs[0].locking_script, oracle_lock().to_vec());
        let bad = P2pkhInput { outpoint: TxOutpoint { txid_be: g.outpoint.txid_be, vout: 1 }, ..g };
        assert_eq!(build_genesis(&bad, &th, 5_000_000, 1).unwrap_err(), BuildError::GenesisVout);
    }
}
