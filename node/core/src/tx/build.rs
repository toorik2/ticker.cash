//! The three transactions v25 ever builds: genesis, update, sweep. Updates may carry extra
//! P2PKH inputs to top up the reserve.
//!
//! Fee policy: exactly `size + 1` sat. Every transaction here is fixed-width before signing
//! (Schnorr signatures are 64 B, the Oracle input carries no transaction signature), so the
//! size is computed once from a fully laid-out draft and never estimated.

use crate::commit::Commit;
use crate::crypto::schnorr_sign;
use crate::statement::Statement;
use crate::tx::covenant::{oracle_redeem_for_table, ticker_lock, TABLE_LEN};
use crate::tx::encode::{encode_tx, Input, Output, TokenPrefix, Tx, TxOutpoint, MINTING_CAPABILITY, NO_CAPABILITY, SEQUENCE_FINAL};
use crate::tx::script::{p2pkh_locking_script, push_data, push_int};
use crate::tx::sighash::{sighash_digest, SpentOutput, SIGHASH_ALL_UTXOS_FORKID};
use crate::{QUORUM, RESERVE_CAP_SATS, ROWS, TICKERS_PER_UPDATE, TICKER_SATS, TICKER_SWEEP_UNITS};

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
    #[error("statement row {0} is out of range or duplicated")]
    Row(u8),
    #[error("statement row {0} carries a malformed signature")]
    Sig(u8),
    #[error("statement row {row} names source {got}, table row names {want}")]
    Source { row: u8, got: u8, want: u8 },
    #[error("statement row {0} does not verify against the table pubkey")]
    Verify(u8),
    #[error("update would spend {spend} sats from the head; covenant cap is {RESERVE_CAP_SATS}")]
    ReserveCap { spend: u64 },
    #[error("head value {0} cannot cover fee and tickers")]
    Insufficient(u64),
    #[error("no tickers to sweep")]
    NoTickers,
    #[error("sweep output {0} sats is below dust")]
    SweepDust(u64),
    #[error("signing failed: {0}")]
    Key(#[from] crate::crypto::KeyError),
    #[error("genesis funding input must be vout 0 (CashTokens category genesis)")]
    GenesisVout,
}

#[derive(Debug, Clone)]
pub struct HeadUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub commit: Commit,
    /// Category in display order.
    pub category: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TickerUtxo {
    pub outpoint: TxOutpoint,
    pub value: u64,
    pub commit: Commit,
}

/// A P2PKH coin plus the key that spends it (reserve top-ups, genesis funding, sweeps).
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

fn finish(tx: Tx) -> BuiltTx {
    let raw = encode_tx(&tx);
    let txid = crate::tx::encode::txid_be(&raw);
    let size = raw.len();
    BuiltTx { tx, raw, txid, size, fee: 0 }
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

/// Validate statements against the table and the head, then sort them by row.
pub fn select_statements(head: &HeadUtxo, table: &[u8], statements: &[Statement]) -> Result<Vec<Statement>, BuildError> {
    assert_eq!(table.len(), TABLE_LEN);
    if statements.len() < QUORUM {
        return Err(BuildError::Quorum(statements.len()));
    }
    let seq = statements[0].seq;
    if seq <= head.commit.seq {
        return Err(BuildError::StaleSeq { new: seq, old: head.commit.seq });
    }
    let cat_vm = category_le(&head.category);
    let mut sorted = statements.to_vec();
    sorted.sort_by_key(|s| s.row);
    for (i, s) in sorted.iter().enumerate() {
        if s.seq != seq {
            return Err(BuildError::MixedSeq(seq, s.seq));
        }
        if s.row as usize >= ROWS || (i > 0 && sorted[i - 1].row == s.row) {
            return Err(BuildError::Row(s.row));
        }
        let entry = &table[s.row as usize * 34..s.row as usize * 34 + 34];
        let pubkey: [u8; 33] = entry[..33].try_into().unwrap();
        let source = entry[33];
        if s.source != source {
            return Err(BuildError::Source { row: s.row, got: s.source, want: source });
        }
        if s.sig_bytes().is_none() {
            return Err(BuildError::Sig(s.row));
        }
        if !s.verify(&cat_vm, &pubkey) {
            return Err(BuildError::Verify(s.row));
        }
    }
    sorted.truncate(ROWS);
    Ok(sorted)
}

/// Build the update transaction. `statements` must already be validated and row-sorted
/// (`select_statements`). `topups` are optional P2PKH inputs whose value joins the reserve.
pub fn build_update(head: &HeadUtxo, table: &[u8], oracle_lock: &[u8; 35], statements: &[Statement], topups: &[P2pkhInput]) -> Result<BuiltTx, BuildError> {
    let sorted = select_statements(head, table, statements)?;
    let seq = sorted[0].seq;
    let prices: Vec<u64> = sorted.iter().map(|s| s.price).collect();
    let median = lower_median(&prices);

    // unlocking: push(median) push(sigs) push(prices) push(rows) push(seq) push(redeem)
    let mut sigs = Vec::with_capacity(64 * sorted.len());
    let mut price_bytes = Vec::with_capacity(8 * sorted.len());
    let mut rows = Vec::with_capacity(sorted.len());
    for s in &sorted {
        sigs.extend_from_slice(&s.sig_bytes().expect("validated"));
        price_bytes.extend_from_slice(&s.price.to_le_bytes());
        rows.push(s.row);
    }
    let mut unlock = Vec::with_capacity(1500);
    push_data(&mut unlock, &median.to_le_bytes());
    push_data(&mut unlock, &sigs);
    push_data(&mut unlock, &price_bytes);
    push_data(&mut unlock, &rows);
    push_data(&mut unlock, &seq.to_le_bytes());
    push_data(&mut unlock, &oracle_redeem_for_table(table));

    let commit = Commit { seq, price: median }.encode().to_vec();
    let cat_le = category_le(&head.category);
    let mut inputs = vec![Input { prev: head.outpoint, unlock_script: unlock, sequence: SEQUENCE_FINAL }];
    let mut sources = vec![SpentOutput {
        value: head.value,
        locking_script: oracle_lock.to_vec(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: head.commit.encode().to_vec(), amount: 0 }),
    }];
    let mut topup_total = 0u64;
    for t in topups {
        // placeholder unlocking of the final width: push(65-byte sig) push(33-byte pubkey)
        let mut placeholder = Vec::with_capacity(100);
        push_data(&mut placeholder, &[0u8; 65]);
        push_data(&mut placeholder, &t.public_key);
        inputs.push(Input { prev: t.outpoint, unlock_script: placeholder, sequence: SEQUENCE_FINAL });
        sources.push(SpentOutput { value: t.value, locking_script: p2pkh_locking_script(&t.pkh).to_vec(), token: None });
        topup_total += t.value;
    }
    let ticker_cost = TICKER_SATS * TICKERS_PER_UPDATE as u64;
    let mut outputs = vec![Output {
        value: 0, // set after sizing
        locking_script: oracle_lock.to_vec(),
        token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: commit.clone(), amount: 0 }),
    }];
    for _ in 0..TICKERS_PER_UPDATE {
        outputs.push(Output {
            value: TICKER_SATS,
            locking_script: ticker_lock(),
            token: Some(TokenPrefix { category_le: cat_le, capability: NO_CAPABILITY, commitment: commit.clone(), amount: 0 }),
        });
    }
    let mut tx = Tx::new(inputs, outputs);
    let size = encode_tx(&tx).len() as u64;
    let fee = size + 1;
    let spend_from_head = fee + ticker_cost;
    if topups.is_empty() && spend_from_head > RESERVE_CAP_SATS {
        return Err(BuildError::ReserveCap { spend: spend_from_head });
    }
    let available = head.value + topup_total;
    if available < spend_from_head {
        return Err(BuildError::Insufficient(head.value));
    }
    tx.outputs[0].value = available - spend_from_head;
    if head.value.saturating_sub(tx.outputs[0].value) > RESERVE_CAP_SATS {
        return Err(BuildError::ReserveCap { spend: head.value - tx.outputs[0].value });
    }
    // sign top-ups (outputs are final now)
    for (i, t) in topups.iter().enumerate() {
        let idx = 1 + i;
        let script_code = p2pkh_locking_script(&t.pkh);
        let digest = sighash_digest(&tx, idx, &script_code, &sources, SIGHASH_ALL_UTXOS_FORKID);
        let sig = schnorr_sign(&t.private_key, &digest)?;
        let mut sig_ht = sig.to_vec();
        sig_ht.push(SIGHASH_ALL_UTXOS_FORKID);
        let mut unlock = Vec::with_capacity(100);
        push_data(&mut unlock, &sig_ht);
        push_data(&mut unlock, &t.public_key);
        tx.inputs[idx].unlock_script = unlock;
    }
    let mut built = finish(tx);
    debug_assert_eq!(built.size as u64, size, "signed size must equal the sized draft");
    built.fee = fee;
    Ok(built)
}

/// Sweep aged Tickers into one P2PKH output. Each input carries `nSequence = 144` (legacy
/// relative-lock units) and the function selector `OP_1` as its whole unlocking script.
pub fn build_sweep(tickers: &[TickerUtxo], dest_pkh: &[u8; 20]) -> Result<BuiltTx, BuildError> {
    if tickers.is_empty() {
        return Err(BuildError::NoTickers);
    }
    let mut unlock = Vec::with_capacity(1);
    push_int(&mut unlock, 1);
    let inputs: Vec<Input> = tickers.iter().map(|t| Input { prev: t.outpoint, unlock_script: unlock.clone(), sequence: TICKER_SWEEP_UNITS }).collect();
    let total: u64 = tickers.iter().map(|t| t.value).sum();
    let mut tx = Tx::new(inputs, vec![Output { value: 0, locking_script: p2pkh_locking_script(dest_pkh).to_vec(), token: None }]);
    let size = encode_tx(&tx).len() as u64;
    let fee = size + 1;
    if total <= fee + P2PKH_DUST {
        return Err(BuildError::SweepDust(total.saturating_sub(fee)));
    }
    tx.outputs[0].value = total - fee;
    let mut built = finish(tx);
    built.fee = fee;
    Ok(built)
}

/// Genesis: spend `funding` (which must be output 0 of its transaction, so its txid becomes the
/// category) into the head with `reserve` sats, and return change to the funder.
pub fn build_genesis(funding: &P2pkhInput, table: &[u8], oracle_lock: &[u8; 35], reserve: u64, initial_seq: u32) -> Result<BuiltTx, BuildError> {
    assert_eq!(table.len(), TABLE_LEN);
    if funding.outpoint.vout != 0 {
        return Err(BuildError::GenesisVout);
    }
    let category = funding.outpoint.txid_be;
    let cat_le = category_le(&category);
    let commit = Commit { seq: initial_seq, price: 0 }.encode().to_vec();
    let mut placeholder = Vec::with_capacity(100);
    push_data(&mut placeholder, &[0u8; 65]);
    push_data(&mut placeholder, &funding.public_key);
    let inputs = vec![Input { prev: funding.outpoint, unlock_script: placeholder, sequence: SEQUENCE_FINAL }];
    let outputs = vec![
        Output { value: reserve, locking_script: oracle_lock.to_vec(), token: Some(TokenPrefix { category_le: cat_le, capability: MINTING_CAPABILITY, commitment: commit, amount: 0 }) },
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
    let script_code = p2pkh_locking_script(&funding.pkh);
    let digest = sighash_digest(&tx, 0, &script_code, &sources, SIGHASH_ALL_UTXOS_FORKID);
    let sig = schnorr_sign(&funding.private_key, &digest)?;
    let mut sig_ht = sig.to_vec();
    sig_ht.push(SIGHASH_ALL_UTXOS_FORKID);
    let mut unlock = Vec::with_capacity(100);
    push_data(&mut unlock, &sig_ht);
    push_data(&mut unlock, &funding.public_key);
    tx.inputs[0].unlock_script = unlock;
    let mut built = finish(tx);
    built.fee = fee;
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_pubkey;
    use crate::tx::covenant::oracle_lock_for_table;

    fn fixture(k: usize) -> (HeadUtxo, Vec<u8>, [u8; 35], Vec<Statement>) {
        let mut table = Vec::with_capacity(TABLE_LEN);
        let mut keys = Vec::new();
        for i in 0..ROWS as u8 {
            let mut sk = [0u8; 32];
            sk[31] = i + 1;
            sk[0] = 9;
            keys.push(sk);
            table.extend_from_slice(&derive_pubkey(&sk).unwrap());
            table.push(i + 1);
        }
        let lock = oracle_lock_for_table(&table);
        let category = [0x22u8; 32];
        let head = HeadUtxo { outpoint: TxOutpoint { txid_be: [0x11; 32], vout: 0 }, value: 50_000_000, commit: Commit { seq: 29_870_000, price: 29_000_000_000 }, category };
        let mut cat_vm = category;
        cat_vm.reverse();
        let statements: Vec<Statement> = (0..k as u8)
            .map(|r| Statement::sign(&keys[r as usize], &cat_vm, r, r + 1, 29_870_001, 29_000_000_000 + r as u64 * 1_000_000 - 6_000_000).unwrap())
            .collect();
        (head, table, lock, statements)
    }

    /// Sizes must equal the cashscript-built transactions from the VM suite (1,701 / 1,774 / 2,140).
    #[test]
    fn update_sizes_match_vm_suite() {
        for (k, expected) in [(7usize, 1701usize), (8, 1774), (13, 2140)] {
            let (head, table, lock, st) = fixture(k);
            let b = build_update(&head, &table, &lock, &st, &[]).unwrap();
            assert_eq!(b.size, expected, "k = {k}");
            assert_eq!(b.fee, expected as u64 + 1);
            assert_eq!(b.tx.outputs.len(), 3);
            assert_eq!(b.tx.outputs[1].value, TICKER_SATS);
            assert_eq!(head.value - b.tx.outputs[0].value, b.fee + 2 * TICKER_SATS);
            let c = Commit::decode(&b.tx.outputs[0].token.as_ref().unwrap().commitment).unwrap();
            assert_eq!(c.seq, 29_870_001);
            let prices: Vec<u64> = st.iter().map(|s| s.price).collect();
            assert_eq!(c.price, lower_median(&prices));
        }
    }

    #[test]
    fn lower_median_rule() {
        assert_eq!(lower_median(&[5, 1, 3]), 3);
        assert_eq!(lower_median(&[4, 1, 3, 2]), 2);
        assert_eq!(lower_median(&[9]), 9);
    }

    #[test]
    fn validation_errors() {
        let (head, table, lock, mut st) = fixture(7);
        assert_eq!(build_update(&head, &table, &lock, &st[..6], &[]).unwrap_err(), BuildError::Quorum(6));
        let mut stale = head.clone();
        stale.commit.seq = 29_870_001;
        assert_eq!(build_update(&stale, &table, &lock, &st, &[]).unwrap_err(), BuildError::StaleSeq { new: 29_870_001, old: 29_870_001 });
        st[3].price += 1; // breaks the signature
        assert_eq!(build_update(&head, &table, &lock, &st, &[]).unwrap_err(), BuildError::Verify(3));
        let (head, table, lock, mut st) = fixture(7);
        st[2].source = 9;
        assert_eq!(build_update(&head, &table, &lock, &st, &[]).unwrap_err(), BuildError::Source { row: 2, got: 9, want: 3 });
        let (head, table, lock, mut st) = fixture(8);
        st[7] = st[6].clone();
        assert_eq!(build_update(&head, &table, &lock, &st, &[]).unwrap_err(), BuildError::Row(6));
    }

    #[test]
    fn topup_adds_signed_input_and_grows_reserve() {
        let (head, table, lock, st) = fixture(7);
        let sk = [0x55u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let t = P2pkhInput { outpoint: TxOutpoint { txid_be: [0x33; 32], vout: 1 }, value: 1_000_000, private_key: sk, public_key: pk, pkh: crate::crypto::hash160(&pk) };
        let b = build_update(&head, &table, &lock, &st, &[t]).unwrap();
        assert_eq!(b.tx.inputs.len(), 2);
        assert_eq!(b.tx.inputs[1].unlock_script.len(), 1 + 65 + 1 + 33);
        assert!(b.tx.outputs[0].value > head.value);
        assert_eq!(b.fee, b.size as u64 + 1);
    }

    #[test]
    fn sweep_and_genesis_shapes() {
        let tk: Vec<TickerUtxo> = (0..3).map(|i| TickerUtxo { outpoint: TxOutpoint { txid_be: [i; 32], vout: 1 }, value: TICKER_SATS, commit: Commit { seq: 1, price: 1 } }).collect();
        let s = build_sweep(&tk, &[0x44; 20]).unwrap();
        assert!(s.tx.inputs.iter().all(|i| i.sequence == 144 && i.unlock_script == vec![0x51]));
        assert_eq!(s.tx.outputs[0].value, 3 * TICKER_SATS - s.fee);
        assert_eq!(s.size, 10 + 3 * (36 + 1 + 1 + 4) + 34);
        let one = build_sweep(&tk[..1], &[0x44; 20]).unwrap();
        assert_eq!(one.size, 86);

        let sk = [0x66u8; 32];
        let pk = derive_pubkey(&sk).unwrap();
        let funding = P2pkhInput { outpoint: TxOutpoint { txid_be: [0x77; 32], vout: 0 }, value: 10_000_000, private_key: sk, public_key: pk, pkh: crate::crypto::hash160(&pk) };
        let (_, table, lock, _) = fixture(7);
        let g = build_genesis(&funding, &table, &lock, 5_000_000, 29_870_000).unwrap();
        let tp = g.tx.outputs[0].token.as_ref().unwrap();
        assert_eq!(tp.capability, MINTING_CAPABILITY);
        let mut expect_cat = [0x77u8; 32];
        expect_cat.reverse();
        assert_eq!(tp.category_le, expect_cat);
        assert_eq!(g.tx.outputs[1].value, 10_000_000 - 5_000_000 - g.fee);
        let bad = P2pkhInput { outpoint: TxOutpoint { txid_be: [0x77; 32], vout: 1 }, ..funding };
        assert_eq!(build_genesis(&bad, &table, &lock, 5_000_000, 1).unwrap_err(), BuildError::GenesisVout);
    }
}
