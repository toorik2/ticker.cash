// v27 VM suite: cashscript 0.14 MockNetworkProvider on BCH_2026_05 plus libauth token validation.
// Snapshot = General Protocols price message (timestamp, messageSequence, dataSequence, price in
// cents) ‖ k. Covers updates, the contiguous counter, rotation, the live migration path from a v26
// head (rotate under v26 rules into the v27 lock, then the first v27 update), recycling of v26
// Tickers by a v27 head, consume with toll, and the reference consumer. `--vectors` writes
// test/v27-vectors.json, which node/core replays byte for byte.
import fs from 'node:fs';
import { Contract, MockNetworkProvider, TransactionBuilder, VmTarget, SignatureTemplate } from 'cashscript';
import { secp256k1, sha256, ripemd160, hexToBin, binToHex, cashAddressToLockingBytecode,
         decodeTransaction, verifyTransactionTokens, encodeLockingBytecodeP2pkh } from '@bitauth/libauth';

const hash160 = (b) => ripemd160.hash(sha256.hash(b));
const cat = (...xs) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const uLE = (n, w) => { const b = new Uint8Array(w); let v = BigInt(n); for (let i = 0; i < w; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const u32 = (n) => uLE(n, 4), u64 = (n) => uLE(n, 8);
const utf8 = (s) => new TextEncoder().encode(s);
const art = (p) => JSON.parse(fs.readFileSync(new URL(p, import.meta.url), 'utf8'));

const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
const ticker = new Contract(art('../artifacts/Ticker.json'), [], { provider, contractType: 'p2s' });
const tickerLock = hexToBin(ticker.bytecode);
const oracle = new Contract(art('../artifacts/Oracle.json'), [tickerLock], { provider, contractType: 'p2sh32' });
const oracleLock = cashAddressToLockingBytecode(oracle.address).bytecode;
// the previous generation, for the migration and legacy-recycle scenarios
const renamed = (a, name) => ({ ...a, contractName: name }); // the debugger wants distinct names across generations
const ticker26 = new Contract(renamed(art('../artifacts/v26/Ticker.json'), 'TickerV26'), [], { provider, contractType: 'p2s' });
const ticker26Lock = hexToBin(ticker26.bytecode);
const oracle26 = new Contract(renamed(art('../artifacts/v26/Oracle.json'), 'OracleV26'), [ticker26Lock], { provider, contractType: 'p2sh32' });
const oracle26Lock = cashAddressToLockingBytecode(oracle26.address).bytecode;

// ─── protocol constants (must equal the covenant literals and node/core/src/lib.rs) ───
const QUORUM = 7, TICKERS = 2, TICKER_SATS = 792n, TOLL = 1000n, LIFE = 86400, LIFE26 = 3600, AHEAD = 21600;

// ─── deterministic fixtures ───
const N = 13;
const keys = Array.from({ length: N }, (_, i) => sha256.hash(utf8(`ticker.cash v27 test row ${i}`)));
const pubs = keys.map((k) => secp256k1.derivePublicKeyCompressed(k));
const SOURCES = [1, 2, 3, 16, 5, 6, 7, 14, 15, 10, 11, 12, 13];
const mkTable = (ps, ss) => cat(...ps.map((p, i) => cat(p, new Uint8Array([ss[i]]))));
const table = mkTable(pubs, SOURCES);
const tableHash = hash160(table);
const categoryHex = binToHex(sha256.hash(utf8('ticker.cash v27 test category')));
const catVm = hexToBin(categoryHex).slice().reverse();
const TS0 = 1792200000, SEQ0 = 1000, PRICE0 = 29000; // $290.00
const RESERVE = 50_000_000n;
const snap = (ts, seq, price, k) => cat(u32(ts), u32(seq), u32(seq), u32(price), new Uint8Array([k]));
const headCommit = (ts, seq, price, k, th = tableHash) => cat(snap(ts, seq, price, k), th);
const sign = (key, source, ts, price) => {
  const msg = cat(new Uint8Array([0x4e]), new Uint8Array([source]), u32(ts), u32(price));
  const sig = secp256k1.signMessageHashSchnorr(key, sha256.hash(msg)); if (typeof sig === 'string') throw new Error(sig); return sig;
};
const approve = (key, oldHash, nextLock, tail, category = catVm) => {
  const msg = cat(new Uint8Array([0x52]), category, oldHash, nextLock, tail);
  const sig = secp256k1.signMessageHashSchnorr(key, sha256.hash(msg)); if (typeof sig === 'string') throw new Error(sig); return sig;
};
const fixedTxid = (label) => binToHex(sha256.hash(utf8('txid ' + label)));
const headUtxo = (commit = headCommit(TS0, SEQ0, PRICE0, 13), label = 'head', sats = RESERVE, lock = oracleLock) => ({ txid: fixedTxid(label), vout: 0, satoshis: sats, lockingBytecode: binToHex(lock),
  token: { category: categoryHex, amount: 0n, nft: { capability: 'minting', commitment: binToHex(commit) } } });
const tickerUtxo = (ts, seq, price, k, label, sats = TICKER_SATS) => ({ txid: fixedTxid(label), vout: 1, satoshis: sats, lockingBytecode: binToHex(tickerLock),
  token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(snap(ts, seq, price, k)) } } });
const ticker26Utxo = (seq26, price8, k, label, sats = 786n) => ({ txid: fixedTxid(label), vout: 1, satoshis: sats, lockingBytecode: binToHex(ticker26Lock),
  token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(cat(u32(seq26), u64(price8), new Uint8Array([k]))) } } });
const mintOut = (commit, amount, to = oracleLock) => ({ to, amount, token: { category: categoryHex, amount: 0n, nft: { capability: 'minting', commitment: binToHex(commit) } } });
const tickerOut = (sc, amount = TICKER_SATS) => ({ to: tickerLock, amount, token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(sc) } } });
const SEQ_NF = 0xfffffffe;

function tokensOk(builder, utxos) {
  const tx = decodeTransaction(hexToBin(builder.build()));
  const src = utxos.map((u) => ({ lockingBytecode: hexToBin(u.lockingBytecode), valueSatoshis: u.satoshis,
    token: u.token ? { category: hexToBin(u.token.category), amount: u.token.amount, nft: u.token.nft ? { capability: u.token.nft.capability, commitment: hexToBin(u.token.nft.commitment) } : undefined } : undefined }));
  return verifyTransactionTokens(tx, src);
}
const results = { ok: 0, bad: 0 };
const expectOk = (name, { b, utxos, size }) => {
  try {
    b.build(); const dbg = b.debug(); const tr = dbg[Object.keys(dbg)[0]]; const m = tr?.[tr.length - 1]?.metrics;
    const t = tokensOk(b, utxos);
    if (t !== true) throw new Error('tokens: ' + t);
    console.log(`OK   ${name}${size ? ` (${size} B)` : ''}${m ? `  opcost ${m.operationCost}/${m.maximumOperationCost}` : ''}`);
    results.ok++;
  } catch (e) { console.log(`FAIL ${name}: ${e.message.split('\n')[0].slice(0, 160)}`); results.bad++; }
};
const expectFail = (name, mk) => {
  try { const { b } = mk(); b.build(); b.debug(); console.log(`BUG  ${name}: accepted`); results.bad++; }
  catch (e) { console.log(`ok   ${name}: rejected -> ${e.message.split('\n')[0].slice(0, 110)}`); results.ok++; }
};
const check = (name, cond, detail = '') => { console.log(`${cond ? 'OK  ' : 'FAIL'} ${name}${detail ? ' ' + detail : ''}`); cond ? results.ok++ : results.bad++; };
function exact(mk) { let b = mk(3000n); const size = BigInt(b.build().length / 2); b = mk(size + 1n); return { b, size: Number(size) }; }

// ─── update scenario builder; `tweak` lets negative tests mutate pieces ───
function update({ k = 13, ts = TS0 + 60, tweak = {}, recycle = [], topup = null, tableBytes = table, rowKeys = keys, rowSources = SOURCES, head = null, oldSeq = SEQ0 } = {}) {
  const rows = tweak.rows ?? Array.from({ length: k }, (_, i) => i);
  const prices = tweak.prices ?? rows.map((r) => PRICE0 + r * 10 - 60);
  const sorted = [...prices].sort((a, b) => a - b);
  const median = tweak.median ?? sorted[Math.floor((rows.length - 1) / 2)];
  const sigs = tweak.sigs ?? cat(...rows.map((r, i) => sign(rowKeys[r], rowSources[r], ts, prices[i])));
  const seq = tweak.seq ?? oldSeq + 1;
  const kByte = tweak.kByte ?? rows.length;
  const sc = tweak.snapshot ?? cat(u32(ts), u32(tweak.msgSeq ?? seq), u32(seq), u32(tweak.commitPrice ?? median), new Uint8Array([kByte]));
  const th = tweak.newTableHash ?? hash160(tableBytes);
  const hUtxo = head ?? headUtxo();
  const utxos = [hUtxo, ...recycle.map((r) => r.utxo), ...(topup ? [topup.utxo] : [])];
  const inTotal = utxos.reduce((a, u) => a + u.satoshis, 0n);
  const locktime = tweak.locktime ?? Math.max(ts - AHEAD, ...recycle.map((r) => r.recycleAt));
  const mk = (fee) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(hUtxo, oracle.unlock.update(tweak.tableArg ?? tableBytes, u32(ts), new Uint8Array(rows), cat(...prices.map(u32)), sigs, u32(median)), { sequence: tweak.sequence ?? SEQ_NF });
    for (const r of recycle) b.addInput(r.utxo, r.unlock ?? ticker.unlock.recycle(), { sequence: SEQ_NF });
    if (topup) b.addInput(topup.utxo, topup.template.unlockP2PKH(), { sequence: SEQ_NF });
    b.addOutput(mintOut(cat(sc, th), inTotal - BigInt(TICKERS) * (tweak.tickerSats ?? TICKER_SATS) - fee - (tweak.extraDrain ?? 0n) - (tweak.extraOutput ? 1000n : 0n)));
    for (let j = 0; j < TICKERS; j++) b.addOutput(tickerOut(tweak.tickerCommit ?? sc, tweak.tickerSats));
    if (tweak.extraOutput) b.addOutput({ to: oracleLock, amount: 1000n });
    b.setLocktime(locktime);
    return b;
  };
  const { b, size } = exact(mk);
  return { b, utxos, size, median, sc, th, kByte };
}

// ─── rotate scenario builder (works for a v27 head, or a v26 head when `legacy` is set) ───
function rotate({ nextLock = oracleLock, nextTail = null, newTable = null, signers = [0, 1, 2, 3, 4, 5, 6], tweak = {}, head = null, tableBytes = table, rowKeys = keys, legacy = false } = {}) {
  const hUtxo = head ?? headUtxo();
  const oldHash = hash160(tableBytes);
  const tail = nextTail ?? hash160(newTable);
  const state = tweak.state ?? (legacy ? hexToBin(hUtxo.token.nft.commitment).slice(0, 13) : snap(TS0, SEQ0, PRICE0, 13));
  const nextCommit = cat(state, tail);
  const sigs = tweak.sigs ?? cat(...signers.map((r) => approve(rowKeys[r], tweak.signedOldHash ?? oldHash, tweak.signedLock ?? nextLock, tail)));
  const contract = legacy ? oracle26 : oracle;
  const mk = (fee) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(hUtxo, contract.unlock.rotate(tableBytes, new Uint8Array(signers), sigs), { sequence: SEQ_NF });
    b.addOutput(mintOut(nextCommit, hUtxo.satoshis - fee - (tweak.extraOutput ? 1000n : 0n), nextLock));
    if (tweak.extraOutput) b.addOutput({ to: oracleLock, amount: 1000n });
    return b;
  };
  const { b, size } = exact(mk);
  return { b, utxos: [hUtxo], size, nextCommit };
}

console.log(`oracle body ${hexToBin(oracle.bytecode).length - tickerLock.length - 1} B, redeem ${hexToBin(oracle.bytecode).length} B, ticker lock ${tickerLock.length} B (p2s), table ${table.length} B, head commit 37 B, ticker commit 17 B`);
console.log(`oracle lock (same for every v27 deployment) ${binToHex(oracleLock)}`);

// ─── updates ───
const sizes = {};
for (const k of [7, 8, 13]) { const u = update({ k }); sizes[k] = u.size; expectOk(`update k=${k}`, u); }
{
  const tx = decodeTransaction(hexToBin(update({ k: 13 }).b.build()));
  const out = tx.outputs[1];
  const bytes = 8 + 1 + (1 + 32 + 1 + 1 + out.token.nft.commitment.length) + out.lockingBytecode.length;
  check('ticker output dust floor', 3n * BigInt(bytes + 148) === TICKER_SATS, `${bytes} B → ${3 * (bytes + 148)} sats, pinned ${TICKER_SATS}`);
  const c = tx.outputs[0].token.nft.commitment;
  const dv = new DataView(c.buffer, c.byteOffset, c.byteLength);
  check('commitment is a GP message: ts, msgSeq == dataSeq == old + 1, price cents, k, table hash', dv.getUint32(0, true) === TS0 + 60 && dv.getUint32(4, true) === SEQ0 + 1 && dv.getUint32(8, true) === SEQ0 + 1 && dv.getUint32(12, true) === PRICE0 && c[16] === 13 && binToHex(c.slice(17)) === binToHex(tableHash));
}
// recycling: a v27 Ticker a day old, a v26 Ticker an hour old (legacy lock and 13-byte commit), and a top-up
const funder = sha256.hash(utf8('ticker.cash v27 test funder'));
const fTemplate = new SignatureTemplate(funder);
const fLock = encodeLockingBytecodeP2pkh(hash160(fTemplate.publicKey));
const topupUtxo = { txid: fixedTxid('topup'), vout: 0, satoshis: 1_000_000n, lockingBytecode: binToHex(fLock) };
const oldV27 = { recycleAt: TS0 - 3 * 86400 + LIFE, utxo: tickerUtxo(TS0 - 3 * 86400, SEQ0 - 100, PRICE0, 13, 'old v27 ticker', TICKER_SATS + 2n * TOLL) };
const SEQ26 = 29882228, PRICE26 = 27_257_000_000n;
const oldV26 = { recycleAt: (SEQ26 - 180) * 60 + LIFE26, utxo: ticker26Utxo(SEQ26 - 180, PRICE26, 13, 'old v26 ticker'), unlock: ticker26.unlock.recycle() };
{
  const u = update({ k: 13, recycle: [oldV27, oldV26], topup: { utxo: topupUtxo, template: fTemplate } });
  sizes.recycle = u.size;
  expectOk('update k=13 recycling a v27 ticker (with tolls) and a v26 ticker, plus a top-up', u);
  const tx = decodeTransaction(hexToBin(u.b.build()));
  const expected = RESERVE + TICKER_SATS + 2n * TOLL + 786n + 1_000_000n - 2n * TICKER_SATS - BigInt(u.size + 1);
  check('reserve after = inputs - 2 tickers - fee', tx.outputs[0].valueSatoshis === expected, String(tx.outputs[0].valueSatoshis));
}
expectFail('recycle a v27 ticker younger than a day', () => update({ recycle: [{ recycleAt: TS0 - 86400 + LIFE - 1, utxo: tickerUtxo(TS0 - 86400, SEQ0 - 50, PRICE0, 13, 'young v27') }] }));
expectFail('recycle a v26 ticker younger than an hour', () => update({ recycle: [{ recycleAt: (SEQ26 - 59) * 60 + LIFE26 - 1, utxo: ticker26Utxo(SEQ26 - 59, PRICE26, 13, 'young v26'), unlock: ticker26.unlock.recycle() }] }));

// the red-team subset forgery still posts, labeled k = 7
{
  const rows = [0, 1, 2, 3, 4, 5, 6];
  const prices = [15003, 15003, 15003, 15003, PRICE0, PRICE0 + 1, PRICE0 + 2];
  const u = update({ tweak: { rows, prices } });
  expectOk('red team 1: 4-key subset at k=7 posts $150 against a $290 market, labeled k=7', u);
  check('commitment k byte = 7', decodeTransaction(hexToBin(u.b.build())).outputs[0].token.nft.commitment[16] === 7);
}

// ─── update: negatives ───
expectFail('k=6 (below the floor)', () => update({ k: 6 }));
expectFail('duplicate row', () => update({ tweak: { rows: [0, 1, 2, 3, 4, 5, 5] } }));
expectFail('row index == table size', () => update({ tweak: { rows: [0, 1, 2, 3, 4, 5, 13], sigs: cat(...[0, 1, 2, 3, 4, 5, 0].map((r, i) => sign(keys[r], SOURCES[r], TS0 + 60, PRICE0 + [0, 1, 2, 3, 4, 5, 13][i] * 10 - 60))) } }));
expectFail('timestamp not increasing (== old)', () => update({ ts: TS0 }));
expectFail('dataSequence not old + 1', () => update({ tweak: { seq: SEQ0 + 2 } }));
expectFail('messageSequence != dataSequence', () => update({ tweak: { msgSeq: SEQ0 + 2 } }));
expectFail('statement signed for another exchange (source byte)', () => update({ k: 7, tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(keys[r], SOURCES[(r + 1) % N], TS0 + 60, PRICE0 + r * 10 - 60))) } }));
// statements name no deployment: a second instance over the same public notaries consumes the very same signatures
{
  const otherCategory = binToHex(sha256.hash(utf8('ticker.cash v27 test category B')));
  const sameSigs = cat(...Array.from({ length: 13 }, (_, r) => sign(keys[r], SOURCES[r], TS0 + 60, PRICE0 + r * 10 - 60)));
  const headB = { ...headUtxo(headCommit(TS0, SEQ0, PRICE0, 13), 'head B'), token: { category: otherCategory, amount: 0n, nft: { capability: 'minting', commitment: binToHex(headCommit(TS0, SEQ0, PRICE0, 13)) } } };
  const sc = snap(TS0 + 60, SEQ0 + 1, PRICE0, 13);
  const mk = (fee) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(headB, oracle.unlock.update(table, u32(TS0 + 60), new Uint8Array(Array.from({ length: 13 }, (_, i) => i)), cat(...Array.from({ length: 13 }, (_, r) => u32(PRICE0 + r * 10 - 60))), sameSigs, u32(PRICE0)), { sequence: SEQ_NF });
    b.addOutput({ to: oracleLock, amount: RESERVE - 2n * TICKER_SATS - fee, token: { category: otherCategory, amount: 0n, nft: { capability: 'minting', commitment: binToHex(cat(sc, tableHash)) } } });
    for (let j = 0; j < 2; j++) b.addOutput({ to: tickerLock, amount: TICKER_SATS, token: { category: otherCategory, amount: 0n, nft: { capability: 'none', commitment: binToHex(sc) } } });
    b.setLocktime(TS0 + 60 - AHEAD);
    return b;
  };
  const { b, size } = exact(mk);
  expectOk('a second oracle instance (other category, same table) accepts the same 13 statements', { b, utxos: [headB], size });
}
expectFail('forged signature (wrong key)', () => update({ k: 7, tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(keys[(r + 1) % N], SOURCES[r], TS0 + 60, PRICE0 + r * 10 - 60))) } }));
expectFail('wrong median claimed (6th of 13)', () => update({ tweak: { median: PRICE0 - 10 } }));
expectFail('median value not among the prices', () => update({ tweak: { median: PRICE0 + 1 } }));
expectFail('commit price != median', () => update({ tweak: { commitPrice: PRICE0 + 1 } }));
expectFail('commit k byte wrong (claims 13 with 7 rows)', () => update({ k: 7, tweak: { kByte: 13 } }));
expectFail('ticker commit mismatch', () => update({ tweak: { tickerCommit: snap(TS0 + 60, SEQ0 + 1, 1, 13) } }));
expectFail('table supplied does not hash to the head', () => update({ tweak: { tableArg: mkTable(pubs, [...SOURCES.slice(1), SOURCES[0]]) } }));
expectFail('head commit with a new table hash (rotation needs rotate())', () => update({ tweak: { newTableHash: hash160(mkTable(pubs.slice(0, 12), SOURCES.slice(0, 12))) } }));
expectFail('reserve drain beyond the fee cap', () => update({ tweak: { extraDrain: 6000n } }));
expectFail('extra output', () => update({ tweak: { extraOutput: true } }));
expectFail('ticker at 793 sats (overpaid dust)', () => update({ tweak: { tickerSats: 793n } }));
expectFail('ticker at 791 sats', () => update({ tweak: { tickerSats: 791n } }));
expectFail('timestamp more than six hours ahead of the locktime', () => update({ tweak: { locktime: TS0 + 60 - AHEAD - 1 } }));
expectFail('final sequence number defeats the time bound', () => update({ tweak: { sequence: 0xffffffff } }));
expectFail('red team 4: update burning last minute\'s tickers through consume()', () => update({ recycle: [{ recycleAt: TS0 - AHEAD, utxo: tickerUtxo(TS0, SEQ0, PRICE0, 13, 'last a'), unlock: ticker.unlock.consume() }, { recycleAt: TS0 - AHEAD, utxo: tickerUtxo(TS0, SEQ0, PRICE0, 13, 'last b'), unlock: ticker.unlock.consume() }] }));

// ─── ticker paths ───
{
  const tU = tickerUtxo(TS0, SEQ0, PRICE0, 13, 'consume me');
  const fU = { txid: fixedTxid('funder coin'), vout: 0, satoshis: 10_000n, lockingBytecode: binToHex(fLock) };
  const consume = (tollPaid, commitOut = snap(TS0, SEQ0, PRICE0, 13), lockOut = tickerLock, change = 8_000n) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(tU, ticker.unlock.consume()); b.addInput(fU, fTemplate.unlockP2PKH());
    b.addOutput({ to: lockOut, amount: TICKER_SATS + tollPaid, token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(commitOut) } } });
    b.addOutput({ to: fLock, amount: change });
    return { b, utxos: [tU, fU] };
  };
  expectOk('ticker consume: re-emit at the same index with the 1,000-sat toll', consume(TOLL));
  expectOk('ticker consume with a larger toll', consume(5_000n, undefined, undefined, 4_000n));
  expectFail('ticker consume without the toll', () => consume(0n));
  expectFail('ticker consume with 999 sats toll', () => consume(999n));
  expectFail('ticker consume with the commitment changed', () => consume(TOLL, snap(TS0 + 60, SEQ0, PRICE0, 13)));
  expectFail('ticker consume re-locked elsewhere', () => consume(TOLL, snap(TS0, SEQ0, PRICE0, 13), fLock));
  expectFail('red team 4: recycle outside an update (input 0 is not the head)', () => {
    const b = new TransactionBuilder({ provider });
    b.addInput(fU, fTemplate.unlockP2PKH(), { sequence: SEQ_NF }); b.addInput(tickerUtxo(TS0 - 2 * 86400, SEQ0 - 60, PRICE0, 13, 'orphan'), ticker.unlock.recycle(), { sequence: SEQ_NF });
    b.addOutput({ to: fLock, amount: 10_000n }); b.setLocktime(TS0 - 2 * 86400 + LIFE);
    return { b };
  });
  check('ticker functions: consume, recycle (no sweep path)', art('../artifacts/Ticker.json').abi.map((f) => f.name).join(',') === 'consume,recycle');
}

// ─── rotation (v27 head) ───
const key13 = sha256.hash(utf8('ticker.cash v27 test row 13'));
const pub13 = secp256k1.derivePublicKeyCompressed(key13);
const table14 = mkTable([...pubs, pub13], [...SOURCES, 4]);
let rotSize;
{
  const r = rotate({ newTable: table14 });
  rotSize = r.size;
  expectOk('rotate: 7 of 13 rows add a 14th row (same script, new table hash)', r);
  const head14 = headUtxo(headCommit(TS0, SEQ0, PRICE0, 13, hash160(table14)), 'head after rotation');
  expectOk('update after rotation: 14 of 14 rows sign', update({ k: 14, head: head14, tableBytes: table14, rowKeys: [...keys, key13], rowSources: [...SOURCES, 4] }));
  expectFail('update after rotation with the old 13-row table', () => update({ k: 13, head: head14 }));
  expectOk('rotate to P2PKH: retirement, state carried, tail empty', rotate({ nextLock: fLock, nextTail: new Uint8Array(0) }));
  expectOk('rotate with 8 of 13', rotate({ newTable: table14, signers: [0, 2, 4, 6, 8, 10, 11, 12] }));
}
expectFail('rotate with 6 of 13 (not a majority)', () => rotate({ newTable: table14, signers: [0, 1, 2, 3, 4, 5] }));
expectFail('rotate: approvals signed over another locking bytecode', () => rotate({ newTable: table14, tweak: { signedLock: fLock } }));
expectFail('rotate: approvals signed for another table (replay against a different head)', () => rotate({ newTable: table14, tweak: { signedOldHash: hash160(table14) } }));
expectFail('rotate: duplicate signer', () => rotate({ newTable: table14, signers: [0, 1, 2, 3, 4, 5, 5] }));
expectFail('rotate: state changed', () => rotate({ newTable: table14, tweak: { state: snap(TS0 + 60, SEQ0, PRICE0, 13) } }));
expectFail('rotate: second output', () => rotate({ newTable: table14, tweak: { extraOutput: true } }));
expectFail('rotate: table supplied does not hash to the head', () => rotate({ newTable: table14, tableBytes: table14 }));

// ─── the live migration path: a v26 head rotates into the v27 lock, then posts its first v27 update ───
let migrateSize, migratedHead;
{
  const commit26 = cat(u32(SEQ26), u64(PRICE26), new Uint8Array([13]), tableHash); // v26 layout: seq ‖ price(8) ‖ k ‖ tableHash
  const head26 = headUtxo(commit26, 'v26 head', RESERVE, oracle26Lock);
  const tail = cat(new Uint8Array(4), tableHash); // 4 filler bytes so the table hash lands at [17..37)
  const r = rotate({ nextLock: oracleLock, nextTail: tail, head: head26, legacy: true });
  migrateSize = r.size;
  expectOk('migration: v26 head rotates into the v27 lock (7 of 13 approvals under v26 rules)', r);
  check('migrated commitment is 37 bytes with the table hash at [17..37)', r.nextCommit.length === 37 && binToHex(r.nextCommit.slice(17)) === binToHex(tableHash));
  migratedHead = headUtxo(r.nextCommit, 'migrated head', RESERVE - BigInt(migrateSize + 1));
  // old bytes [8..12) are the v26 price's high dword: 27,257,000,000 >> 32 = 6, so the counter continues from 7
  const high = Number(PRICE26 >> 32n);
  const first = update({ k: 13, ts: SEQ26 * 60 + 60, head: migratedHead, oldSeq: high });
  expectOk(`first v27 update after migration (dataSequence ${high + 1})`, first);
  const c = decodeTransaction(hexToBin(first.b.build())).outputs[0].token.nft.commitment;
  const dv = new DataView(c.buffer, c.byteOffset, c.byteLength);
  check('first v27 commitment: ts = minute start, sequences = ' + (high + 1) + ', table hash kept', dv.getUint32(0, true) === SEQ26 * 60 + 60 && dv.getUint32(8, true) === high + 1 && dv.getUint32(4, true) === high + 1 && binToHex(c.slice(17)) === binToHex(tableHash));
  expectFail('first v27 update with the wrong counter', () => update({ k: 13, ts: SEQ26 * 60 + 60, head: migratedHead, oldSeq: high + 1 }));
}

// ─── reference consumer ───
{
  const recip = sha256.hash(utf8('ticker.cash v27 test recipient'));
  const rt = new SignatureTemplate(recip);
  const rLock = encodeLockingBytecodeP2pkh(hash160(rt.publicKey));
  const gated = (minK, strike = 28000, minT = TS0 - 600, maxT = TS0 + 600) => new Contract(art('../artifacts/PriceGated.json'), [rt.publicKey, u32(strike), catVm, BigInt(minT), BigInt(maxT), BigInt(minK)], { provider, contractType: 'p2sh32' });
  const release = (pg, tU) => {
    const pgLock = cashAddressToLockingBytecode(pg.address).bytecode;
    const pU = { txid: fixedTxid('gated coin'), vout: 0, satoshis: 100_000n, lockingBytecode: binToHex(pgLock) };
    const fU = { txid: fixedTxid('funder coin 2'), vout: 0, satoshis: 10_000n, lockingBytecode: binToHex(fLock) };
    const b = new TransactionBuilder({ provider });
    b.addInput(pU, pg.unlock.release(rt)); b.addInput(tU, ticker.unlock.consume()); b.addInput(fU, fTemplate.unlockP2PKH());
    b.addOutput({ to: rLock, amount: 100_000n });
    b.addOutput({ to: tickerLock, amount: tU.satoshis + TOLL, token: tU.token });
    b.addOutput({ to: fLock, amount: 8_000n });
    return { b, utxos: [pU, tU, fU] };
  };
  expectOk('PriceGated: releases on a k=13 ticker with minK=11', release(gated(11), tickerUtxo(TS0, SEQ0, PRICE0, 13, 'gated ticker')));
  expectFail('PriceGated: refuses a k=7 ticker when minK=11', () => release(gated(11), tickerUtxo(TS0, SEQ0, PRICE0, 7, 'weak ticker')));
  expectFail('PriceGated: refuses a stale ticker', () => release(gated(7), tickerUtxo(TS0 - 660, SEQ0 - 11, PRICE0, 13, 'stale ticker')));
  expectFail('PriceGated: refuses a hoarded ticker', () => release(gated(7), tickerUtxo(TS0 + 660, SEQ0 + 11, PRICE0, 13, 'future ticker')));
  expectFail('PriceGated: refuses a price below strike', () => release(gated(7, 30000), tickerUtxo(TS0, SEQ0, PRICE0, 13, 'low ticker')));
}

console.log(`\nsizes: update k=7 ${sizes[7]} B, k=8 ${sizes[8]} B, k=13 ${sizes[13]} B, k=13 + 2 recycled + top-up ${sizes.recycle} B, rotate (7 sigs) ${rotSize} B, migration ${migrateSize} B`);
console.log(`${results.bad === 0 ? 'ALL GREEN' : 'FAILURES'}: ${results.ok} passed, ${results.bad} failed`);

// ─── vectors for node/core ───
if (process.argv.includes('--vectors')) {
  const u13 = update({ k: 13 });
  const uR = update({ k: 13, recycle: [oldV27, oldV26], topup: { utxo: topupUtxo, template: fTemplate } });
  const rot = rotate({ newTable: table14 });
  const commit26 = cat(u32(SEQ26), u64(PRICE26), new Uint8Array([13]), tableHash);
  const head26 = headUtxo(commit26, 'v26 head', RESERVE, oracle26Lock);
  const tail = cat(new Uint8Array(4), tableHash);
  const mig = rotate({ nextLock: oracleLock, nextTail: tail, head: head26, legacy: true });
  const stmts = (k, ts) => Array.from({ length: k }, (_, r) => { const price = PRICE0 + r * 10 - 60; return { row: r, source: SOURCES[r], ts, price, sig: binToHex(sign(keys[r], SOURCES[r], ts, price)) }; });
  const vectors = {
    note: 'generated by contracts/test/v27.suite.mjs --vectors; node/core replays these byte for byte',
    category: categoryHex, oracle_lock: binToHex(oracleLock), ticker_lock: binToHex(tickerLock), oracle_redeem: binToHex(hexToBin(oracle.bytecode)),
    oracle26_lock: binToHex(oracle26Lock), oracle26_redeem: binToHex(hexToBin(oracle26.bytecode)), ticker26_lock: binToHex(ticker26Lock),
    keys: keys.map(binToHex), sources: SOURCES, table: binToHex(table), table_hash: binToHex(tableHash),
    head: { txid: fixedTxid('head'), vout: 0, value: RESERVE.toString(), ts: TS0, seq: SEQ0, price: PRICE0, k: 13 },
    update_k13: { ts: TS0 + 60, statements: stmts(13, TS0 + 60), tx: u13.b.build(), size: u13.size },
    update_recycle_topup: {
      ts: TS0 + 60, statements: stmts(13, TS0 + 60),
      recycled_v27: [{ txid: fixedTxid('old v27 ticker'), vout: 1, value: (TICKER_SATS + 2n * TOLL).toString(), ts: TS0 - 3 * 86400, seq: SEQ0 - 100, price: PRICE0, k: 13 }],
      recycled_v26: [{ txid: fixedTxid('old v26 ticker'), vout: 1, value: '786', seq: SEQ26 - 180, price: PRICE26.toString(), k: 13 }],
      topup: { txid: fixedTxid('topup'), vout: 0, value: '1000000', private_key: binToHex(funder) },
      tx: uR.b.build(), size: uR.size,
    },
    rotate: { new_table: binToHex(table14), signers: [0, 1, 2, 3, 4, 5, 6], approvals: [0, 1, 2, 3, 4, 5, 6].map((r) => binToHex(approve(keys[r], tableHash, oracleLock, hash160(table14)))), tx: rot.b.build(), size: rot.size },
    migrate: { head26: { txid: fixedTxid('v26 head'), vout: 0, value: RESERVE.toString(), seq: SEQ26, price: PRICE26.toString(), k: 13 }, tail: binToHex(tail), signers: [0, 1, 2, 3, 4, 5, 6], approvals: [0, 1, 2, 3, 4, 5, 6].map((r) => binToHex(approve(keys[r], tableHash, oracleLock, tail))), tx: mig.b.build(), size: mig.size },
    genesis: { txid: fixedTxid('genesis funding'), vout: 0, value: '100000000', private_key: binToHex(funder), reserve: '50000000', ts0: TS0 },
  };
  fs.writeFileSync(new URL('./v27-vectors.json', import.meta.url), JSON.stringify(vectors, null, 1));
  console.log('wrote test/v27-vectors.json');
}
process.exit(results.bad === 0 ? 0 : 1);
