// v26 VM suite: cashscript 0.14 MockNetworkProvider on BCH_2026_05 plus libauth token validation.
// Every scenario is built with exact fees (size + 1 sat). Negative scenarios drive one forged
// transaction into each `require`, including the red-team proofs of concept against v25.
// `--vectors` additionally writes test/v26-vectors.json, which node/core replays byte for byte.
import fs from 'node:fs';
import { Contract, MockNetworkProvider, TransactionBuilder, VmTarget, SignatureTemplate } from 'cashscript';
import { secp256k1, sha256, ripemd160, hexToBin, binToHex, cashAddressToLockingBytecode,
         decodeTransaction, verifyTransactionTokens, encodeLockingBytecodeP2pkh } from '@bitauth/libauth';

const hash160 = (b) => ripemd160.hash(sha256.hash(b));
const cat = (...xs) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const uLE = (n, w) => { const b = new Uint8Array(w); let v = BigInt(n); for (let i = 0; i < w; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const u32 = (n) => uLE(n, 4), u64 = (n) => uLE(n, 8);
const utf8 = (s) => new TextEncoder().encode(s);

const oracleArtifact = JSON.parse(fs.readFileSync(new URL('../artifacts/Oracle.json', import.meta.url), 'utf8'));
const tickerArtifact = JSON.parse(fs.readFileSync(new URL('../artifacts/Ticker.json', import.meta.url), 'utf8'));
const pgArtifact = JSON.parse(fs.readFileSync(new URL('../artifacts/PriceGated.json', import.meta.url), 'utf8'));
const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
const ticker = new Contract(tickerArtifact, [], { provider, contractType: 'p2s' });
const tickerLock = hexToBin(ticker.bytecode);
const oracle = new Contract(oracleArtifact, [tickerLock], { provider, contractType: 'p2sh32' });
const oracleLock = cashAddressToLockingBytecode(oracle.address).bytecode;

// ─── protocol constants (must equal the covenant literals and node/core/src/lib.rs) ───
const QUORUM = 7, TICKERS = 2, TICKER_SATS = 786n, TOLL = 1000n, LIFE = 3600, AHEAD = 21600;
const FEE_CAP = (unlockLen) => 1000n + 2n * BigInt(unlockLen);

// ─── deterministic fixtures ───
const N = 13;
const keys = Array.from({ length: N }, (_, i) => sha256.hash(utf8(`ticker.cash v26 test row ${i}`)));
const pubs = keys.map((k) => secp256k1.derivePublicKeyCompressed(k));
const SOURCES = [1, 2, 3, 16, 5, 6, 7, 14, 15, 10, 11, 12, 13];
const mkTable = (ps, ss) => cat(...ps.map((p, i) => cat(p, new Uint8Array([ss[i]]))));
const table = mkTable(pubs, SOURCES);
const tableHash = hash160(table);
const categoryHex = binToHex(sha256.hash(utf8('ticker.cash v26 test category')));
const catVm = hexToBin(categoryHex).slice().reverse();
const SEQ0 = 29_870_000, PRICE0 = 29_000_000_000n;
const RESERVE = 50_000_000n;
const headCommit = (seq, price, k, th = tableHash) => cat(u32(seq), u64(price), new Uint8Array([k]), th);
const snapshot = (seq, price, k) => cat(u32(seq), u64(price), new Uint8Array([k]));
const sign = (key, source, seq, price, category = catVm) => {
  const msg = cat(new Uint8Array([0x4e]), category, new Uint8Array([source]), u32(seq), u64(price));
  const sig = secp256k1.signMessageHashSchnorr(key, sha256.hash(msg)); if (typeof sig === 'string') throw new Error(sig); return sig;
};
const approve = (key, oldHash, nextLock, tail, category = catVm) => {
  const msg = cat(new Uint8Array([0x52]), category, oldHash, nextLock, tail);
  const sig = secp256k1.signMessageHashSchnorr(key, sha256.hash(msg)); if (typeof sig === 'string') throw new Error(sig); return sig;
};
const fixedTxid = (label) => binToHex(sha256.hash(utf8('txid ' + label)));
const headUtxo = (commit = headCommit(SEQ0, PRICE0, 13), label = 'head', sats = RESERVE) => ({ txid: fixedTxid(label), vout: 0, satoshis: sats, lockingBytecode: binToHex(oracleLock),
  token: { category: categoryHex, amount: 0n, nft: { capability: 'minting', commitment: binToHex(commit) } } });
const tickerUtxo = (seq, price, k, label, sats = TICKER_SATS) => ({ txid: fixedTxid(label), vout: 1, satoshis: sats, lockingBytecode: binToHex(tickerLock),
  token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(snapshot(seq, price, k)) } } });
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

// Fee policy helper: lay the transaction out once at a guessed fee, measure, rebuild at size + 1.
function exact(mk) { let b = mk(3000n); const size = BigInt(b.build().length / 2); b = mk(size + 1n); return { b, size: Number(size) }; }

// ─── update scenario builder; `tweak` lets negative tests mutate pieces ───
function update({ k = 13, seq = SEQ0 + 1, tweak = {}, recycle = [], topup = null, tableBytes = table, rowKeys = keys, rowSources = SOURCES, head = null } = {}) {
  const rows = tweak.rows ?? Array.from({ length: k }, (_, i) => i);
  const prices = tweak.prices ?? rows.map((r) => PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n);
  const sorted = [...prices].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const median = tweak.median ?? sorted[Math.floor((rows.length - 1) / 2)];
  const sigs = tweak.sigs ?? cat(...rows.map((r, i) => sign(rowKeys[r], rowSources[r], seq, prices[i])));
  const kByte = tweak.kByte ?? rows.length;
  const sc = snapshot(seq, tweak.commitPrice ?? median, kByte);
  const th = tweak.newTableHash ?? hash160(tableBytes);
  const hUtxo = head ?? headUtxo();
  const utxos = [hUtxo, ...recycle.map((r) => r.utxo), ...(topup ? [topup.utxo] : [])];
  const inTotal = utxos.reduce((a, u) => a + u.satoshis, 0n);
  const locktime = tweak.locktime ?? Math.max(seq * 60 - AHEAD, ...recycle.map((r) => r.seq * 60 + LIFE));
  const mk = (fee) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(hUtxo, oracle.unlock.update(tweak.tableArg ?? tableBytes, u32(seq), new Uint8Array(rows), cat(...prices.map(u64)), sigs, u64(median)), { sequence: tweak.sequence ?? SEQ_NF });
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

// ─── rotate scenario builder ───
function rotate({ nextLock = oracleLock, nextTail = null, newTable = null, signers = [0, 1, 2, 3, 4, 5, 6], tweak = {}, head = null, tableBytes = table, rowKeys = keys } = {}) {
  const hUtxo = head ?? headUtxo();
  const oldHash = hash160(tableBytes);
  const tail = nextTail ?? hash160(newTable);
  const state = tweak.state ?? snapshot(SEQ0, PRICE0, 13);
  const nextCommit = cat(state, tail);
  const sigs = tweak.sigs ?? cat(...signers.map((r) => approve(rowKeys[r], tweak.signedOldHash ?? oldHash, tweak.signedLock ?? nextLock, tail)));
  const mk = (fee) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(hUtxo, oracle.unlock.rotate(tableBytes, new Uint8Array(signers), sigs), { sequence: SEQ_NF });
    b.addOutput(mintOut(nextCommit, hUtxo.satoshis - fee - (tweak.extraOutput ? 1000n : 0n), nextLock));
    if (tweak.extraOutput) b.addOutput({ to: oracleLock, amount: 1000n });
    return b;
  };
  const { b, size } = exact(mk);
  return { b, utxos: [hUtxo], size, nextCommit };
}

console.log(`oracle body ${oracleArtifact.bytecode.split(' ').length ? hexToBin(oracle.bytecode).length - tickerLock.length - 1 : '?'} B, redeem ${hexToBin(oracle.bytecode).length} B, ticker lock ${tickerLock.length} B (p2s), table ${table.length} B, head commit 33 B, ticker commit 13 B`);
console.log(`oracle lock (same for every v26 deployment) ${binToHex(oracleLock)}`);

// ─── updates ───
const sizes = {};
for (const k of [7, 8, 13]) { const u = update({ k }); sizes[k] = u.size; expectOk(`update k=${k}`, u); }
{
  // Ticker output byte size and dust: 3 × (size + 148) must equal the pinned value
  const tx = decodeTransaction(hexToBin(update({ k: 7 }).b.build()));
  const out = tx.outputs[1];
  const bytes = 8 + 1 + (out.token ? 1 + 32 + 1 + 1 + out.token.nft.commitment.length : 0) + out.lockingBytecode.length;
  console.log(`${3n * BigInt(bytes + 148) === TICKER_SATS ? 'OK  ' : 'FAIL'} ticker output ${bytes} B, dust floor ${3 * (bytes + 148)} sats, pinned ${TICKER_SATS}`);
  if (3n * BigInt(bytes + 148) !== TICKER_SATS) results.bad++; else results.ok++;
}
// recycling two hour-old Tickers plus a top-up coin: their value joins the reserve
const funder = sha256.hash(utf8('ticker.cash v26 test funder'));
const fTemplate = new SignatureTemplate(funder);
const fLock = encodeLockingBytecodeP2pkh(hash160(fTemplate.publicKey));
const topupUtxo = { txid: fixedTxid('topup'), vout: 0, satoshis: 1_000_000n, lockingBytecode: binToHex(fLock) };
{
  const old = [{ seq: SEQ0 - 120, utxo: tickerUtxo(SEQ0 - 120, PRICE0, 13, 'old ticker a') }, { seq: SEQ0 - 119, utxo: tickerUtxo(SEQ0 - 119, PRICE0, 12, 'old ticker b', TICKER_SATS + 2n * TOLL) }];
  const u = update({ k: 13, recycle: old, topup: { utxo: topupUtxo, template: fTemplate } });
  sizes.recycle = u.size;
  expectOk('update k=13 recycling 2 tickers + 1 top-up', u);
  const tx = decodeTransaction(hexToBin(u.b.build()));
  const expected = RESERVE + TICKER_SATS + TICKER_SATS + 2n * TOLL + 1_000_000n - 2n * TICKER_SATS - BigInt(u.size + 1);
  console.log(`${tx.outputs[0].valueSatoshis === expected ? 'OK  ' : 'FAIL'} reserve after = inputs - 2 tickers - fee (${tx.outputs[0].valueSatoshis})`);
  if (tx.outputs[0].valueSatoshis === expected) results.ok++; else results.bad++;
}
// the red-team subset forgery still posts, but the commitment says k = 7 (4 keys own this minute, and every reader can see that)
{
  const rows = [0, 1, 2, 3, 4, 5, 6];
  const prices = [150_03n * 1_000_000n, 150_03n * 1_000_000n, 150_03n * 1_000_000n, 150_03n * 1_000_000n, PRICE0, PRICE0 + 1n, PRICE0 + 2n];
  const u = update({ tweak: { rows, prices } });
  expectOk('red team 1: 4-key subset at k=7 posts $150 against a $290 market, labeled k=7', u);
  const c = decodeTransaction(hexToBin(u.b.build())).outputs[0].token.nft.commitment;
  console.log(`${c[12] === 7 ? 'OK  ' : 'FAIL'} commitment k byte = ${c[12]} (a consumer demanding k >= 11 ignores this minute)`);
  if (c[12] === 7) results.ok++; else results.bad++;
}

// ─── update: negatives ───
expectFail('k=6 (below the floor)', () => update({ k: 6 }));
expectFail('duplicate row', () => update({ tweak: { rows: [0, 1, 2, 3, 4, 5, 5] } }));
expectFail('row index == table size', () => update({ tweak: { rows: [0, 1, 2, 3, 4, 5, 13], sigs: cat(...[0, 1, 2, 3, 4, 5, 0].map((r, i) => sign(keys[r], SOURCES[r], SEQ0 + 1, PRICE0 + BigInt([0, 1, 2, 3, 4, 5, 13][i]) * 1_000_000n - 6_000_000n))) } }));
expectFail('stale seq (== old)', () => update({ seq: SEQ0 }));
expectFail('statement signed for another exchange (source byte)', () => update({ k: 7, tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(keys[r], SOURCES[(r + 1) % N], SEQ0 + 1, PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n))) } }));
expectFail('statement signed for another deployment (category)', () => update({ k: 7, tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(keys[r], SOURCES[r], SEQ0 + 1, PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n, sha256.hash(utf8('other'))))) } }));
expectFail('forged signature (wrong key)', () => update({ k: 7, tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(keys[(r + 1) % N], SOURCES[r], SEQ0 + 1, PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n))) } }));
expectFail('wrong median claimed (6th of 13)', () => update({ tweak: { median: PRICE0 - 1_000_000n } }));
expectFail('median value not among the prices', () => update({ tweak: { median: PRICE0 + 1n } }));
expectFail('commit price != median', () => update({ tweak: { commitPrice: PRICE0 + 1n } }));
expectFail('commit k byte wrong (claims 13 with 7 rows)', () => update({ k: 7, tweak: { kByte: 13 } }));
expectFail('ticker commit mismatch', () => update({ tweak: { tickerCommit: snapshot(SEQ0 + 1, 1n, 13) } }));
expectFail('table supplied does not hash to the head', () => update({ tweak: { tableArg: mkTable(pubs, [...SOURCES.slice(1), SOURCES[0]]) } }));
expectFail('head commit with a new table hash (rotation needs rotate())', () => update({ tweak: { newTableHash: hash160(mkTable(pubs.slice(0, 12), SOURCES.slice(0, 12))) } }));
expectFail('reserve drain beyond the fee cap', () => update({ tweak: { extraDrain: 6000n } }));
expectFail('extra output', () => update({ tweak: { extraOutput: true } }));
expectFail('ticker at 787 sats (overpaid dust)', () => update({ tweak: { tickerSats: 787n } }));
expectFail('ticker at 785 sats', () => update({ tweak: { tickerSats: 785n } }));
expectFail('seq more than six hours ahead of the locktime', () => update({ seq: SEQ0 + 1, tweak: { locktime: (SEQ0 + 1) * 60 - AHEAD - 1 } }));
expectFail('final sequence number defeats the time bound', () => update({ tweak: { sequence: 0xffffffff } }));
expectFail('red team 4: update burning last minute\'s tickers through consume()', () => update({ recycle: [{ seq: SEQ0, utxo: tickerUtxo(SEQ0, PRICE0, 13, 'last a'), unlock: ticker.unlock.consume() }, { seq: SEQ0, utxo: tickerUtxo(SEQ0, PRICE0, 13, 'last b'), unlock: ticker.unlock.consume() }], tweak: { locktime: (SEQ0 + 1) * 60 - AHEAD } }));
expectFail('recycle a ticker younger than an hour', () => update({ recycle: [{ seq: SEQ0 - 59, utxo: tickerUtxo(SEQ0 - 59, PRICE0, 13, 'young') }], tweak: { locktime: (SEQ0 - 59) * 60 + LIFE - 1 } }));

// ─── ticker paths ───
{
  const tU = tickerUtxo(SEQ0, PRICE0, 13, 'consume me');
  const fU = { txid: fixedTxid('funder coin'), vout: 0, satoshis: 10_000n, lockingBytecode: binToHex(fLock) };
  const consume = (tollPaid, commitOut = snapshot(SEQ0, PRICE0, 13), lockOut = tickerLock, change = 8_000n) => {
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
  expectFail('ticker consume with the commitment changed', () => consume(TOLL, snapshot(SEQ0 + 1, PRICE0, 13)));
  expectFail('ticker consume re-locked elsewhere', () => consume(TOLL, snapshot(SEQ0, PRICE0, 13), fLock));
  expectFail('red team 4: recycle outside an update (input 0 is not the head)', () => {
    const b = new TransactionBuilder({ provider });
    b.addInput(fU, fTemplate.unlockP2PKH(), { sequence: SEQ_NF }); b.addInput(tickerUtxo(SEQ0 - 120, PRICE0, 13, 'orphan'), ticker.unlock.recycle(), { sequence: SEQ_NF });
    b.addOutput({ to: fLock, amount: 10_000n }); b.setLocktime((SEQ0 - 120) * 60 + LIFE);
    return { b };
  });
  // there is no sweep(): a Ticker is destroyed only by an update, and never re-locked by anyone
  console.log(`${tickerArtifact.abi.map((f) => f.name).join(',') === 'consume,recycle' ? 'OK  ' : 'FAIL'} ticker functions: ${tickerArtifact.abi.map((f) => f.name).join(', ')} (red team 4: no sweep path)`);
  if (tickerArtifact.abi.map((f) => f.name).join(',') === 'consume,recycle') results.ok++; else results.bad++;
}

// ─── rotation ───
const key13 = sha256.hash(utf8('ticker.cash v26 test row 13'));
const pub13 = secp256k1.derivePublicKeyCompressed(key13);
const table14 = mkTable([...pubs, pub13], [...SOURCES, 4]);
let rotSize;
{
  const r = rotate({ newTable: table14 });
  rotSize = r.size;
  expectOk('rotate: 7 of 13 rows add a 14th row (same script, new table hash)', r);
  // the head now carries the new table hash; an update must supply the 14-row table and may include row 13
  const head14 = headUtxo(headCommit(SEQ0, PRICE0, 13, hash160(table14)), 'head after rotation');
  const keys14 = [...keys, key13], sources14 = [...SOURCES, 4];
  expectOk('update after rotation: 14 of 14 rows sign', update({ k: 14, head: head14, tableBytes: table14, rowKeys: keys14, rowSources: sources14 }));
  expectFail('update after rotation with the old 13-row table', () => update({ k: 13, head: head14 }));
  expectOk('rotate to P2PKH: retirement, state carried, tail empty', rotate({ nextLock: fLock, nextTail: new Uint8Array(0) }));
  expectOk('rotate with 8 of 13', rotate({ newTable: table14, signers: [0, 2, 4, 6, 8, 10, 11, 12] }));
}
expectFail('rotate with 6 of 13 (not a majority)', () => rotate({ newTable: table14, signers: [0, 1, 2, 3, 4, 5] }));
expectFail('rotate: approvals signed over another locking bytecode', () => rotate({ newTable: table14, tweak: { signedLock: fLock } }));
expectFail('rotate: approvals signed for another table (replay against a different head)', () => rotate({ newTable: table14, tweak: { signedOldHash: hash160(table14) } }));
expectFail('rotate: duplicate signer', () => rotate({ newTable: table14, signers: [0, 1, 2, 3, 4, 5, 5] }));
expectFail('rotate: state (seq, price, k) changed', () => rotate({ newTable: table14, tweak: { state: snapshot(SEQ0 + 1, PRICE0, 13) } }));
expectFail('rotate: second output', () => rotate({ newTable: table14, tweak: { extraOutput: true } }));
expectFail('rotate: table supplied does not hash to the head', () => rotate({ newTable: table14, tableBytes: table14 }));

// ─── reference consumer ───
{
  const recip = sha256.hash(utf8('ticker.cash v26 test recipient'));
  const rt = new SignatureTemplate(recip);
  const rLock = encodeLockingBytecodeP2pkh(hash160(rt.publicKey));
  const gated = (minK, strike = 28_000_000_000n, minSeq = SEQ0 - 10, maxSeq = SEQ0 + 10) => new Contract(pgArtifact, [rt.publicKey, u64(strike), catVm, BigInt(minSeq), BigInt(maxSeq), BigInt(minK)], { provider, contractType: 'p2sh32' });
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
  expectOk('PriceGated: releases on a k=13 ticker with minK=11', release(gated(11), tickerUtxo(SEQ0, PRICE0, 13, 'gated ticker')));
  expectFail('PriceGated: refuses a k=7 ticker when minK=11 (the red-team minute)', () => release(gated(11), tickerUtxo(SEQ0, PRICE0, 7, 'weak ticker')));
  expectFail('PriceGated: refuses a stale ticker (seq below minSeq)', () => release(gated(7), tickerUtxo(SEQ0 - 11, PRICE0, 13, 'stale ticker')));
  expectFail('PriceGated: refuses a hoarded ticker (seq above maxSeq)', () => release(gated(7), tickerUtxo(SEQ0 + 11, PRICE0, 13, 'future ticker')));
  expectFail('PriceGated: refuses a price below strike', () => release(gated(7, 30_000_000_000n), tickerUtxo(SEQ0, PRICE0, 13, 'low ticker')));
}

console.log(`\nsizes: update k=7 ${sizes[7]} B, k=8 ${sizes[8]} B, k=13 ${sizes[13]} B, k=13 + 2 recycled + top-up ${sizes.recycle} B, rotate (7 sigs) ${rotSize} B`);
console.log(`${results.bad === 0 ? 'ALL GREEN' : 'FAILURES'}: ${results.ok} passed, ${results.bad} failed`);

// ─── vectors for node/core ───
if (process.argv.includes('--vectors')) {
  const u13 = update({ k: 13 });
  const old = [{ seq: SEQ0 - 120, utxo: tickerUtxo(SEQ0 - 120, PRICE0, 13, 'old ticker a') }];
  const uR = update({ k: 13, recycle: old, topup: { utxo: topupUtxo, template: fTemplate } });
  const rot = rotate({ newTable: table14 });
  const stmts = (k, seq) => Array.from({ length: k }, (_, r) => { const price = PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n; return { row: r, source: SOURCES[r], seq, price: price.toString(), sig: binToHex(sign(keys[r], SOURCES[r], seq, price)) }; });
  const vectors = {
    note: 'generated by contracts/test/v26.suite.mjs --vectors; node/core replays these byte for byte',
    category: categoryHex, oracle_lock: binToHex(oracleLock), ticker_lock: binToHex(tickerLock), oracle_redeem: binToHex(hexToBin(oracle.bytecode)),
    keys: keys.map(binToHex), sources: SOURCES, table: binToHex(table), table_hash: binToHex(tableHash),
    head: { txid: fixedTxid('head'), vout: 0, value: RESERVE.toString(), seq: SEQ0, price: PRICE0.toString(), k: 13 },
    update_k13: { seq: SEQ0 + 1, statements: stmts(13, SEQ0 + 1), tx: u13.b.build(), size: u13.size },
    update_recycle_topup: {
      seq: SEQ0 + 1, statements: stmts(13, SEQ0 + 1),
      recycled: [{ txid: fixedTxid('old ticker a'), vout: 1, value: TICKER_SATS.toString(), seq: SEQ0 - 120, price: PRICE0.toString(), k: 13 }],
      topup: { txid: fixedTxid('topup'), vout: 0, value: '1000000', private_key: binToHex(funder) },
      tx: uR.b.build(), size: uR.size,
    },
    rotate: { new_table: binToHex(table14), signers: [0, 1, 2, 3, 4, 5, 6], approvals: [0, 1, 2, 3, 4, 5, 6].map((r) => binToHex(approve(keys[r], tableHash, oracleLock, hash160(table14)))), tx: rot.b.build(), size: rot.size },
    genesis: { txid: fixedTxid('genesis funding'), vout: 0, value: '100000000', private_key: binToHex(funder), reserve: '50000000', seq0: SEQ0 },
  };
  fs.writeFileSync(new URL('./v26-vectors.json', import.meta.url), JSON.stringify(vectors, null, 1));
  console.log('wrote test/v26-vectors.json');
}
process.exit(results.bad === 0 ? 0 : 1);
