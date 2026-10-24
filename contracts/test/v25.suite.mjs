import fs from 'node:fs';
import { Contract, MockNetworkProvider, TransactionBuilder, VmTarget, SignatureTemplate } from 'cashscript';
import { secp256k1, sha256, hexToBin, binToHex, generatePrivateKey, generateRandomBytes, cashAddressToLockingBytecode,
         decodeTransaction, verifyTransactionTokens, ripemd160, encodeLockingBytecodeP2pkh } from '@bitauth/libauth';
const hash160 = (b) => ripemd160.hash(sha256.hash(b));

const oracleArtifact = JSON.parse(fs.readFileSync(new URL('../artifacts/Oracle.json', import.meta.url), 'utf8'));
const tickerArtifact = JSON.parse(fs.readFileSync(new URL('../artifacts/Ticker.json', import.meta.url), 'utf8'));
const provider = new MockNetworkProvider({ vmTarget: VmTarget.BCH_2026_05 });
const ticker = new Contract(tickerArtifact, [], { provider, contractType: 'p2s' });
const tickerLock = hexToBin(ticker.bytecode);
// placeholder, set after the table exists
let oracle, oracleLock;

const N = 13, Q = 7, K = 2, TICKER_SATS = 708n, RESERVE = 50_000_000n; // 708 = dust floor of the 88-byte P2S token output
const keys = Array.from({ length: N }, () => generatePrivateKey(() => generateRandomBytes(32)));
const pubs = keys.map(k => secp256k1.derivePublicKeyCompressed(k));
const cat = (...xs) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const SOURCES = Array.from({ length: N }, (_, i) => i + 1); // exchange ids 1..13 as in node/core/src/chain/sources.rs
const table = cat(...pubs.map((p, i) => cat(p, new Uint8Array([SOURCES[i]]))));
oracle = new Contract(oracleArtifact, [table, tickerLock], { provider, contractType: 'p2sh32' });
oracleLock = cashAddressToLockingBytecode(oracle.address).bytecode;
const categoryHex = binToHex(generateRandomBytes(32));
const catVm = hexToBin(categoryHex).slice().reverse();
const uLE = (n, w) => { const b = new Uint8Array(w); let v = BigInt(n); for (let i = 0; i < w; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const u32 = (n) => uLE(n, 4), u64 = (n) => uLE(n, 8);
const sign = (row, seq, body, key = keys[row], source = SOURCES[row], category = catVm) => {
  const msg = cat(new Uint8Array([0x4e]), category, new Uint8Array([row]), new Uint8Array([source]), u32(seq), body);
  const sig = secp256k1.signMessageHashSchnorr(key, sha256.hash(msg)); if (typeof sig === 'string') throw new Error(sig); return sig;
};
const SEQ0 = 29_870_000, PRICE0 = 29_000_000_000n;
const oldCommit = cat(u32(SEQ0), u64(PRICE0));
const oracleUtxo = (commit = oldCommit) => ({ txid: binToHex(generateRandomBytes(32)), vout: 0, satoshis: RESERVE, lockingBytecode: binToHex(oracleLock),
  token: { category: categoryHex, amount: 0n, nft: { capability: 'minting', commitment: binToHex(commit) } } });
const mintOut = (commit, amount) => ({ to: oracleLock, amount, token: { category: categoryHex, amount: 0n, nft: { capability: 'minting', commitment: binToHex(commit) } } });
const tickerOut = (sc, amount = TICKER_SATS) => ({ to: tickerLock, amount, token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(sc) } } });

function tokensOk(builder, utxos) {
  const tx = decodeTransaction(hexToBin(builder.build()));
  const src = utxos.map(u => ({ lockingBytecode: hexToBin(u.lockingBytecode), valueSatoshis: u.satoshis,
    token: u.token ? { category: hexToBin(u.token.category), amount: u.token.amount, nft: u.token.nft ? { capability: u.token.nft.capability, commitment: hexToBin(u.token.nft.commitment) } : undefined } : undefined }));
  return verifyTransactionTokens(tx, src);
}

// Scenario builder for updates. `tweak` lets negative tests mutate pieces.
function update({ k = Q, seq = SEQ0 + 1, tweak = {} } = {}) {
  const rows = tweak.rows ?? Array.from({ length: k }, (_, i) => i);
  const prices = tweak.prices ?? rows.map((r) => PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n);
  const sorted = [...prices].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const median = tweak.median ?? sorted[Math.floor((rows.length - 1) / 2)];
  const sigs = tweak.sigs ?? cat(...rows.map((r, i) => sign(r, seq, u64(prices[i]))));
  const sc = cat(u32(seq), u64(tweak.commitPrice ?? median));
  const newCommit = sc;
  const utxo = oracleUtxo(tweak.oldCommit);
  const mk = (fee) => {
    const b = new TransactionBuilder({ provider });
    b.addInput(utxo, oracle.unlock.update(u32(seq), new Uint8Array(rows), cat(...prices.map(u64)), sigs, u64(median)));
    b.addOutput(mintOut(newCommit, RESERVE - BigInt(K) * (tweak.tickerSats ?? TICKER_SATS) - fee - (tweak.extraDrain ?? 0n) - (tweak.extraOutput ? 1000n : 0n)));
    for (let j = 0; j < K; j++) b.addOutput(tickerOut(tweak.tickerCommit ?? sc, tweak.tickerSats));
    if (tweak.extraOutput) b.addOutput({ to: oracleLock, amount: 1000n });
    return b;
  };
  let b = mk(3000n); const size = BigInt(b.build().length / 2); b = mk(size + 1n); // fee policy: exactly size + 1 sat
  return { b, utxo, size: Number(size) };
}
const expectOk = (name, { b, utxo, size }) => { try { b.build(); const dbg = b.debug(); const tr = dbg[Object.keys(dbg)[0]]; const m = tr?.[tr.length - 1]?.metrics; if (m) console.log(`     opcost ${m.operationCost}/${m.maximumOperationCost}  hashIters ${m.hashDigestIterations}/${m.maximumHashDigestIterations}  sigchecks ${m.signatureCheckCount}`); const t = tokensOk(b, Array.isArray(utxo) ? utxo : [utxo]); console.log(`OK   ${name}${size ? ` (${size} B)` : ''} tokens=${t === true ? 'valid' : t}`); } catch (e) { console.log(`FAIL ${name}: ${e.message.split('\n')[0].slice(0, 140)}`); } };
const expectFail = (name, mk) => { try { const { b } = mk(); b.build(); b.debug(); console.log(`BUG  ${name}: accepted`); } catch (e) { console.log(`ok   ${name}: rejected -> ${e.message.split('\n')[0].slice(0, 110)}`); } };

console.log(`oracle redeem ${oracle.bytecode.length / 2} B (table ${table.length} B inside), ticker lock ${tickerLock.length} B (p2s), head commit ${oldCommit.length} B`);
expectOk('update k=7', update({ k: 7 }));
expectOk('update k=13', update({ k: 13 }));
expectOk('update k=8 (even, lower median)', update({ k: 8 }));
expectFail('update k=6 (below quorum)', () => update({ k: 6 }));
expectFail('duplicate row', () => update({ tweak: { rows: [0, 1, 2, 3, 4, 5, 5] } }));
expectFail('stale seq (== old)', () => update({ seq: SEQ0 }));
expectFail('statement signed for another exchange (source byte)', () => update({ tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(r, SEQ0 + 1, u64(PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n), keys[r], SOURCES[(r + 1) % N]))) } }));
expectFail('statement signed for another deployment (category)', () => update({ tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(r, SEQ0 + 1, u64(PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n), keys[r], SOURCES[r], generateRandomBytes(32)))) } }));
expectFail('forged signature (wrong key)', () => update({ tweak: { sigs: cat(...Array.from({ length: 7 }, (_, r) => sign(r, SEQ0 + 1, u64(PRICE0 + BigInt(r) * 1_000_000n - 6_000_000n), keys[(r + 1) % N]))) } }));
expectFail('wrong median claimed', () => update({ tweak: { median: PRICE0 + 6_000_000n } }));
expectFail('commit price != median', () => update({ tweak: { commitPrice: PRICE0 + 1n } }));
expectFail('ticker commit mismatch', () => update({ tweak: { tickerCommit: cat(u32(SEQ0 + 1), u64(1n)) } }));
expectFail('reserve drain > 5000', () => update({ tweak: { extraDrain: 6000n } }));
expectFail('extra output', () => update({ tweak: { extraOutput: true } }));
expectFail('ticker value 709 (overpay)', () => update({ tweak: { tickerSats: 709n } }));

// Ticker paths
{
  const sc = cat(u32(SEQ0), u64(PRICE0));
  const tUtxo = { txid: binToHex(generateRandomBytes(32)), vout: 1, satoshis: TICKER_SATS, lockingBytecode: binToHex(tickerLock), token: { category: categoryHex, amount: 0n, nft: { capability: 'none', commitment: binToHex(sc) } } };
  const p2pkhOut = hexToBin('76a914' + '11'.repeat(20) + '88ac');
  const sweep = new TransactionBuilder({ provider }); sweep.addInput(tUtxo, ticker.unlock.sweep(), { sequence: 144 }); sweep.addOutput({ to: p2pkhOut, amount: TICKER_SATS - 87n }); // single-ticker sweep: 86 B tx, fee 87
  expectOk('ticker sweep after 144 units (NFT burned)', { b: sweep, utxo: tUtxo, size: sweep.build().length / 2 });
  expectFail('ticker sweep at 143 units', () => { const b = new TransactionBuilder({ provider }); b.addInput(tUtxo, ticker.unlock.sweep(), { sequence: 143 }); b.addOutput({ to: p2pkhOut, amount: TICKER_SATS - 87n }); return { b }; });
  // consume: ticker at input 0 re-emitted at output 0; a P2PKH funder pays the fee
  const fk = generatePrivateKey(() => generateRandomBytes(32)); const st = new SignatureTemplate(fk);
  const fLock = encodeLockingBytecodeP2pkh(hash160(st.publicKey));
  const fUtxo = { txid: binToHex(generateRandomBytes(32)), vout: 0, satoshis: 10_000n, lockingBytecode: binToHex(fLock) };
  const c = new TransactionBuilder({ provider }); c.addInput(tUtxo, ticker.unlock.consume()); c.addInput(fUtxo, st.unlockP2PKH()); c.addOutput(tickerOut(sc)); c.addOutput({ to: fLock, amount: 9_000n });
  expectOk('ticker consume (re-emit at same index)', { b: c, utxo: [tUtxo, fUtxo], size: undefined });
  expectFail('ticker consume with value changed', () => { const b = new TransactionBuilder({ provider }); b.addInput(tUtxo, ticker.unlock.consume()); b.addInput(fUtxo, st.unlockP2PKH()); b.addOutput(tickerOut(sc, 800n)); b.addOutput({ to: fLock, amount: 9_000n }); return { b }; });
}
