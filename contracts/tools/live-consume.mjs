// Live consumer test against the deployed oracle: fund a PriceGated coin (strike $100, minK 11),
// then release it by co-spending the newest Ticker and re-emitting it with the 1,000-sat toll.
// Proves the consumer path on the real network: P2S Ticker spend, toll, k gate, exact fees.
//
//   node tools/live-consume.mjs [--dry-run]
//   env TICKER_MANIFEST (default https://usd.ticker.cash/manifest.json)
//       TICKER_OPERATOR_KEY (default ~/.ticker-node/operator.key; 32-byte hex, never printed)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Contract, ElectrumNetworkProvider, TransactionBuilder, SignatureTemplate, Network } from 'cashscript';
import { sha256, ripemd160, hexToBin, binToHex, encodeLockingBytecodeP2pkh, cashAddressToLockingBytecode } from '@bitauth/libauth';

const dry = process.argv.includes('--dry-run');
const GATED_SATS = 3_000n, TOLL = 1_000n, MIN_K = 11n, STRIKE = 10_000_000_000n; // $100
const cat = (...xs) => { const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0)); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const uLE = (n, w) => { const b = new Uint8Array(w); let v = BigInt(n); for (let i = 0; i < w; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const txidOf = (hex) => binToHex(sha256.hash(sha256.hash(hexToBin(hex))).reverse());
const exact = (mk) => { let b = mk(2000n); const size = BigInt(b.build().length / 2); b = mk(size + 1n); return { b, fee: size + 1n, size: Number(size) }; };

const m = await (await fetch(process.env.TICKER_MANIFEST || 'https://usd.ticker.cash/manifest.json')).json();
if (m.version !== 26) throw new Error('not a v26 manifest');
const provider = new ElectrumNetworkProvider(m.network === 'mainnet' ? Network.MAINNET : Network.CHIPNET);
const keyPath = process.env.TICKER_OPERATOR_KEY || path.join(os.homedir(), '.ticker-node', 'operator.key');
const st = new SignatureTemplate(hexToBin(fs.readFileSync(keyPath, 'utf8').trim()));
const opLock = encodeLockingBytecodeP2pkh(ripemd160.hash(sha256.hash(st.publicKey)));
const opLockHex = binToHex(opLock);
const catVm = hexToBin(m.category).reverse();
const tickerLock = hexToBin(m.ticker_lock);

const artifacts = (n) => JSON.parse(fs.readFileSync(new URL(`../artifacts/${n}.json`, import.meta.url), 'utf8'));
const ticker = new Contract(artifacts('Ticker'), [], { provider, contractType: 'p2s' });
if (ticker.bytecode !== m.ticker_lock) throw new Error('compiled Ticker lock differs from the manifest');

// newest Ticker of our category (unconfirmed ones included)
const tickers = (await provider.getUtxosForLockingBytecode(tickerLock)).filter((u) => u.token && u.token.category === m.category && u.token.nft && u.token.nft.capability === 'none' && u.token.nft.commitment.length === 26);
if (!tickers.length) throw new Error('no Ticker found');
const decode = (c) => { const b = hexToBin(c); const dv = new DataView(b.buffer, b.byteOffset, b.byteLength); return { seq: dv.getUint32(0, true), price: dv.getBigUint64(4, true), k: b[12] }; };
tickers.sort((a, b) => decode(b.token.nft.commitment).seq - decode(a.token.nft.commitment).seq);
const t = tickers[0];
const snap = decode(t.token.nft.commitment);
console.log(`ticker ${t.txid.slice(0, 12)}…:${t.vout} seq ${snap.seq} price ${Number(snap.price) / 1e8} k ${snap.k} value ${t.satoshis} (${tickers.length} tickers live)`);
if (BigInt(snap.k) < MIN_K) throw new Error(`newest ticker has k=${snap.k} < ${MIN_K}`);

const gated = new Contract(artifacts('PriceGated'), [st.publicKey, uLE(STRIKE, 8), catVm, BigInt(snap.seq - 5), BigInt(snap.seq + 5), MIN_K], { provider, contractType: 'p2sh32' });
const gatedLock = cashAddressToLockingBytecode(gated.address).bytecode;
const gatedLockHex = binToHex(gatedLock);

// operator coin
const coins = (await provider.getUtxosForLockingBytecode(opLock)).filter((u) => !u.token).sort((a, b) => Number(b.satoshis - a.satoshis));
if (!coins.length) throw new Error('operator key has no coins');
const coin = coins[0];
console.log(`operator coin ${coin.txid.slice(0, 12)}…:${coin.vout} ${coin.satoshis} sats (${coins.length} coins)`);

// step 1: fund the gated coin
const fund = exact((fee) => { const b = new TransactionBuilder({ provider }); b.addInput(coin, st.unlockP2PKH()); b.addOutput({ to: gatedLock, amount: GATED_SATS }); b.addOutput({ to: opLock, amount: coin.satoshis - GATED_SATS - fee }); return b; });
const fundHex = fund.b.build();
const fundTxid = txidOf(fundHex);
const change = coin.satoshis - GATED_SATS - fund.fee;
console.log(`fund tx ${fund.size} B fee ${fund.fee} → ${fundTxid}`);

// step 2: release with the Ticker (consume + toll), fee from the change coin
const pgUtxo = { txid: fundTxid, vout: 0, satoshis: GATED_SATS, lockingBytecode: gatedLockHex };
const funder = { txid: fundTxid, vout: 1, satoshis: change, lockingBytecode: opLockHex };
const rel = exact((fee) => {
  const b = new TransactionBuilder({ provider });
  b.addInput(pgUtxo, gated.unlock.release(st));
  b.addInput(t, ticker.unlock.consume());
  b.addInput(funder, st.unlockP2PKH());
  b.addOutput({ to: opLock, amount: GATED_SATS });
  b.addOutput({ to: tickerLock, amount: t.satoshis + TOLL, token: t.token });
  b.addOutput({ to: opLock, amount: change - TOLL - fee });
  return b;
});
const relHex = rel.b.build();
console.log(`release tx ${rel.size} B fee ${rel.fee} → ${txidOf(relHex)} (ticker re-emitted at output 1 with ${t.satoshis + TOLL} sats)`);
if (dry) { console.log('dry-run: nothing broadcast'); process.exit(0); }
console.log('broadcast fund   ', await provider.sendRawTransaction(fundHex));
console.log('broadcast release', await provider.sendRawTransaction(relHex));
const after = (await provider.getUtxosForLockingBytecode(tickerLock)).find((u) => u.txid === txidOf(relHex) && u.vout === 1);
console.log(after ? `ticker now at ${after.txid.slice(0, 12)}…:1 with ${after.satoshis} sats, commitment ${after.token.nft.commitment}` : 'ticker not yet visible at the lock');
process.exit(0);
