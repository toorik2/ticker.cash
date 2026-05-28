#!/usr/bin/env tsx
// v12 oneshot deploy with TWO prep txs (each producing a vout=0 outpoint).
// CashTokens consensus requires genesis input vout == 0.

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { binToHex, hash160 } from '@bitauth/libauth';
import { Contract, ElectrumNetworkProvider, Network, SignatureTemplate, TransactionBuilder } from 'cashscript';
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';

import { OracleArtifact, PublisherSlotArtifact, TickerArtifact } from '../src/load-artifacts.js';
import { deriveWallets, NOTARY_COUNT, PUBLISHER_COUNT } from '../src/keys.js';
import { loadSeed } from '../src/seed.js';
import { SOURCES, SOURCE_COUNT, packedSourceCNHashes, ORACLE_DUST, reverseHex, u16LE } from '../src/helpers.js';
import { encodeOracleCommit } from '../src/oracle-update.js';

const ELECTRUM_HOST = process.env.TICKER_ELECTRUM_HOST ?? '127.0.0.1';
const ELECTRUM_PORT = Number(process.env.TICKER_ELECTRUM_PORT ?? 50001);
const sock = new ElectrumTcpSocket(ELECTRUM_HOST, ELECTRUM_PORT, false, 8000);
const client = new ElectrumClient('ticker-deploy', '1.4.1', sock, { sendKeepAliveIntervalInMilliSeconds: 30_000 });
const provider = new ElectrumNetworkProvider(Network.CHIPNET, { electrum: client });

const STATE_PATH = '.ticker/deploy-state.json';
const GENESIS_FUND_SATS = 1_000_000n;
const FUND_RESERVE_SATS = 5_000n;
const SLOT_DUST = 1_000n;
const explorerTxUrl = (txid: string): string => `https://chipnet.imaginary.cash/tx/${txid}`;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const fetchBootstrapMedianSats = async (): Promise<bigint> => {
  const sources = [
    { url: 'https://api.binance.com/api/v3/ticker/price?symbol=BCHUSDT', extract: (b: string) => parseFloat((JSON.parse(b) as { price: string }).price) },
    { url: 'https://api.kraken.com/0/public/Ticker?pair=BCHUSD', extract: (b: string) => { const j = JSON.parse(b) as { result: Record<string, { c: [string, string] }> }; const k = Object.keys(j.result)[0]!; return parseFloat(j.result[k]!.c[0]); } },
    { url: 'https://api.coinbase.com/v2/prices/BCH-USD/spot', extract: (b: string) => parseFloat((JSON.parse(b) as { data: { amount: string } }).data.amount) },
  ];
  const fetchOne = async (s: typeof sources[number]) => { const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 5_000); try { const r = await fetch(s.url, { signal: ctl.signal }); if (!r.ok) throw new Error(`${s.url}: HTTP ${r.status}`); return s.extract(await r.text()); } finally { clearTimeout(t); } };
  const usds = (await Promise.allSettled(sources.map(fetchOne))).filter((r): r is PromiseFulfilledResult<number> => r.status === 'fulfilled' && Number.isFinite(r.value) && r.value > 0).map((r) => r.value).sort((a, b) => a - b);
  if (usds.length < 2) throw new Error(`bootstrap: only ${usds.length} sources responded`);
  return BigInt(Math.round(usds[Math.floor((usds.length - 1) / 2)]! * 1e8));
};

const slotGenesisCommit = (sourceId: number, pkh20: Uint8Array): Uint8Array => {
  const c = new Uint8Array(39); c[0] = 0x72; c.set(u16LE(sourceId), 1); c.set(pkh20, 3); return c;
};

const loadState = () => existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const saveState = (s: any) => { mkdirSync(dirname(STATE_PATH), { recursive: true }); writeFileSync(STATE_PATH, JSON.stringify(s, null, 2)); };

const broadcast = process.argv.includes('--broadcast');
console.log(`v12 oneshot deploy — ${broadcast ? 'BROADCAST' : 'plan only'}`);

const seed = loadSeed();
const wallets = deriveWallets(seed);
const state = loadState();
const masterSig = new SignatureTemplate(wallets.master.privateKey);
const masterAddr = wallets.master.address;

if (wallets.notaries.length !== 7 || wallets.publishers.length !== 13 || SOURCES.length !== SOURCE_COUNT) throw new Error('roster mismatch');

const tickerContract = new Contract(TickerArtifact, [], { provider });
state.tickerAddress = tickerContract.tokenAddress;
state.tickerLockingBytecodeHex = tickerContract.lockingBytecode;
console.log(`Ticker: ${state.tickerAddress}`);

async function refreshMasterUtxos() {
  return (await provider.getUtxos(masterAddr)).filter((u) => !u.token);
}

// ── Prep tx 1: make slot genesis vout=0 ──
let slotPrepTxid: string = state.slotPrepTxid;
if (!slotPrepTxid) {
  let utxos = await refreshMasterUtxos();
  const bal = utxos.reduce((s, u) => s + u.satoshis, 0n);
  console.log(`master ${masterAddr}: ${bal} sats`);
  if (bal < GENESIS_FUND_SATS * 2n + FUND_RESERVE_SATS * 2n) throw new Error(`master ${bal} too low`);
  if (!broadcast) { console.log(`plan: prep1 → vout=0 (${GENESIS_FUND_SATS} sats)`); process.exit(0); }

  const pb = new TransactionBuilder({ provider });
  for (const u of utxos) pb.addInput(u, masterSig.unlockP2PKH());
  pb.addOutput({ to: masterAddr, amount: GENESIS_FUND_SATS });
  pb.addOutput({ to: masterAddr, amount: bal - GENESIS_FUND_SATS - FUND_RESERVE_SATS });
  const tx = await pb.send();
  slotPrepTxid = tx.txid;
  state.slotPrepTxid = slotPrepTxid;
  saveState(state);
  console.log(`✓ prep1 (slot): ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
  await sleep(2_000);
}

// ── Prep tx 2: make oracle genesis vout=0 (spends slotPrep.vout=1) ──
let oraclePrepTxid: string = state.oraclePrepTxid;
if (!oraclePrepTxid) {
  const utxos = await refreshMasterUtxos();
  const prep1Change = utxos.find((u) => u.txid === slotPrepTxid && u.vout === 1);
  if (!prep1Change) throw new Error(`prep1.vout=1 not found`);
  if (!broadcast) { console.log(`plan: prep2 → vout=0 (${GENESIS_FUND_SATS} sats)`); process.exit(0); }

  const pb = new TransactionBuilder({ provider });
  pb.addInput(prep1Change, masterSig.unlockP2PKH());
  pb.addOutput({ to: masterAddr, amount: GENESIS_FUND_SATS });
  if (prep1Change.satoshis > GENESIS_FUND_SATS + FUND_RESERVE_SATS + 546n) {
    pb.addOutput({ to: masterAddr, amount: prep1Change.satoshis - GENESIS_FUND_SATS - FUND_RESERVE_SATS });
  }
  const tx = await pb.send();
  oraclePrepTxid = tx.txid;
  state.oraclePrepTxid = oraclePrepTxid;
  saveState(state);
  console.log(`✓ prep2 (oracle): ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
  await sleep(2_000);
}

// ── Resolve the two genesis outpoints ──
const refreshedUtxos = await refreshMasterUtxos();
const slotOutpoint = refreshedUtxos.find((u) => u.txid === slotPrepTxid && u.vout === 0);
const oracleOutpoint = refreshedUtxos.find((u) => u.txid === oraclePrepTxid && u.vout === 0);
if (!slotOutpoint || !oracleOutpoint) throw new Error('outpoints missing');
console.log(`slot   outpoint: ${slotOutpoint.txid}:${slotOutpoint.vout} (${slotOutpoint.satoshis} sats)`);
console.log(`oracle outpoint: ${oracleOutpoint.txid}:${oracleOutpoint.vout} (${oracleOutpoint.satoshis} sats)`);

const slotCategory = slotOutpoint.txid;
const oracleCategory = oracleOutpoint.txid;
const slotCatLE = reverseHex(slotCategory);
const oracleCatLE = reverseHex(oracleCategory);

// ── Construct contracts ──
const oracle = new Contract(OracleArtifact, [state.tickerLockingBytecodeHex, slotCatLE], { provider });
state.oracleAddress = oracle.tokenAddress;
state.oracleLockingBytecodeHex = oracle.lockingBytecode;

const slotConstructorArgs = [
  ...wallets.notaries.slice(0, 7).map((n) => binToHex(n.publicKey)),
  packedSourceCNHashes(),
  oracleCatLE,
  oracle.lockingBytecode,
];
const slot = new Contract(PublisherSlotArtifact, slotConstructorArgs, { provider });
state.slotAddress = slot.tokenAddress;
state.slotLockingBytecodeHex = slot.lockingBytecode;
console.log(`Oracle: ${state.oracleAddress}`);
console.log(`Slot:   ${state.slotAddress}`);

// ── Oracle genesis tx ──
if (!state.oracleMintTxid) {
  const median = await fetchBootstrapMedianSats();
  const initLastTs = Math.floor(Date.now() / 1000) - 60;
  state.bootstrapMedianSats = median.toString();
  state.initLastTs = initLastTs;
  console.log(`bootstrap median: ${median} sats ($${Number(median) / 1e8})`);
  const commit = encodeOracleCommit({ seq: 0, lastTs: initLastTs, medianUsd: median, activeCount: 0 });

  const tb = new TransactionBuilder({ provider });
  tb.addInput(oracleOutpoint, masterSig.unlockP2PKH());
  tb.addOutput({ to: oracle.tokenAddress, amount: ORACLE_DUST, token: { amount: 0n, category: oracleCategory, nft: { capability: 'minting', commitment: binToHex(commit) } } });
  const change = oracleOutpoint.satoshis - ORACLE_DUST - FUND_RESERVE_SATS;
  if (change >= 546n) tb.addOutput({ to: masterAddr, amount: change });
  const tx = await tb.send();
  state.oracleMintTxid = tx.txid;
  state.oracleCategory = oracleCategory;
  saveState(state);
  console.log(`✓ oracle mint: ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
  await sleep(1_500);
}

// ── Slot genesis tx (mint 13 slots) ──
if (!state.slotMintTxid) {
  const tb = new TransactionBuilder({ provider });
  tb.addInput(slotOutpoint, masterSig.unlockP2PKH());
  const slotsMinted: Array<{ sourceId: number; pkhHex: string; publisherLabel: string }> = [];
  for (let i = 0; i < 13; i++) {
    const pub = wallets.publishers[i]!;
    const sourceId = SOURCES[i]!.id;
    const pkh = hash160(pub.publicKey);
    const commit = slotGenesisCommit(sourceId, pkh);
    tb.addOutput({ to: slot.tokenAddress, amount: SLOT_DUST, token: { amount: 0n, category: slotCategory, nft: { capability: 'mutable', commitment: binToHex(commit) } } });
    slotsMinted.push({ sourceId, pkhHex: binToHex(pkh), publisherLabel: pub.label });
  }
  const change = slotOutpoint.satoshis - SLOT_DUST * 13n - FUND_RESERVE_SATS;
  if (change >= 546n) tb.addOutput({ to: masterAddr, amount: change });
  const tx = await tb.send();
  state.slotMintTxid = tx.txid;
  state.slotCategory = slotCategory;
  state.slotsMinted = slotsMinted;
  saveState(state);
  console.log(`✓ slot genesis: ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
}

console.log(`\nSummary:`);
console.log(`  Ticker        : ${state.tickerAddress}`);
console.log(`  Oracle        : ${state.oracleAddress}  category=${state.oracleCategory}`);
console.log(`  PublisherSlot : ${state.slotAddress}    category=${state.slotCategory}`);
process.exit(0);
