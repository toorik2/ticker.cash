#!/usr/bin/env tsx
/**
 * Chipnet deploy ceremony (v12 architecture).
 *
 * Two genesis transactions are constructed and broadcast:
 *
 *   1. Slot genesis tx: spends a fresh non-token vout=0 outpoint owned by
 *      `master`. The first input's txid becomes the slot category. The tx
 *      creates 13 mutable (0x01) PublisherSlot NFTs at the PublisherSlot
 *      P2SH-32 address, one per (publisher, sourceId) pair. After this tx
 *      confirms, the slot category is closed forever (CashTokens consensus).
 *
 *   2. Oracle genesis tx: spends a separate fresh outpoint. Mints exactly
 *      ONE minting (0x02) Oracle state NFT at the Oracle P2SH-32 address,
 *      with a 19-byte commit carrying (seq=0, lastTs=now-60s, median=$BCH).
 *
 * Dependency order (categories are circular):
 *   - Oracle constructor takes `slotCategoryReversed` (= LE of slot txid).
 *   - PublisherSlot constructor takes `oracleCategoryReversed` AND
 *     `oracleLockingBytecode` (P2SH-32 of Oracle covenant).
 *   So we: pick both genesis outpoints → derive both categories → construct
 *   Oracle Contract (yields oracleLockingBytecode) → construct PublisherSlot
 *   Contract → broadcast both genesis txs.
 *
 * State file: .ticker/deploy-state.json
 *
 * Run:
 *   npx tsx scripts/deploy.ts                  # plan only
 *   npx tsx scripts/deploy.ts --broadcast      # execute (consumes master funds)
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  binToHex,
  hash160,
} from '@bitauth/libauth';
import {
  Contract,
  ElectrumNetworkProvider,
  Network,
  SignatureTemplate,
  TransactionBuilder,
} from 'cashscript';
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';

const ELECTRUM_HOST = process.env.TICKER_ELECTRUM_HOST ?? '127.0.0.1';
const ELECTRUM_PORT = Number(process.env.TICKER_ELECTRUM_PORT ?? 50001);
const ELECTRUM_TLS = (process.env.TICKER_ELECTRUM_TLS ?? 'false') === 'true';
const buildLocalProvider = (): ElectrumNetworkProvider => {
  const socket = new ElectrumTcpSocket(ELECTRUM_HOST, ELECTRUM_PORT, ELECTRUM_TLS, 8000);
  const client = new ElectrumClient('ticker-deploy', '1.4.1', socket, {
    sendKeepAliveIntervalInMilliSeconds: 30_000,
    reconnectAfterMilliSeconds: 5000,
  });
  return new ElectrumNetworkProvider(Network.CHIPNET, { electrum: client });
};

import {
  OracleArtifact,
  PublisherSlotArtifact,
  TickerArtifact,
} from '../src/load-artifacts.js';
import { deriveWallets, NOTARY_COUNT, PUBLISHER_COUNT } from '../src/keys.js';
import { loadSeed } from '../src/seed.js';
import {
  SOURCES,
  SOURCE_COUNT,
  sourceCNHashHex,
  packedSourceCNHashes,
  ORACLE_DUST,
  reverseHex,
  u16LE,
} from '../src/helpers.js';
import { encodeOracleCommit } from '../src/oracle-update.js';

const STATE_PATH = '.ticker/deploy-state.json';
const FUND_RESERVE_SATS = 5_000n;
const GENESIS_INPUT_MIN_SATS = 20_000n;
const SLOT_DUST = 1_000n;
const explorerTxUrl = (txid: string): string => `https://chipnet.imaginary.cash/tx/${txid}`;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

const fetchBootstrapMedianSats = async (): Promise<bigint> => {
  const sources: Array<{ url: string; extract: (b: string) => number }> = [
    { url: 'https://api.binance.com/api/v3/ticker/price?symbol=BCHUSDT',
      extract: (b) => parseFloat((JSON.parse(b) as { price: string }).price) },
    { url: 'https://api.kraken.com/0/public/Ticker?pair=BCHUSD',
      extract: (b) => {
        const j = JSON.parse(b) as { result: Record<string, { c: [string, string] }> };
        const k = Object.keys(j.result)[0]!;
        return parseFloat(j.result[k]!.c[0]);
      } },
    { url: 'https://api.coinbase.com/v2/prices/BCH-USD/spot',
      extract: (b) => parseFloat((JSON.parse(b) as { data: { amount: string } }).data.amount) },
  ];
  const fetchOne = async (s: typeof sources[number]): Promise<number> => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 5_000);
    try {
      const r = await fetch(s.url, { signal: ctl.signal });
      if (!r.ok) throw new Error(`${s.url}: HTTP ${r.status}`);
      return s.extract(await r.text());
    } finally { clearTimeout(t); }
  };
  const usds = (await Promise.allSettled(sources.map(fetchOne)))
    .filter((r): r is PromiseFulfilledResult<number> => r.status === 'fulfilled' && Number.isFinite(r.value) && r.value > 0)
    .map((r) => r.value)
    .sort((a, b) => a - b);
  if (usds.length < 2) throw new Error(`bootstrap: only ${usds.length} sources responded; need ≥ 2`);
  const median = usds[Math.floor((usds.length - 1) / 2)]!;
  const sats = BigInt(Math.round(median * 1e8));
  if (sats <= 0n) throw new Error(`bootstrap median ${sats} ≤ 0`);
  return sats;
};

interface DeployState {
  tickerAddress?: string;
  tickerLockingBytecodeHex?: string;
  slotCategory?: string;
  slotMintTxid?: string;
  slotAddress?: string;
  slotLockingBytecodeHex?: string;
  oracleCategory?: string;
  oracleMintTxid?: string;
  oracleAddress?: string;
  oracleLockingBytecodeHex?: string;
  initLastTs?: number;
  bootstrapMedianSats?: string;
  slotsMinted?: Array<{ sourceId: number; pkhHex: string; publisherLabel: string }>;
}

const loadState = (): DeployState =>
  existsSync(STATE_PATH) ? (JSON.parse(readFileSync(STATE_PATH, 'utf8')) as DeployState) : {};

const saveState = (s: DeployState): void => {
  mkdirSync(dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
};

const slotGenesisCommit = (sourceId: number, pkh20: Uint8Array): Uint8Array => {
  if (pkh20.length !== 20) throw new Error(`pkh ${pkh20.length} != 20`);
  const c = new Uint8Array(39);
  c[0] = 0x72;
  c.set(u16LE(sourceId), 1);
  c.set(pkh20, 3);
  return c;
};

const main = async (): Promise<void> => {
  const broadcast = process.argv.includes('--broadcast');
  console.log(`ticker.cash v12 deploy — ${broadcast ? 'BROADCAST' : 'plan only (--broadcast to execute)'}`);

  const seed = loadSeed();
  const wallets = deriveWallets(seed);
  const state = loadState();
  const provider = buildLocalProvider();
  console.log(`  electrum: ${ELECTRUM_HOST}:${ELECTRUM_PORT}${ELECTRUM_TLS ? ' (tls)' : ''}`);

  if (wallets.notaries.length !== NOTARY_COUNT) throw new Error(`expected ${NOTARY_COUNT} notaries`);
  if (wallets.publishers.length !== PUBLISHER_COUNT) throw new Error(`expected ${PUBLISHER_COUNT} publishers`);
  if (PUBLISHER_COUNT !== 13) throw new Error(`v12 requires PUBLISHER_COUNT=13`);
  if (NOTARY_COUNT !== 7) throw new Error(`v12 requires NOTARY_COUNT=7`);
  if (SOURCES.length !== SOURCE_COUNT) throw new Error(`expected ${SOURCE_COUNT} sources`);

  console.log(`\n[1/4] Balances:`);
  const masterUtxos = await provider.getUtxos(wallets.master.address);
  const masterBalance = masterUtxos.filter((u) => !u.token).reduce((s, u) => s + u.satoshis, 0n);
  console.log(`  master ${wallets.master.address}: ${masterBalance} sats (${masterUtxos.length} utxos)`);
  if (masterBalance < GENESIS_INPUT_MIN_SATS * 2n) {
    console.log(`  ⚠ master needs ≥ ${GENESIS_INPUT_MIN_SATS * 2n} sats (slot + oracle genesis).`);
  }

  console.log(`\n[2/4] Ticker covenant (unchanged from v11, no constructor args):`);
  const tickerContract = new Contract(TickerArtifact, [], { provider });
  state.tickerAddress = tickerContract.tokenAddress;
  state.tickerLockingBytecodeHex = tickerContract.lockingBytecode;
  console.log(`  Ticker address: ${state.tickerAddress}`);

  // ─── Stage 3: Slot genesis (mints 13 mutable NFTs) ─────────────────
  console.log(`\n[3/4] PublisherSlot genesis (13 NFTs):`);
  SOURCES.forEach((s) => console.log(`    source ${String(s.id).padStart(2, ' ')} (${s.name.padEnd(20, ' ')}): ${sourceCNHashHex(s)}  ${s.canonicalCN}`));

  let slotGenesisOutpoint: { txid: string; vout: number; satoshis: bigint } | undefined;
  let slotCategoryReversed: string | undefined;

  if (!state.slotMintTxid) {
    if (!broadcast) {
      console.log(`  → plan: mint 13 slot NFTs in one tx (vout=0 outpoint ≥ ${GENESIS_INPUT_MIN_SATS} sats)`);
    } else {
      const masterSig = new SignatureTemplate(wallets.master.privateKey);
      const nonToken = masterUtxos.filter((u) => !u.token);
      let genesis = nonToken.find((u) => u.vout === 0 && u.satoshis >= GENESIS_INPUT_MIN_SATS);
      if (!genesis) {
        const total = nonToken.reduce((s, u) => s + u.satoshis, 0n);
        if (total < GENESIS_INPUT_MIN_SATS + FUND_RESERVE_SATS) {
          throw new Error(`master ${total} sats < ${GENESIS_INPUT_MIN_SATS + FUND_RESERVE_SATS}`);
        }
        const pb = new TransactionBuilder({ provider });
        for (const u of nonToken) pb.addInput(u, masterSig.unlockP2PKH());
        pb.addOutput({ to: wallets.master.address, amount: total - FUND_RESERVE_SATS });
        const pt = await pb.send();
        console.log(`     prep: ${pt.txid}`);
        await sleep(3_000);
        const refreshed = await provider.getUtxos(wallets.master.address);
        genesis = refreshed.find((u) => !u.token && u.vout === 0 && u.txid === pt.txid);
        if (!genesis) throw new Error(`prep tx not visible`);
      }
      slotGenesisOutpoint = { txid: genesis.txid, vout: genesis.vout, satoshis: genesis.satoshis };
      slotCategoryReversed = reverseHex(genesis.txid);
      console.log(`  slot genesis outpoint: ${genesis.txid}:${genesis.vout} (${genesis.satoshis} sats)`);
    }
  } else {
    slotCategoryReversed = reverseHex(state.slotCategory!);
    console.log(`  ✓ already minted: ${state.slotMintTxid}  slotCategory=${state.slotCategory}`);
  }

  // ─── Stage 4: Oracle Contract construction + genesis ─────────────────
  console.log(`\n[4/4] Oracle covenant (v12, 50% ratchet, walks slot inputs):`);
  if (!slotCategoryReversed && !state.slotCategory) {
    console.log(`  → SKIP (slot genesis not run yet)`);
    saveState(state);
    return;
  }
  const slotCatLE = slotCategoryReversed ?? reverseHex(state.slotCategory!);
  const oracle = new Contract(OracleArtifact, [state.tickerLockingBytecodeHex!, slotCatLE], { provider });
  state.oracleAddress = oracle.tokenAddress;
  state.oracleLockingBytecodeHex = oracle.lockingBytecode;
  console.log(`  Oracle address: ${state.oracleAddress}`);

  // Now construct slot Contract (needs oracleLockingBytecode)
  const slotConstructorArgs = [
    binToHex(wallets.notaries[0]!.publicKey),
    binToHex(wallets.notaries[1]!.publicKey),
    binToHex(wallets.notaries[2]!.publicKey),
    binToHex(wallets.notaries[3]!.publicKey),
    binToHex(wallets.notaries[4]!.publicKey),
    binToHex(wallets.notaries[5]!.publicKey),
    binToHex(wallets.notaries[6]!.publicKey),
    packedSourceCNHashes(),
    slotCatLE,                                  // placeholder, set below
    oracle.lockingBytecode,
  ];

  // Broadcast Oracle genesis (requires fresh outpoint)
  let oracleCategoryReversed: string | undefined;
  if (!state.oracleMintTxid) {
    const bootstrapMedianSats = await fetchBootstrapMedianSats();
    state.bootstrapMedianSats = bootstrapMedianSats.toString();
    const initLastTs = Math.floor(Date.now() / 1000) - 60;
    state.initLastTs = initLastTs;
    console.log(`  bootstrap median: ${bootstrapMedianSats} sats (= ${Number(bootstrapMedianSats) / 1e8} BCH-USD)`);

    const commitment = encodeOracleCommit({ seq: 0, lastTs: initLastTs, medianUsd: bootstrapMedianSats, activeCount: 0 });

    if (!broadcast) {
      console.log(`  → plan: mint Oracle state NFT (19 B commit)`);
      console.log(`  → commit hex: ${binToHex(commitment)}`);
    } else {
      const refreshedMaster = await provider.getUtxos(wallets.master.address);
      const nonToken = refreshedMaster.filter((u) => !u.token);
      const masterSig = new SignatureTemplate(wallets.master.privateKey);
      let genesis = nonToken.find((u) => u.vout === 0 && u.satoshis >= GENESIS_INPUT_MIN_SATS);
      if (!genesis) {
        const total = nonToken.reduce((s, u) => s + u.satoshis, 0n);
        const pb = new TransactionBuilder({ provider });
        for (const u of nonToken) pb.addInput(u, masterSig.unlockP2PKH());
        pb.addOutput({ to: wallets.master.address, amount: total - FUND_RESERVE_SATS });
        const pt = await pb.send();
        console.log(`     prep: ${pt.txid}`);
        await sleep(3_000);
        const refreshed2 = await provider.getUtxos(wallets.master.address);
        genesis = refreshed2.find((u) => !u.token && u.vout === 0 && u.txid === pt.txid);
        if (!genesis) throw new Error(`prep tx not visible`);
      }
      const category = genesis.txid;
      oracleCategoryReversed = reverseHex(category);

      const tb = new TransactionBuilder({ provider });
      tb.addInput(genesis, masterSig.unlockP2PKH());
      tb.addOutput({
        to: oracle.tokenAddress,
        amount: ORACLE_DUST,
        token: { amount: 0n, category, nft: { capability: 'minting', commitment: binToHex(commitment) } },
      });
      const change = genesis.satoshis - ORACLE_DUST - FUND_RESERVE_SATS;
      if (change >= 546n) tb.addOutput({ to: wallets.master.address, amount: change });
      const tx = await tb.send();
      state.oracleMintTxid = tx.txid;
      state.oracleCategory = category;
      saveState(state);
      console.log(`     ✓ oracle mint: ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
      await sleep(2_000);
    }
  } else {
    oracleCategoryReversed = reverseHex(state.oracleCategory!);
    console.log(`  ✓ already minted: ${state.oracleMintTxid}`);
  }

  if (!oracleCategoryReversed) {
    saveState(state);
    return;
  }
  slotConstructorArgs[8] = oracleCategoryReversed;
  const slot = new Contract(PublisherSlotArtifact, slotConstructorArgs, { provider });
  state.slotAddress = slot.tokenAddress;
  state.slotLockingBytecodeHex = slot.lockingBytecode;
  console.log(`  PublisherSlot address: ${state.slotAddress}`);

  if (!state.slotMintTxid && broadcast) {
    if (!slotGenesisOutpoint) throw new Error('slotGenesisOutpoint missing');
    const masterSig = new SignatureTemplate(wallets.master.privateKey);
    const category = slotGenesisOutpoint.txid;
    const tb = new TransactionBuilder({ provider });
    tb.addInput(slotGenesisOutpoint, masterSig.unlockP2PKH());

    const slotsMinted: DeployState['slotsMinted'] = [];
    for (let i = 0; i < 13; i++) {
      const pub = wallets.publishers[i]!;
      const sourceId = SOURCES[i]!.id;
      const pkh = hash160(pub.publicKey);
      const commit = slotGenesisCommit(sourceId, pkh);
      tb.addOutput({
        to: slot.tokenAddress,
        amount: SLOT_DUST,
        token: { amount: 0n, category, nft: { capability: 'mutable', commitment: binToHex(commit) } },
      });
      slotsMinted.push({ sourceId, pkhHex: binToHex(pkh), publisherLabel: pub.label });
    }
    const totalDust = SLOT_DUST * 13n;
    const change = slotGenesisOutpoint.satoshis - totalDust - FUND_RESERVE_SATS;
    if (change >= 546n) tb.addOutput({ to: wallets.master.address, amount: change });

    const tx = await tb.send();
    state.slotMintTxid = tx.txid;
    state.slotCategory = category;
    state.slotsMinted = slotsMinted;
    saveState(state);
    console.log(`     ✓ slot genesis: ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
  } else if (state.slotMintTxid) {
    console.log(`  ✓ already minted: ${state.slotMintTxid}`);
  }

  saveState(state);
  console.log(`\nDeploy state saved to ${STATE_PATH}`);
  console.log(`\nSummary:`);
  console.log(`  Ticker         : ${state.tickerAddress}`);
  console.log(`  Oracle         : ${state.oracleAddress}    category=${state.oracleCategory}`);
  console.log(`  PublisherSlot  : ${state.slotAddress}      category=${state.slotCategory}`);
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
