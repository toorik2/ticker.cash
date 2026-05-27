#!/usr/bin/env tsx
/**
 * Chipnet deploy ceremony.
 *
 * Three covenants get minted in a fixed order:
 *   1. Ticker (no constructor args; address derived from compiled bytecode).
 *   2. TLSNotaryGateway (7 notary pubkeys + 13-source CN-hash blob + VA
 *      locking bytecode + expiry offset). A minting NFT is issued at the
 *      gateway address from a master-funded UTXO; this funding txid becomes
 *      the attestation category for all subsequent VerifiedAttestations.
 *   3. Oracle (Ticker locking bytecode + LE-reversed attestation category).
 *      Genesis state NFT is minted with a bootstrap median price.
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
  VerifiedAttestationArtifact,
  TickerArtifact,
  TLSNotaryGatewayArtifact,
} from '../src/load-artifacts.js';
import { deriveWallets, loadSeed, NOTARY_COUNT } from '../src/keys.js';
import {
  SOURCES,
  SOURCE_COUNT,
  sourceCNHashHex,
  packedSourceCNHashes,
  ORACLE_DUST,
  GATEWAY_DUST,
  VA_EXPIRY_OFFSET,
  reverseHex,
} from '../src/helpers.js';
import { encodeOracleCommit } from '../src/oracle-update.js';

const STATE_PATH = '.ticker/deploy-state.json';
const FUND_RESERVE_SATS = 5_000n;
const GENESIS_INPUT_MIN_SATS = 8_000n;
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
  gatewayCategory?: string;
  gatewayMintTxid?: string;
  gatewayAddress?: string;
  vaAddress?: string;
  vaLockingBytecodeHex?: string;
  oracleCategory?: string;
  oracleMintTxid?: string;
  oracleAddress?: string;
  initLastTs?: number;
  bootstrapMedianSats?: string;
}

const loadState = (): DeployState =>
  existsSync(STATE_PATH) ? (JSON.parse(readFileSync(STATE_PATH, 'utf8')) as DeployState) : {};

const saveState = (s: DeployState): void => {
  mkdirSync(dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
};

const main = async (): Promise<void> => {
  const broadcast = process.argv.includes('--broadcast');
  console.log(`deploy ceremony — ${broadcast ? 'BROADCAST' : 'plan only (--broadcast to execute)'}`);

  const seed = loadSeed();
  const wallets = deriveWallets(seed);
  const state = loadState();
  const provider = buildLocalProvider();
  console.log(`  electrum: ${ELECTRUM_HOST}:${ELECTRUM_PORT}${ELECTRUM_TLS ? ' (tls)' : ''}`);

  console.log(`\n[1/5] Balances:`);
  const masterUtxos = await provider.getUtxos(wallets.master.address);
  const masterBalance = masterUtxos.filter((u) => !u.token).reduce((s, u) => s + u.satoshis, 0n);
  console.log(`  master ${wallets.master.address}: ${masterBalance} sats (${masterUtxos.length} utxos)`);
  if (masterBalance < GENESIS_INPUT_MIN_SATS * 2n) {
    console.log(`  ⚠ master needs ≥ ${GENESIS_INPUT_MIN_SATS * 2n} sats (gateway + oracle).`);
  }

  // ─── Stage 2: Ticker covenant ────────────────────────────────────────
  console.log(`\n[2/5] Ticker covenant (no constructor args):`);
  const tickerContract = new Contract(TickerArtifact, [], { provider });
  const tickerLockingBytecode = tickerContract.lockingBytecode;
  state.tickerAddress = tickerContract.tokenAddress;
  state.tickerLockingBytecodeHex = tickerLockingBytecode;
  console.log(`  Ticker address: ${state.tickerAddress}`);

  // ─── Stage 3: TLSNotaryGateway ──────────────────────────────────────
  console.log(`\n[3/5] TLSNotaryGateway (7 notary pubkeys, 13 source CNs):`);
  if (SOURCES.length !== SOURCE_COUNT) throw new Error(`expected ${SOURCE_COUNT} sources`);
  if (wallets.notaries.length !== NOTARY_COUNT) throw new Error(`expected ${NOTARY_COUNT} notaries`);
  if (NOTARY_COUNT !== 7) throw new Error(`requires NOTARY_COUNT=7, got ${NOTARY_COUNT}`);
  const vaContract = new Contract(VerifiedAttestationArtifact, [], { provider });
  state.vaAddress = vaContract.tokenAddress;
  state.vaLockingBytecodeHex = vaContract.lockingBytecode;
  console.log(`  VerifiedAttestation address: ${state.vaAddress}`);
  const gatewayConstructorArgs = [
    binToHex(wallets.notaries[0]!.publicKey),
    binToHex(wallets.notaries[1]!.publicKey),
    binToHex(wallets.notaries[2]!.publicKey),
    binToHex(wallets.notaries[3]!.publicKey),
    binToHex(wallets.notaries[4]!.publicKey),
    binToHex(wallets.notaries[5]!.publicKey),
    binToHex(wallets.notaries[6]!.publicKey),
    packedSourceCNHashes(),
    vaContract.lockingBytecode,
    BigInt(VA_EXPIRY_OFFSET),
  ];
  const gateway = new Contract(TLSNotaryGatewayArtifact, gatewayConstructorArgs, { provider });
  state.gatewayAddress = gateway.tokenAddress;
  console.log(`  TLSNotaryGateway address: ${state.gatewayAddress}`);
  SOURCES.forEach((s) => console.log(`    source ${String(s.id).padStart(2, ' ')} (${s.name.padEnd(20, ' ')}): ${sourceCNHashHex(s)}  ${s.canonicalCN}`));

  if (!state.gatewayMintTxid) {
    if (!broadcast) {
      console.log(`  → plan: mint gateway minter NFT (need ≥ ${GENESIS_INPUT_MIN_SATS} sats at vout=0)`);
    } else {
      const masterSig = new SignatureTemplate(wallets.master.privateKey);
      const nonToken = masterUtxos.filter((u) => !u.token);
      let genesis = nonToken.find((u) => u.vout === 0 && u.satoshis >= GENESIS_INPUT_MIN_SATS);
      if (!genesis) {
        const total = nonToken.reduce((s, u) => s + u.satoshis, 0n);
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
      const category = genesis.txid;
      const blockHeight = await provider.getBlockHeight();
      const heightLE = new Uint8Array(4);
      new DataView(heightLE.buffer).setUint32(0, blockHeight, true);
      const init = new Uint8Array(16);
      init[0] = 0x71;
      init.set(heightLE, 1);
      const tb = new TransactionBuilder({ provider });
      tb.addInput(genesis, masterSig.unlockP2PKH());
      tb.addOutput({
        to: gateway.tokenAddress,
        amount: GATEWAY_DUST,
        token: { amount: 0n, category, nft: { capability: 'minting', commitment: binToHex(init) } },
      });
      const change = genesis.satoshis - GATEWAY_DUST - FUND_RESERVE_SATS;
      if (change >= 546n) tb.addOutput({ to: wallets.master.address, amount: change });
      const tx = await tb.send();
      state.gatewayMintTxid = tx.txid;
      state.gatewayCategory = category;
      saveState(state);
      console.log(`     ✓ gateway mint: ${tx.txid}  ${explorerTxUrl(tx.txid)}`);
      await sleep(2_000);
    }
  } else {
    console.log(`  ✓ already minted: ${state.gatewayMintTxid}  category=${state.gatewayCategory}`);
  }

  if (!state.gatewayCategory) {
    console.log(`\n[4/5] Oracle — SKIPPED (gateway not minted)`);
    saveState(state);
    return;
  }

  // ─── Stage 4: Oracle covenant address ───────────────────────────────
  console.log(`\n[4/5] Oracle covenant (50% threshold ratchet):`);
  const attestationCategoryLEHex = reverseHex(state.gatewayCategory);
  const oracleConstructorArgs = [tickerLockingBytecode, attestationCategoryLEHex];
  const oracle = new Contract(OracleArtifact, oracleConstructorArgs, { provider });
  state.oracleAddress = oracle.tokenAddress;
  console.log(`  Oracle address: ${state.oracleAddress}`);

  // Pure wall-clock initLastTs. The notary stamps Date.now(); the Oracle
  // enforces newTs > prevTs + [30, 7200]. Chain time (MTP, tx.locktime)
  // is not in the trust path anywhere.
  const initLastTs = Math.floor(Date.now() / 1000) - 60;
  state.initLastTs = initLastTs;
  console.log(`  init Oracle lastTs: ${initLastTs}  (= wall_clock - 60s)`);

  // ─── Stage 5: Oracle genesis (19 B commit) ──────────────────────────
  console.log(`\n[5/5] Oracle state NFT (genesis):`);
  if (!state.oracleMintTxid) {
    const bootstrapMedianSats = await fetchBootstrapMedianSats();
    state.bootstrapMedianSats = bootstrapMedianSats.toString();
    console.log(`  → bootstrap median: ${bootstrapMedianSats} sats (${Number(bootstrapMedianSats) / 1e8} BCH-USD)`);
    const commitment = encodeOracleCommit({
      seq: 0,
      lastTs: initLastTs,
      medianUsd: bootstrapMedianSats,
      activeCount: 0,
    });
    if (!broadcast) {
      console.log(`  → plan: mint Oracle state NFT (19 B commit)`);
      console.log(`  → commit hex: ${binToHex(commitment)}`);
    } else {
      const refreshedMaster = await provider.getUtxos(wallets.master.address);
      const nonToken = refreshedMaster.filter((u) => !u.token);
      const masterBal = nonToken.reduce((s, u) => s + u.satoshis, 0n);
      if (masterBal < GENESIS_INPUT_MIN_SATS) {
        throw new Error(`master has ${masterBal} sats; need ≥ ${GENESIS_INPUT_MIN_SATS}`);
      }
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
      console.log(`     oracle category: ${category}`);
    }
  } else {
    console.log(`  ✓ already minted: ${state.oracleMintTxid}  category=${state.oracleCategory}`);
  }

  saveState(state);
  console.log(`\nDeploy state saved to ${STATE_PATH}`);
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
