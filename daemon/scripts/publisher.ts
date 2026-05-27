#!/usr/bin/env tsx
/**
 * Publisher daemon — one process per publisher slot (v12 architecture).
 *
 * v12 architecture: no gateway, no per-cycle VA mints. Each publisher owns
 * ONE persistent slot NFT minted at genesis. Each cycle, the publisher
 * calls PublisherSlot.attest() to rewrite their slot's commitment with
 * fresh (price, ts, cycleSeq). Oracle.update then consumes ≥7 slots and
 * re-emits each one unchanged at the matching output index.
 *
 * Cycle:
 *   1. Read Oracle state → derive newSeq = prevSeq + 1.
 *   2. Find OUR slot UTXO (filter slot address by commitment[3..23) == pkh).
 *   3. Verify slot.cycleSeq < newSeq (else attest will fail monotonicity).
 *   4. Request notary attestation from one of the 7 notaries.
 *   5. Build + broadcast PublisherSlot.attest() — slot rewritten with newSeq.
 *   6. Watch slot address; once ≥ 7 slots have cycleSeq == newSeq:
 *      a. Build Oracle.update with N slot inputs (sorted by pkh ascending).
 *      b. Broadcast. If another publisher wins the race, that's OK.
 *
 * No central coordinator. Each publisher acts independently.
 *
 * Usage:
 *   npx tsx scripts/publisher.ts --slot 0 \
 *     --notary-url http://127.0.0.1:8081 \
 *     --notary-url http://127.0.0.1:8082 \
 *     ...
 *
 * One publisher per slot in {0..12}.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  binToHex,
  hexToBin,
  hash160,
  secp256k1,
  sha256,
  type Sha256,
  type Secp256k1,
} from '@bitauth/libauth';
import {
  Contract,
  ElectrumNetworkProvider,
  Network,
  SignatureTemplate,
  TransactionBuilder,
  type Utxo,
} from 'cashscript';
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';

const ELECTRUM_HOST = process.env.TICKER_ELECTRUM_HOST ?? '127.0.0.1';
const ELECTRUM_PORT = Number(process.env.TICKER_ELECTRUM_PORT ?? 50001);
const ELECTRUM_TLS = (process.env.TICKER_ELECTRUM_TLS ?? 'false') === 'true';
const buildLocalProvider = (): ElectrumNetworkProvider => {
  const socket = new ElectrumTcpSocket(ELECTRUM_HOST, ELECTRUM_PORT, ELECTRUM_TLS, 8000);
  const client = new ElectrumClient('ticker-publisher', '1.4.1', socket, {
    sendKeepAliveIntervalInMilliSeconds: 30_000,
    reconnectAfterMilliSeconds: 5000,
  });
  return new ElectrumNetworkProvider(Network.CHIPNET, { electrum: client });
};

import {
  OracleArtifact,
  PublisherSlotArtifact,
  TickerArtifact,
  ORACLE_COMMIT_LEN,
  SLOT_COMMIT_LEN,
  TICKER_HEAD_COUNT,
} from '../src/load-artifacts.js';
import { deriveWallets, NOTARY_COUNT, PUBLISHER_COUNT } from '../src/keys.js';
import { loadSeed } from '../src/seed.js';
import {
  SOURCES,
  packedSourceCNHashes,
  ORACLE_DUST,
  TICKER_DUST,
  THR_FLOOR,
  publisherSigDigest,
  u16LE,
  u32LE,
  u64LE,
  reverseHex,
} from '../src/helpers.js';
import {
  decodeOracleCommit,
  encodeOracleCommit,
  encodeTickerCommit,
  type OracleState,
} from '../src/oracle-update.js';

const sha256Hash = (data: Uint8Array): Uint8Array => (sha256 as Sha256).hash(data);

const SCRUB_PATTERNS: ReadonlyArray<RegExp> = [
  /\bWARNING: it is unsafe to use this Bitauth URI[\s\S]*$/,
  /https:\/\/ide\.bitauth\.com\/import-template\/\S+/g,
  /Bitauth URI:[\s\S]*?(?=\n\n|\n[A-Z]|$)/g,
];
const scrubSecrets = (s: string): string => {
  let out = s;
  for (const r of SCRUB_PATTERNS) out = out.replace(r, '[REDACTED-bitauth-uri]');
  return out;
};

const STATE_PATH_PREFIX = '.ticker/publisher-state-';
const DEPLOY_STATE_PATH = '.ticker/deploy-state.json';
const POLL_INTERVAL_MS = 2_000;
const SLOT_WAIT_MS = 25_000;
const TX_FEE_BUFFER_ATTEST = 2_000n;
const TX_FEE_BUFFER_UPDATE = 6_000n;

interface ParsedArgs {
  slot: number;
  notaryUrls: string[];
  once?: boolean;
}

const parseArgs = (): ParsedArgs => {
  const argv = process.argv.slice(2);
  let slot = 0;
  const notaryUrls: string[] = [];
  let once = false;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--slot') slot = parseInt(argv[++i] ?? '', 10);
    else if (argv[i] === '--notary-url') notaryUrls.push(argv[++i] ?? '');
    else if (argv[i] === '--once') once = true;
  }
  if (!Number.isInteger(slot) || slot < 0 || slot >= PUBLISHER_COUNT) {
    throw new Error(`--slot must be 0..${PUBLISHER_COUNT - 1}`);
  }
  if (notaryUrls.length === 0) throw new Error('at least one --notary-url required');
  return { slot, notaryUrls, once };
};

interface PublisherState {
  lastCycleSeq?: number;
  lastAttestTxid?: string;
  lastUpdateTxid?: string;
}

const statePath = (slot: number): string => `${STATE_PATH_PREFIX}${slot}.json`;
const loadPublisherState = (slot: number): PublisherState => {
  const p = statePath(slot);
  return existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as PublisherState) : {};
};
const savePublisherState = (slot: number, s: PublisherState): void => {
  mkdirSync(dirname(statePath(slot)), { recursive: true });
  writeFileSync(statePath(slot), JSON.stringify(s, null, 2));
};

interface DeployState {
  tickerAddress: string;
  tickerLockingBytecodeHex: string;
  slotCategory: string;
  slotAddress: string;
  slotLockingBytecodeHex: string;
  oracleCategory: string;
  oracleAddress: string;
  oracleLockingBytecodeHex: string;
}
const loadDeployState = (): DeployState => {
  if (!existsSync(DEPLOY_STATE_PATH)) {
    throw new Error(`no deploy state at ${DEPLOY_STATE_PATH}; run scripts/deploy.ts first`);
  }
  const s = JSON.parse(readFileSync(DEPLOY_STATE_PATH, 'utf8')) as Partial<DeployState>;
  const required = [
    'tickerAddress', 'tickerLockingBytecodeHex',
    'slotCategory', 'slotAddress', 'slotLockingBytecodeHex',
    'oracleCategory', 'oracleAddress', 'oracleLockingBytecodeHex',
  ] as const;
  for (const k of required) {
    if (!s[k]) throw new Error(`deploy state missing ${k}`);
  }
  return s as DeployState;
};

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

interface NotarySignResponse {
  sourceId: number;
  price: string;
  timestamp: number;
  serverName: string;
  notarySig: string;
  notaryPubkey: string;
}

const requestNotarySign = async (
  notaryUrl: string,
  sourceId: number,
  cycleSeq: number,
  pubkeyHashHex: string,
): Promise<NotarySignResponse> => {
  const res = await fetch(`${notaryUrl}/sign`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sourceId, cycleSeq, pubkeyHash: pubkeyHashHex }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`notary ${notaryUrl} HTTP ${res.status}: ${err}`);
  }
  return (await res.json()) as NotarySignResponse;
};

const u32LE_read = (b: Uint8Array, offset: number): number =>
  new DataView(b.buffer, b.byteOffset + offset, 4).getUint32(0, true);

interface SlotCommit {
  sourceId: number;
  pkh: Uint8Array;
  price: bigint;
  timestamp: number;
  cycleSeq: number;
}
const decodeSlotCommit = (commit: Uint8Array): SlotCommit | undefined => {
  if (commit.length !== SLOT_COMMIT_LEN || commit[0] !== 0x72) return undefined;
  return {
    sourceId: new DataView(commit.buffer, commit.byteOffset + 1, 2).getUint16(0, true),
    pkh: commit.slice(3, 23),
    price: new DataView(commit.buffer, commit.byteOffset + 23, 8).getBigUint64(0, true),
    timestamp: u32LE_read(commit, 31),
    cycleSeq: u32LE_read(commit, 35),
  };
};

const encodeSlotCommit = (
  sourceId: number,
  pkh: Uint8Array,
  price: bigint,
  timestamp: number,
  cycleSeq: number,
): Uint8Array => {
  if (pkh.length !== 20) throw new Error(`pkh ${pkh.length} != 20`);
  const c = new Uint8Array(39);
  c[0] = 0x72;
  c.set(u16LE(sourceId), 1);
  c.set(pkh, 3);
  c.set(u64LE(price), 23);
  c.set(u32LE(timestamp), 31);
  c.set(u32LE(cycleSeq), 35);
  return c;
};

const main = async (): Promise<void> => {
  const { slot, notaryUrls, once } = parseArgs();
  const seed = loadSeed();
  const wallets = deriveWallets(seed);
  const publisher = wallets.publishers[slot]!;
  const publisherSig = new SignatureTemplate(publisher.privateKey);
  const myPkh = hash160(publisher.publicKey);

  const deploy = loadDeployState();
  const provider = buildLocalProvider();
  console.log(`  electrum: ${ELECTRUM_HOST}:${ELECTRUM_PORT}${ELECTRUM_TLS ? ' (tls)' : ''}`);

  if (slot >= SOURCES.length) throw new Error(`slot ${slot} ≥ SOURCES.length ${SOURCES.length}`);
  const source = SOURCES[slot]!;
  console.log(`ticker-publisher slot=${slot} addr=${publisher.address} → sourceId=${source.id} (${source.name})`);
  console.log(`  oracle ${deploy.oracleAddress}`);
  console.log(`  slot   ${deploy.slotAddress}`);

  if (wallets.notaries.length !== 7) throw new Error(`v12 requires 7 notaries`);

  const slotConstructorArgs = [
    binToHex(wallets.notaries[0]!.publicKey),
    binToHex(wallets.notaries[1]!.publicKey),
    binToHex(wallets.notaries[2]!.publicKey),
    binToHex(wallets.notaries[3]!.publicKey),
    binToHex(wallets.notaries[4]!.publicKey),
    binToHex(wallets.notaries[5]!.publicKey),
    binToHex(wallets.notaries[6]!.publicKey),
    packedSourceCNHashes(),
    reverseHex(deploy.oracleCategory),
    deploy.oracleLockingBytecodeHex,
  ];
  const slotContract = new Contract(PublisherSlotArtifact, slotConstructorArgs, { provider });
  if (slotContract.tokenAddress !== deploy.slotAddress) {
    throw new Error(`slot address mismatch`);
  }
  const oracle = new Contract(OracleArtifact, [
    deploy.tickerLockingBytecodeHex,
    reverseHex(deploy.slotCategory),
  ], { provider });
  if (oracle.tokenAddress !== deploy.oracleAddress) throw new Error(`oracle address mismatch`);
  const ticker = new Contract(TickerArtifact, [], { provider });
  const slotConsumeUnlocker = slotContract.unlock.consume();

  let pubState = loadPublisherState(slot);
  let cycleCounter = 0;

  while (true) {
    cycleCounter += 1;
    console.log(`\n── cycle ${cycleCounter} ──`);
    try {
      const oracleUtxos = await provider.getUtxos(oracle.tokenAddress);
      const oracleUtxo = oracleUtxos.find(
        (u) => u.token?.category === deploy.oracleCategory && u.token.nft?.capability === 'minting',
      );
      if (!oracleUtxo) {
        await sleep(POLL_INTERVAL_MS);
        continue;
      }
      const oracleCommitment = hexToBin(oracleUtxo.token!.nft!.commitment);
      const prevSeq = u32LE_read(oracleCommitment, 1);
      const prevTs = u32LE_read(oracleCommitment, 5);
      const newSeq = prevSeq + 1;
      const now = Math.floor(Date.now() / 1000);
      console.log(`  prevSeq=${prevSeq} → newSeq=${newSeq}  prevTs=${prevTs}`);

      if (now < prevTs + 30) {
        const waitSec = (prevTs + 30) - now + 1;
        console.log(`  stride floor — waiting ${waitSec}s`);
        await sleep(waitSec * 1000);
        continue;
      }

      const allSlots = await provider.getUtxos(deploy.slotAddress);
      const mySlot = allSlots.find((u) => {
        if (!u.token || u.token.category !== deploy.slotCategory) return false;
        if (u.token.nft?.capability !== 'mutable') return false;
        const sc = decodeSlotCommit(hexToBin(u.token.nft!.commitment));
        return sc !== undefined && binToHex(sc.pkh) === binToHex(myPkh);
      });
      if (!mySlot) {
        console.log(`  could not find my slot`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }
      const mySlotCommit = decodeSlotCommit(hexToBin(mySlot.token!.nft!.commitment))!;

      if (newSeq <= mySlotCommit.cycleSeq) {
        console.log(`  newSeq=${newSeq} <= slot.cycleSeq=${mySlotCommit.cycleSeq}; skip`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      const alreadyAttestedForNewSeq = mySlotCommit.cycleSeq === newSeq;
      if (!alreadyAttestedForNewSeq) {
        const notaryUrl = notaryUrls[cycleCounter % notaryUrls.length]!;
        const notaryIdx = cycleCounter % NOTARY_COUNT;
        let attestation: NotarySignResponse;
        try {
          attestation = await requestNotarySign(notaryUrl, source.id, newSeq, binToHex(myPkh));
        } catch (err) {
          console.log(`  notary failed: ${scrubSecrets(err instanceof Error ? err.message : String(err))}`);
          await sleep(POLL_INTERVAL_MS);
          continue;
        }
        const price = BigInt(attestation.price);
        console.log(`  notary ok: price=${price} ts=${attestation.timestamp}`);

        const cnHash20 = hash160(new TextEncoder().encode(attestation.serverName));
        const digest = publisherSigDigest(source.id, price, attestation.timestamp, myPkh, newSeq, cnHash20);
        const publisherSchnorr = (secp256k1 as Secp256k1).signMessageHashSchnorr(publisher.privateKey, digest);
        if (typeof publisherSchnorr === 'string') throw new Error(`sign: ${publisherSchnorr}`);

        const funderUtxos = (await provider.getUtxos(publisher.address)).filter((u) => !u.token);
        const funderBalance = funderUtxos.reduce((s, u) => s + u.satoshis, 0n);
        if (funderBalance < TX_FEE_BUFFER_ATTEST) {
          console.log(`  insufficient funds ${funderBalance}`);
          await sleep(POLL_INTERVAL_MS);
          continue;
        }

        const targetLocktime = attestation.timestamp;
        const newCommit = encodeSlotCommit(source.id, myPkh, price, attestation.timestamp, newSeq);

        const attestTx = new TransactionBuilder({ provider });
        attestTx.addInput(
          mySlot,
          slotContract.unlock.attest(
            BigInt(notaryIdx),
            binToHex(hexToBin(attestation.notarySig)),
            binToHex(new TextEncoder().encode(attestation.serverName)),
            binToHex(u64LE(price)),
            binToHex(u32LE(attestation.timestamp)),
            binToHex(publisher.publicKey),
            binToHex(publisherSchnorr),
            binToHex(u32LE(newSeq)),
          ),
        );
        for (const u of funderUtxos) attestTx.addInput(u, publisherSig.unlockP2PKH());
        attestTx.addOutput({
          to: slotContract.tokenAddress,
          amount: mySlot.satoshis,
          token: {
            amount: 0n,
            category: deploy.slotCategory,
            nft: { capability: 'mutable', commitment: binToHex(newCommit) },
          },
        });
        const change = funderBalance - TX_FEE_BUFFER_ATTEST;
        if (change >= 546n) attestTx.addOutput({ to: publisher.address, amount: change });
        attestTx.setLocktime(targetLocktime);

        await sleep(Math.floor(Math.random() * 1000));
        let attestTxid: string;
        try {
          const raw = attestTx.build();
          attestTxid = await provider.sendRawTransaction(raw);
        } catch (err) {
          const msg = scrubSecrets(err instanceof Error ? err.message : String(err));
          if (msg.includes('mempool-conflict') || msg.includes('already spent')) {
            console.log(`  attest race lost`);
            await sleep(POLL_INTERVAL_MS);
            continue;
          }
          throw err;
        }
        pubState.lastAttestTxid = attestTxid;
        pubState.lastCycleSeq = newSeq;
        savePublisherState(slot, pubState);
        console.log(`  ✓ attest: ${attestTxid}`);
      }

      console.log(`  waiting for ≥${THR_FLOOR} slots at cycleSeq=${newSeq}…`);
      const waitUntil = Date.now() + SLOT_WAIT_MS;
      let cycleSlots: Utxo[] = [];
      while (Date.now() < waitUntil) {
        await sleep(3_000);
        const allNow = await provider.getUtxos(deploy.slotAddress);
        cycleSlots = allNow.filter((u) => {
          if (!u.token || u.token.category !== deploy.slotCategory) return false;
          if (u.token.nft?.capability !== 'mutable') return false;
          const sc = decodeSlotCommit(hexToBin(u.token.nft!.commitment));
          return sc !== undefined && sc.cycleSeq === newSeq;
        });
        if (cycleSlots.length >= THR_FLOOR) break;
      }
      console.log(`  cycleSlots.length=${cycleSlots.length}`);
      if (cycleSlots.length < THR_FLOOR) {
        if (once) break;
        continue;
      }

      cycleSlots.sort((a, b) => {
        const ca = hexToBin(a.token!.nft!.commitment);
        const cb = hexToBin(b.token!.nft!.commitment);
        for (let i = 22; i >= 3; i -= 1) {
          if (ca[i]! !== cb[i]!) return ca[i]! - cb[i]!;
        }
        return 0;
      });
      const seenPkh = new Set<string>();
      cycleSlots = cycleSlots.filter((u) => {
        const k = binToHex(hexToBin(u.token!.nft!.commitment).slice(3, 23));
        if (seenPkh.has(k)) return false;
        seenPkh.add(k);
        return true;
      });

      const updateFunder = (await provider.getUtxos(publisher.address)).filter((u) => !u.token);
      const updateFunderBal = updateFunder.reduce((s, u) => s + u.satoshis, 0n);
      const minUpdateFunds = BigInt(TICKER_HEAD_COUNT) * TICKER_DUST + TX_FEE_BUFFER_UPDATE;
      if (updateFunderBal < minUpdateFunds) {
        console.log(`  funder too low ${updateFunderBal}`);
        if (once) break;
        continue;
      }

      if (oracleCommitment.length !== ORACLE_COMMIT_LEN) {
        throw new Error(`bad oracle commit length`);
      }
      const prevState: OracleState = decodeOracleCommit(oracleCommitment);

      const tsValues = cycleSlots.map((u) => u32LE_read(hexToBin(u.token!.nft!.commitment), 31)).sort((a, b) => a - b);
      const claimedNewTs = tsValues[Math.floor(tsValues.length / 2)]!;
      if (claimedNewTs <= prevTs || claimedNewTs - prevTs < 30) {
        if (once) break;
        continue;
      }

      const pricesBlobParts = cycleSlots.map((u) => hexToBin(u.token!.nft!.commitment).slice(23, 31));
      const pricesBlob = new Uint8Array(pricesBlobParts.reduce((s, p) => s + p.length, 0));
      let off = 0;
      for (const p of pricesBlobParts) { pricesBlob.set(p, off); off += p.length; }

      const priceValues = cycleSlots.map((u) => {
        const c = hexToBin(u.token!.nft!.commitment);
        return new DataView(c.buffer, c.byteOffset + 23, 8).getBigUint64(0, true);
      }).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const claimedMedian = priceValues[Math.floor((priceValues.length - 1) / 2)]!;

      const decayed = Number((BigInt(prevState.activeCount) * 9n) / 10n);
      let newActive = cycleSlots.length;
      if (decayed > newActive) newActive = decayed;
      if (newActive < 7) newActive = 7;

      const newOracleCommit = encodeOracleCommit({
        seq: newSeq,
        lastTs: claimedNewTs,
        medianUsd: claimedMedian,
        activeCount: newActive,
      });
      const newTickerCommit = encodeTickerCommit({
        seq: newSeq,
        lastTs: claimedNewTs,
        medianUsd: claimedMedian,
      });

      const builder = new TransactionBuilder({ provider });
      const budgetPad = new Uint8Array(1024);
      builder.addInput(
        oracleUtxo,
        oracle.unlock.update(
          binToHex(pricesBlob),
          binToHex(u64LE(claimedMedian)),
          binToHex(u32LE(claimedNewTs)),
          binToHex(budgetPad),
        ),
      );
      for (const s of cycleSlots) builder.addInput(s, slotConsumeUnlocker);
      for (const u of updateFunder) builder.addInput(u, publisherSig.unlockP2PKH());

      builder.addOutput({
        to: oracle.tokenAddress,
        amount: ORACLE_DUST,
        token: {
          amount: 0n,
          category: deploy.oracleCategory,
          nft: { capability: 'minting', commitment: binToHex(newOracleCommit) },
        },
      });
      for (const s of cycleSlots) {
        builder.addOutput({
          to: slotContract.tokenAddress,
          amount: s.satoshis,
          token: {
            amount: 0n,
            category: deploy.slotCategory,
            nft: { capability: 'mutable', commitment: s.token!.nft!.commitment },
          },
        });
      }
      const tickerOutput = {
        to: ticker.tokenAddress,
        amount: TICKER_DUST,
        token: {
          amount: 0n,
          category: deploy.oracleCategory,
          nft: { capability: 'mutable' as const, commitment: binToHex(newTickerCommit) },
        },
      };
      builder.addOutput(tickerOutput);
      builder.addOutput(tickerOutput);
      const funderChange = updateFunderBal - BigInt(TICKER_HEAD_COUNT) * TICKER_DUST - TX_FEE_BUFFER_UPDATE;
      if (funderChange >= 546n) {
        builder.addOutput({ to: publisher.address, amount: funderChange });
      }

      try {
        const raw = builder.build();
        const updateTxid = await provider.sendRawTransaction(raw);
        pubState.lastUpdateTxid = updateTxid;
        savePublisherState(slot, pubState);
        console.log(`  ✓ Oracle.update: ${updateTxid}`);
      } catch (err) {
        const msg = scrubSecrets(err instanceof Error ? err.message : String(err));
        if (msg.includes('txn-mempool-conflict') || msg.includes('already spent') || msg.includes('duplicate')) {
          console.log(`  Oracle.update race lost — OK`);
        } else {
          console.log(`  Oracle.update failed: ${msg}`);
        }
      }
      if (once) break;
    } catch (err) {
      console.error(`  cycle error:`, scrubSecrets(err instanceof Error ? err.message : String(err)));
      if (once) throw err;
      await sleep(POLL_INTERVAL_MS);
    }
  }
};

main().catch((err) => { console.error(scrubSecrets(err instanceof Error ? err.message : String(err))); process.exit(1); });
