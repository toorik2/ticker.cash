#!/usr/bin/env tsx
/**
 * Publisher daemon — one process per publisher slot.
 *
 * Cycle:
 *   1. Read Oracle state → derive (cycleSeq, target_locktime).
 *   2. Request notary attestation from one of the 7 notaries (round-robin).
 *   3. Build + broadcast TLSNotaryGateway.mint → emits a VerifiedAttestation NFT.
 *   4. Watch the VA UTXO set; once N ≥ THR_FLOOR (7) VAs exist for this cycle:
 *      a. Build Oracle.update with N VAs + Oracle UTXO + funder.
 *      b. Broadcast. If another publisher wins the race, the tx is rejected
 *         with "input already spent" — normal; treat as a successful cycle.
 *
 * No central coordinator. Each publisher acts independently; the chain is state.
 *
 * Usage:
 *   npx tsx scripts/publisher.ts --slot 0 \
 *     --notary-url http://127.0.0.1:8081 \
 *     --notary-url http://127.0.0.1:8082 \
 *     ...
 *
 * Run one publisher per slot in {0..12} (13 publishers per source).
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
import type { Utxo } from 'cashscript';
import {
  Contract,
  ElectrumNetworkProvider,
  Network,
  SignatureTemplate,
  TransactionBuilder,
} from 'cashscript';
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';

// Build an ElectrumNetworkProvider pointed at the local local-fulcrum Fulcrum
// (not the public chipnet default). Matches the notary's setup so all
// publisher/notary chain queries hit the same trust root.
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
  VerifiedAttestationArtifact,
  TickerArtifact,
  TLSNotaryGatewayArtifact,
  ORACLE_COMMIT_LEN,
  TICKER_HEAD_COUNT,
} from '../src/load-artifacts.js';
import { deriveWallets, loadSeed, NOTARY_COUNT, PUBLISHER_COUNT } from '../src/keys.js';
import {
  SOURCES,
  packedSourceCNHashes,
  ORACLE_DUST,
  TICKER_DUST,
  GATEWAY_DUST,
  VA_DUST,
  CYCLE_STRIDE_SEC,
  VA_EXPIRY_OFFSET,
  THR_FLOOR,
  publisherSigDigest,
  u16LE,
  u32LE,
  u64LE,
  reverseHex,
} from '../src/helpers.js';
import {
  buildOracleUpdate,
  decodeOracleCommit,
  recommendClaimedNewTs,
  type OracleState,
} from '../src/oracle-update.js';

const sha256Hash = (data: Uint8Array): Uint8Array => (sha256 as Sha256).hash(data);

/**
 * Remove cashscript debug URIs from error messages before logging.
 *
 * cashscript@0.13.0-next.8's FailedTransactionError appends a base64-encoded
 * libauth WalletTemplate to console.warn — that template contains the
 * private keys used in the failed tx. If we re-emit err.message via
 * console.error (or any logging path), keys land in journalctl which is
 * persistent + group-readable. Strip them defensively.
 *
 * Also strips:
 *   - bitauth IDE URLs (https://ide.bitauth.com/import-template/...)
 *   - inline WARNING preamble cashscript emits
 *   - any 64-hex blob that could be a private key
 */
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
// 2 s polls give snappy mempool-head pickup without thrashing — the cycle
// fires per minute (notary-attested time, no chain-MTP gate).
const POLL_INTERVAL_MS = 2_000;
const VA_WAIT_MS = 25_000;        // after our VA lands, wait up to 25s for others
const TX_FEE_BUFFER_VA = 2_000n;
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
  lastVATxid?: string;
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
  vaAddress: string;
  vaLockingBytecodeHex: string;
  gatewayCategory: string;
  gatewayAddress: string;
  oracleCategory: string;
  oracleAddress: string;
}
const loadDeployState = (): DeployState => {
  if (!existsSync(DEPLOY_STATE_PATH)) {
    throw new Error(`no deploy state at ${DEPLOY_STATE_PATH}; run deploy.ts first`);
  }
  const s = JSON.parse(readFileSync(DEPLOY_STATE_PATH, 'utf8')) as Partial<DeployState>;
  const required = [
    'tickerAddress', 'tickerLockingBytecodeHex',
    'vaAddress', 'vaLockingBytecodeHex',
    'gatewayCategory', 'gatewayAddress',
    'oracleCategory', 'oracleAddress',
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

// ─── Cycle execution ──────────────────────────────────────────────────────

const main = async (): Promise<void> => {
  const { slot, notaryUrls, once } = parseArgs();
  const seed = loadSeed();
  const wallets = deriveWallets(seed);
  const publisher = wallets.publishers[slot]!;
  const publisherSig = new SignatureTemplate(publisher.privateKey);

  const deploy = loadDeployState();
  const provider = buildLocalProvider();
  console.log(`  electrum: ${ELECTRUM_HOST}:${ELECTRUM_PORT}${ELECTRUM_TLS ? ' (tls)' : ''}`);

  // Publisher's assigned source (round-robin across the 3 sources)
  // Slot N → source N+1 (sourceIds are 1-indexed). 30 slots, 30 sources, 1:1.
  if (slot >= SOURCES.length) {
    throw new Error(`slot ${slot} ≥ SOURCES.length ${SOURCES.length}`);
  }
  const source = SOURCES[slot]!;
  console.log(`publisher slot=${slot} addr=${publisher.address} → sourceId=${source.id} (${source.name})`);
  console.log(`  notary urls: ${notaryUrls.join(', ')}`);
  console.log(`  oracle ${deploy.oracleAddress}`);
  console.log(`  gateway ${deploy.gatewayAddress}`);
  console.log(`  va ${deploy.vaAddress}`);

  // Reconstruct contract instances (7-key notary OR-list)
  if (wallets.notaries.length !== 7) {
    throw new Error(`requires 7 notaries, got ${wallets.notaries.length}`);
  }
  const gatewayConstructorArgs = [
    binToHex(wallets.notaries[0]!.publicKey),
    binToHex(wallets.notaries[1]!.publicKey),
    binToHex(wallets.notaries[2]!.publicKey),
    binToHex(wallets.notaries[3]!.publicKey),
    binToHex(wallets.notaries[4]!.publicKey),
    binToHex(wallets.notaries[5]!.publicKey),
    binToHex(wallets.notaries[6]!.publicKey),
    packedSourceCNHashes(),
    deploy.vaLockingBytecodeHex,
    BigInt(VA_EXPIRY_OFFSET),
  ];
  const gateway = new Contract(TLSNotaryGatewayArtifact, gatewayConstructorArgs, { provider });
  const oracle = new Contract(OracleArtifact, [
    deploy.tickerLockingBytecodeHex,
    reverseHex(deploy.gatewayCategory),
  ], { provider });
  const va = new Contract(VerifiedAttestationArtifact, [], { provider });
  const ticker = new Contract(TickerArtifact, [], { provider });
  const vaUnlocker = va.unlock.consume();

  let pubState = loadPublisherState(slot);
  let cycleCounter = 0;

  while (true) {
    cycleCounter += 1;
    console.log(`\n── cycle ${cycleCounter} ──`);
    try {
      // Read Oracle state
      const oracleUtxos = await provider.getUtxos(oracle.tokenAddress);
      const oracleUtxo = oracleUtxos.find(
        (u) => u.token?.category === deploy.oracleCategory && u.token.nft?.capability === 'minting',
      );
      if (!oracleUtxo) {
        console.log(`  no Oracle UTXO found — waiting`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }
      const oracleCommitment = hexToBin(oracleUtxo.token!.nft!.commitment);
      const prevSeq = new DataView(oracleCommitment.buffer.slice(oracleCommitment.byteOffset + 1, oracleCommitment.byteOffset + 5)).getUint32(0, true);
      // bytes[5..9) is lastTs (notary-attested time).
      const prevTs = new DataView(oracleCommitment.buffer.slice(oracleCommitment.byteOffset + 5, oracleCommitment.byteOffset + 9)).getUint32(0, true);
      const cycleSeq = prevSeq + 1;
      const now = Math.floor(Date.now() / 1000);

      // VA mint tx.locktime still goes through the Gateway covenant (unchanged
      // from the Gateway), which checks |notary_ts - tx.locktime| <= 7200. Compute MTP
      // so we can set the VA mint locktime to MTP-1 (always valid).
      const tipHeight = await provider.getBlockHeight();
      const last11: number[] = [];
      for (let h = tipHeight - 10; h <= tipHeight; h += 1) {
        const hdr = (await provider.performRequest('blockchain.block.header', h)) as string;
        last11.push(parseInt(hdr.slice(68 * 2, 68 * 2 + 8).match(/../g)!.reverse().join(''), 16));
      }
      last11.sort((a, b) => a - b);
      const mtp = last11[Math.floor(last11.length / 2)]!;
      // VA mint locktime — passes Gateway's freshness window as long as
      // notary_ts ≈ wall_clock and wall_clock - mtp <= 7200.
      const targetLocktime = mtp - 1;
      console.log(`  prevSeq=${prevSeq} → cycleSeq=${cycleSeq}  prevTs=${prevTs}  vaLocktime=${targetLocktime}  now=${now}  mtp=${mtp}`);

      // Ensure the notary's wall-clock signature will satisfy the covenant's
      // 30s stride floor (claimedNewTs - prevTs >= 30). If we ask notary too
      // soon after prev cycle, ts will be too close and the VA is unusable
      // for that cycle (stuck in mempool until cycle naturally advances).
      const minNotaryTime = prevTs + 30;
      if (now < minNotaryTime) {
        const waitSec = minNotaryTime - now + 1;
        console.log(`  stride floor — waiting ${waitSec}s for wall_clock to reach prevTs+30`);
        await sleep(waitSec * 1000);
        continue;
      }

      // If we already minted a VA for this cycle, skip the notary/mint
      // section but still try Oracle.update with whatever VAs are in mempool.
      // This avoids a deadlock where one failed Oracle.update would lock the
      // cycle until a new prevSeq arrived.
      const alreadyMintedForThisCycle = pubState.lastCycleSeq === cycleSeq;
      if (alreadyMintedForThisCycle) {
        console.log(`  VA for cycleSeq=${cycleSeq} already minted; retrying Oracle.update with mempool VAs`);
      }

      // ── Notary request + VA mint (skip if already minted this cycle) ──
      if (!alreadyMintedForThisCycle) {
      // Request notary signature. We send our own pubkeyHash so the notary
      // can bind the signature to this specific publisher identity (covenant
      // requires this binding to prevent one notary sig from being reused
      // across N self-generated keypairs).
      const pubkeyHash20 = hash160(publisher.publicKey);
      const notaryUrl = notaryUrls[cycleCounter % notaryUrls.length]!;
      const notaryIdx = cycleCounter % NOTARY_COUNT;  // matches the gateway's OR-list order
      console.log(`  asking notary ${notaryUrl} (idx ${notaryIdx}) for sourceId=${source.id}…`);
      let attestation: NotarySignResponse;
      try {
        attestation = await requestNotarySign(notaryUrl, source.id, cycleSeq, binToHex(pubkeyHash20));
      } catch (err) {
        console.log(`  notary failed: ${scrubSecrets(err instanceof Error ? err.message : String(err))}; skipping cycle`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }
      const price = BigInt(attestation.price);
      console.log(`  notary ok: price=${price} ts=${attestation.timestamp} serverName=${attestation.serverName}`);

      // Build publisher's own sig over (sourceId, price, ts, pubkeyHash, cycleSeq, cnHash)
      const cnHash20 = hash160(new TextEncoder().encode(attestation.serverName));
      const digest = publisherSigDigest(source.id, price, attestation.timestamp, pubkeyHash20, cycleSeq, cnHash20);
      const publisherSchnorr = (secp256k1 as Secp256k1).signMessageHashSchnorr(publisher.privateKey, digest);
      if (typeof publisherSchnorr === 'string') throw new Error(`sign: ${publisherSchnorr}`);

      // Build TLSNotaryGateway.mint tx
      const gatewayUtxos = await provider.getUtxos(gateway.tokenAddress);
      const gatewayUtxo = gatewayUtxos.find(
        (u) => u.token?.category === deploy.gatewayCategory && u.token.nft?.capability === 'minting',
      );
      if (!gatewayUtxo) {
        console.log(`  no Gateway minter UTXO found — deploy.gatewayCategory=${deploy.gatewayCategory}; waiting`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }
      const funderUtxos = await provider.getUtxos(publisher.address);
      const nonToken = funderUtxos.filter((u) => !u.token);
      const funderBalance = nonToken.reduce((s, u) => s + u.satoshis, 0n);
      if (funderBalance < VA_DUST + TX_FEE_BUFFER_VA) {
        console.log(`  insufficient funds: ${funderBalance} sats; need ≥ ${VA_DUST + TX_FEE_BUFFER_VA}`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      const mintTx = new TransactionBuilder({ provider });
      mintTx.addInput(
        gatewayUtxo,
        gateway.unlock.mint(
          BigInt(notaryIdx),
          binToHex(hexToBin(attestation.notarySig)),
          binToHex(new TextEncoder().encode(attestation.serverName)),
          binToHex(u16LE(source.id)),
          binToHex(u64LE(price)),
          binToHex(u32LE(attestation.timestamp)),
          binToHex(publisher.publicKey),
          binToHex(pubkeyHash20),
          binToHex(publisherSchnorr),
          binToHex(u32LE(cycleSeq)),
        ),
      );
      for (const u of nonToken) mintTx.addInput(u, publisherSig.unlockP2PKH());

      // Output 0: gateway minter re-emit
      mintTx.addOutput({
        to: gateway.tokenAddress,
        amount: gatewayUtxo.satoshis,
        token: {
          amount: gatewayUtxo.token?.amount ?? 0n,
          category: gatewayUtxo.token!.category,
          nft: { capability: 'minting', commitment: gatewayUtxo.token!.nft!.commitment },
        },
      });
      // Output 1: VA NFT
      const expiryLockBytes = u32LE(targetLocktime + VA_EXPIRY_OFFSET);
      const reserved = new Uint8Array(8);
      const vaCommitment = new Uint8Array(51);
      vaCommitment[0] = 0x70;
      vaCommitment.set(u16LE(source.id), 1);
      vaCommitment.set(pubkeyHash20, 3);
      vaCommitment.set(expiryLockBytes, 23);
      vaCommitment.set(reserved, 27);
      vaCommitment.set(u64LE(price), 35);
      vaCommitment.set(u32LE(attestation.timestamp), 43);
      vaCommitment.set(u32LE(cycleSeq), 47);
      mintTx.addOutput({
        to: va.tokenAddress,
        amount: VA_DUST,
        token: {
          amount: 0n,
          category: deploy.gatewayCategory,                // shares gateway category
          nft: { capability: 'none', commitment: binToHex(vaCommitment) },
        },
      });
      // Output 2: change
      const change = funderBalance - VA_DUST - TX_FEE_BUFFER_VA;
      if (change >= 546n) mintTx.addOutput({ to: publisher.address, amount: change });
      mintTx.setLocktime(targetLocktime);

      console.log(`  broadcasting VA mint tx (locktime=${targetLocktime})…`);
      // Random jitter so 30 publishers don't dogpile the same gateway UTXO
      await sleep(Math.floor(Math.random() * 2000));
      let mintTxid: string;
      let attempt = 0;
      const MAX_ATTEMPTS = 8;
      let txToBroadcast = mintTx;
      while (true) {
        attempt += 1;
        try {
          const mintRaw = txToBroadcast.build();
          mintTxid = await provider.sendRawTransaction(mintRaw);
          break;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          if (attempt >= MAX_ATTEMPTS) throw err;
          if (!msg.includes('mempool-conflict') && !msg.includes('already spent')) throw err;
          console.log(`    mempool conflict on attempt ${attempt}; rebuilding with fresh gateway UTXO`);
          await sleep(500 + Math.floor(Math.random() * 1500));
          const refreshedG = await provider.getUtxos(gateway.tokenAddress);
          const newGUtxo = refreshedG.find((u) => u.token?.category === deploy.gatewayCategory && u.token.nft?.capability === 'minting');
          if (!newGUtxo) throw new Error('no gateway UTXO after retry');
          const refreshedFunder = (await provider.getUtxos(publisher.address)).filter((u) => !u.token);
          const refreshedBal = refreshedFunder.reduce((s, u) => s + u.satoshis, 0n);
          if (refreshedBal < VA_DUST + TX_FEE_BUFFER_VA) throw new Error(`refunded funder too low (${refreshedBal})`);
          const rebuild = new TransactionBuilder({ provider });
          rebuild.addInput(
            newGUtxo,
            gateway.unlock.mint(
              BigInt(notaryIdx),
              binToHex(hexToBin(attestation.notarySig)),
              binToHex(new TextEncoder().encode(attestation.serverName)),
              binToHex(u16LE(source.id)),
              binToHex(u64LE(price)),
              binToHex(u32LE(attestation.timestamp)),
              binToHex(publisher.publicKey),
              binToHex(pubkeyHash20),
              binToHex(publisherSchnorr),
              binToHex(u32LE(cycleSeq)),
            ),
          );
          for (const u of refreshedFunder) rebuild.addInput(u, publisherSig.unlockP2PKH());
          rebuild.addOutput({
            to: gateway.tokenAddress,
            amount: newGUtxo.satoshis,
            token: {
              amount: newGUtxo.token?.amount ?? 0n,
              category: newGUtxo.token!.category,
              nft: { capability: 'minting', commitment: newGUtxo.token!.nft!.commitment },
            },
          });
          rebuild.addOutput({
            to: va.tokenAddress,
            amount: VA_DUST,
            token: { amount: 0n, category: deploy.gatewayCategory, nft: { capability: 'none', commitment: binToHex(vaCommitment) } },
          });
          const refreshedChange = refreshedBal - VA_DUST - TX_FEE_BUFFER_VA;
          if (refreshedChange >= 546n) rebuild.addOutput({ to: publisher.address, amount: refreshedChange });
          rebuild.setLocktime(targetLocktime);
          txToBroadcast = rebuild;
        }
      }
      const mintResult = { txid: mintTxid };
      pubState.lastVATxid = mintResult.txid;
      pubState.lastCycleSeq = cycleSeq;
      savePublisherState(slot, pubState);
      console.log(`  ✓ VA mint: ${mintResult.txid} (attempt ${attempt})`);
      }   // end if (!alreadyMintedForThisCycle)

      // Now wait for others' VAs, then try Oracle.update
      console.log(`  waiting up to ${VA_WAIT_MS / 1000}s for peer VAs…`);
      const waitUntil = Date.now() + VA_WAIT_MS;
      let myVAInputs: Utxo[] = [];
      while (Date.now() < waitUntil) {
        await sleep(3_000);
        const vaUtxos = await provider.getUtxos(va.tokenAddress);
        // Filter to current cycle's VAs (cycleSeq at bytes 47..51)
        myVAInputs = vaUtxos.filter((u) => {
          if (!u.token || u.token.category !== deploy.gatewayCategory) return false;
          const c = u.token.nft?.commitment;
          if (!c || c.length !== 102) return false;
          const bytes = hexToBin(c);
          if (bytes[0] !== 0x70) return false;
          const seqInCommit = new DataView(bytes.buffer.slice(bytes.byteOffset + 47, bytes.byteOffset + 51)).getUint32(0, true);
          if (seqInCommit !== cycleSeq) return false;
          // Drop VAs whose notary timestamp is at or before prevTs — they're
          // stale carryovers (e.g., mempool leftovers from a previous notary
          // generation) and would drag the median below the Oracle's strict-
          // increasing newTs gate. Fresh wall-clock VAs only.
          const tsInCommit = new DataView(bytes.buffer.slice(bytes.byteOffset + 43, bytes.byteOffset + 47)).getUint32(0, true);
          if (tsInCommit <= prevTs) return false;
          return true;
        });
        console.log(`    seen ${myVAInputs.length} VAs for cycleSeq=${cycleSeq}`);
        if (myVAInputs.length >= THR_FLOOR) break;
      }

      if (myVAInputs.length < THR_FLOOR) {
        console.log(`  cycle ${cycleSeq}: insufficient VAs (${myVAInputs.length} < ${THR_FLOOR}); abandoning`);
        if (once) break;
        continue;
      }

      // Oracle covenant enforces strict-ascending pubkeyHash160 across
      // VA inputs (distinctness). Sort by `int(pkh+0x00)`
      // ascending, which equals lexicographic compare of reversed bytes.
      //
      // Also dedupe by pkh — when a publisher re-mints in the same
      // cycle (e.g., after a lost race or rebuild), multiple VAs share one
      // pkh and break strict-ascending. Keep only the first match.
      const seenPkh = new Set<string>();
      myVAInputs = myVAInputs.filter((u) => {
        const c = hexToBin(u.token!.nft!.commitment!);
        const pkhHex = binToHex(c.slice(3, 23));
        if (seenPkh.has(pkhHex)) return false;
        seenPkh.add(pkhHex);
        return true;
      });
      myVAInputs.sort((a, b) => {
        const ca = hexToBin(a.token!.nft!.commitment!);
        const cb = hexToBin(b.token!.nft!.commitment!);
        // pkh at bytes 3..23; reverse to BE for byte-lex == LE-int ordering
        for (let i = 22; i >= 3; i -= 1) {
          if (ca[i]! !== cb[i]!) return ca[i]! - cb[i]!;
        }
        return 0;
      });

      // Try to build Oracle.update — first publisher to broadcast wins
      console.log(`  attempting Oracle.update with N=${myVAInputs.length} VAs (sorted by pkh)`);

      // Pull funder UTXOs fresh post-VA-mint
      const updateFunder = (await provider.getUtxos(publisher.address))
        .filter((u) => !u.token);
      const updateFunderBal = updateFunder.reduce((s, u) => s + u.satoshis, 0n);
      // Oracle dust + K Ticker dusts + fee.
      const minUpdateFunds = ORACLE_DUST + BigInt(TICKER_HEAD_COUNT) * TICKER_DUST + 10_000n;
      if (updateFunderBal < minUpdateFunds) {
        console.log(`  insufficient funder balance for Oracle.update (${updateFunderBal} sats; need ≥ ${minUpdateFunds}); skipping`);
        if (once) break;
        continue;
      }

      // 19-byte commit (no history).
      if (oracleCommitment.length !== ORACLE_COMMIT_LEN) {
        throw new Error(`expected ${ORACLE_COMMIT_LEN}B Oracle commit, got ${oracleCommitment.length}`);
      }
      const prevState: OracleState = decodeOracleCommit(oracleCommitment);

      // claimedNewTs = median of VA notary-attested timestamps.
      // Covenant requires: newTs > prevTs, newTs - prevTs ∈ [30, 7200],
      // and a majority of VAs within ±120s of newTs.
      const claimedNewTs = recommendClaimedNewTs(myVAInputs);
      if (claimedNewTs <= prevTs) {
        console.log(`    skipping: claimedNewTs=${claimedNewTs} <= prevTs=${prevTs} (notaries haven't advanced past prev cycle)`);
        if (once) break;
        continue;
      }
      if (claimedNewTs - prevTs < 30) {
        console.log(`    skipping: stride ${claimedNewTs - prevTs}s < 30s min`);
        if (once) break;
        continue;
      }
      if (claimedNewTs - prevTs > 7200) {
        console.log(`    warning: stride ${claimedNewTs - prevTs}s > 7200s max — covenant will reject`);
        if (once) break;
        continue;
      }
      console.log(`    claimedNewTs=${claimedNewTs} (prev=${prevTs}, +${claimedNewTs - prevTs}s)`);

      try {
        const budgetPadBytes = 1024;
        const { builder, claimedMedian } = buildOracleUpdate({
          oracle,
          ticker,
          oracleUtxo,
          vaUtxos: myVAInputs,
          vaUnlocker,
          funderUtxos: updateFunder,
          funderSig: publisherSig,
          funderAddress: publisher.address,
          prevState,
          claimedNewTs,
          provider,
          budgetPadBytes,
        });
        console.log(`    claimedMedian=${claimedMedian}`);
        // Bypass cashscript's .send() debug-eval bug (tx.locktime triggers it).
        const updateRaw = builder.build();
        const updateTxid = await provider.sendRawTransaction(updateRaw);
        const updateResult = { txid: updateTxid };
        pubState.lastUpdateTxid = updateResult.txid;
        savePublisherState(slot, pubState);
        console.log(`  ✓ Oracle.update broadcast: ${updateResult.txid}`);
      } catch (err) {
        const msg = scrubSecrets(err instanceof Error ? err.message : String(err));
        if (msg.includes('txn-mempool-conflict') || msg.includes('already spent') || msg.includes('duplicate')) {
          console.log(`  Oracle.update race lost (another publisher won) — OK`);
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
