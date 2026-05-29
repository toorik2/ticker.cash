/**
 * Chain-derived observability snapshot for stats.ticker.cash.
 *
 * Reads three Fulcrum surfaces:
 *   - the Oracle UTXO (current cycle: seq, lastTs, medianUsd, activeCount)
 *   - the 13 slot UTXOs (per-publisher freshness: lastAttestTs, lastCycleSeq,
 *     and the publisher pkh extracted from commit bytes [3..23])
 *   - each publisher's P2PKH wallet UTXOs (current balance for runway calc)
 *
 * No config drift: the 13 publisher pkhs are extracted directly from the
 * live slot commits, so adding/swapping slots doesn't require a config
 * file update. The same fact means if a slot UTXO ever goes missing the
 * reader degrades gracefully (fewer rows in the slots[] array).
 *
 * Snapshot cached for STATS_TTL_MS (default 2 s) to dedupe concurrent
 * viewers, mirroring oracle-state.ts's cache shape.
 *
 * Phase B (operator-stats-poll.ts) attaches `operatorReported` to each
 * slot for opted-in operators; this module always emits `null` for that
 * field — composition happens in server.ts before the JSON is sent.
 */
import {
  encodeCashAddress,
  CashAddressNetworkPrefix,
  CashAddressType,
  binToHex,
  hexToBin,
  decodeTransaction,
} from '@bitauth/libauth';

import { electrumRequest, electrumPing } from './electrum.js';
import { decodeOracleCommitment } from './oracle-state.js';
import { fetchAllOperatorStats } from './operator-stats-poll.js';
import { decodeSlotCommit } from '../../daemon/src/slot-commit.js';
import { SOURCES } from '../../daemon/src/helpers.js';
import contracts from './contracts.json';

// ─── inline script parser — extract notaryIdx from a slot.attest unlock ──
//
// A push-only Bitcoin Cash script (which is what every unlocking script is).
// Walks PUSH opcodes, returns the args. Returns `ok: false` and a partial
// list if it hits a non-push opcode mid-stream.
const parsePushOnlyScript = (script: Uint8Array): { pushes: Uint8Array[]; ok: boolean } => {
  const pushes: Uint8Array[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i]!;
    if (op === 0x00) { pushes.push(new Uint8Array(0)); i += 1; }
    else if (op >= 0x51 && op <= 0x60) { pushes.push(Uint8Array.of(op - 0x50)); i += 1; }
    else if (op >= 0x01 && op <= 0x4b) {
      if (i + 1 + op > script.length) return { pushes, ok: false };
      pushes.push(script.subarray(i + 1, i + 1 + op));
      i += 1 + op;
    } else if (op === 0x4c) {
      if (i + 1 >= script.length) return { pushes, ok: false };
      const len = script[i + 1]!;
      if (i + 2 + len > script.length) return { pushes, ok: false };
      pushes.push(script.subarray(i + 2, i + 2 + len));
      i += 2 + len;
    } else if (op === 0x4d) {
      if (i + 2 >= script.length) return { pushes, ok: false };
      const len = script[i + 1]! | (script[i + 2]! << 8);
      if (i + 3 + len > script.length) return { pushes, ok: false };
      pushes.push(script.subarray(i + 3, i + 3 + len));
      i += 3 + len;
    } else {
      return { pushes, ok: false };
    }
  }
  return { pushes, ok: true };
};

const decodePushAsSmallInt = (b: Uint8Array): number | null => {
  if (b.length === 0) return 0;
  if (b.length > 4) return null;
  let v = 0;
  for (let i = 0; i < b.length; i += 1) v |= b[i]! << (i * 8);
  return v;
};

// Slot.attest unlocking layout (PUSHes, bottom of stack first):
//   notaryIdx, notarySig, serverName, price, timestamp, publisherPubkey,
//   publisherSchnorr, newSeq, funcSelector, redeemScript     = 10 pushes
// Slot.consume unlocking layout: funcSelector, redeemScript  = 2 pushes
const ATTEST_PUSH_COUNT = 10;
const notaryIdxFromSlotInputScript = (script: Uint8Array): number | null => {
  const { pushes, ok } = parsePushOnlyScript(script);
  if (!ok || pushes.length !== ATTEST_PUSH_COUNT) return null;
  const v = decodePushAsSmallInt(pushes[0]!);
  if (v === null || v < 0 || v >= 7) return null;
  return v;
};

// ─── tunables ────────────────────────────────────────────────────────────

const STATS_TTL_MS = Number(process.env.TICKER_STATS_TTL_MS ?? 2000);
const STALENESS_THRESHOLD_SEC = 300;
const DEFAULT_CYCLE_STRIDE_SEC = 60;

// Cost model: each publisher pays the attest fee every cycle; only the
// race-winner pays the Oracle.update fee + ticker dust. Amortize the
// update cost across the publisher count to get the per-publisher
// expected drain per cycle.
const TX_FEE_BUFFER_ATTEST  = 2_000n;
const TX_FEE_BUFFER_UPDATE  = 20_000n;
const TICKER_DUST           = 1_500n;
const TICKER_HEAD_COUNT     = 2n;
const PUBLISHER_COUNT       = 13n;
const EXPECTED_SATS_PER_CYCLE =
  TX_FEE_BUFFER_ATTEST + (TX_FEE_BUFFER_UPDATE + TICKER_HEAD_COUNT * TICKER_DUST) / PUBLISHER_COUNT;
// = 2000 + (20000 + 3000)/13 ≈ 3769 sats/cycle expected drain per publisher.

// ─── Fulcrum query shapes (mirror oracle-state.ts) ───────────────────────

interface ScripthashUtxo {
  tx_hash: string;
  tx_pos: number;
  value: number;          // sats
  height: number;
  token_data?: {
    category: string;
    amount: string;
    nft?: { capability: string; commitment: string };
  };
}

async function getAddressUtxos(address: string): Promise<ScripthashUtxo[]> {
  return electrumRequest<ScripthashUtxo[]>(
    'blockchain.address.listunspent', address, 'include_tokens',
  );
}

// ─── notaryIdx extraction with walk-back through consume → attest ────────
//
// A slot's birthing tx is either:
//   - slot.attest:  input[0] = slot input with `attest(notaryIdx, ...)`,
//                   vout 0 = slot output. Parse input[0] directly.
//   - Oracle.update: input[K] = slot input with `consume()` for slot at
//                   vout K (K >= 1). The notaryIdx for THIS cycle was set
//                   in the *previous* tx — the slot.attest that produced
//                   the slot UTXO consumed at input[K]. We walk back via
//                   that input's outpoint.
//
// Cache keys are `${txid}:${vout}` because the result depends on which
// input we're inspecting. At most one recursion step: in steady state the
// chain is attest → consume → attest → consume → … so any consume() walks
// back exactly one step to land on the previous attest.
const txNotaryCache = new Map<string, number | null>();
const TX_NOTARY_CACHE_CAP = 500;
const TX_NOTARY_MAX_DEPTH = 3;

const fetchNotaryIdxForSlot = async (
  txid: string,
  vout: number,
  depth = 0,
): Promise<number | null> => {
  const key = `${txid}:${vout}`;
  const cached = txNotaryCache.get(key);
  if (cached !== undefined) return cached;
  if (depth >= TX_NOTARY_MAX_DEPTH) return null;
  let result: number | null = null;
  try {
    const hex = await electrumRequest<string>('blockchain.transaction.get', txid);
    const tx = decodeTransaction(hexToBin(hex));
    if (typeof tx !== 'string' && tx.inputs.length > vout) {
      const slotInput = tx.inputs[vout]!;
      const direct = notaryIdxFromSlotInputScript(slotInput.unlockingBytecode);
      if (direct !== null) {
        result = direct;
      } else {
        // Likely a consume() with only 2 PUSHes — walk back one step to the
        // slot.attest that produced the UTXO this consume just consumed.
        const prevTxid = binToHex(slotInput.outpointTransactionHash);
        const prevVout = slotInput.outpointIndex;
        result = await fetchNotaryIdxForSlot(prevTxid, prevVout, depth + 1);
      }
    }
  } catch {
    return null;  // transient fetch errors aren't cached
  }
  txNotaryCache.set(key, result);
  if (txNotaryCache.size > TX_NOTARY_CACHE_CAP) {
    const oldestKey = txNotaryCache.keys().next().value;
    if (oldestKey !== undefined) txNotaryCache.delete(oldestKey);
  }
  return result;
};

// ─── per-cycle history ring buffer ───────────────────────────────────────
// One entry per cycle (deduped on seq). Capped; oldest evicted FIFO.
export interface HistoryEntry {
  seq: number;
  lastTs: number;
  slotsCurrent: number;
  cycleStrideSec: number;
}
const history: HistoryEntry[] = [];
const HISTORY_MAX = 100;
const recordHistory = (entry: HistoryEntry): void => {
  if (history.length > 0 && history[history.length - 1]!.seq === entry.seq) return;
  history.push(entry);
  if (history.length > HISTORY_MAX) history.shift();
};

// ─── exported types (frontend + aggregator consume) ──────────────────────

export type SlotStatus = 'ok' | 'lagging' | 'stalled' | 'unfunded';

export interface OperatorReported {
  uptimeSec: number;
  errorsSinceStart: number;
  lastAttestTxid: string | null;
  lastUpdateTxid: string | null;
  fetchedAt: number;
}

export interface SlotRow {
  slot: number;                          // 0..12 — index in the SOURCES order
  sourceId: number;
  sourceName: string;
  publisherPkh: string;                  // 40 hex
  publisherAddress: string;              // P2PKH chipnet/mainnet
  lastAttestTs: number;                  // unix sec (from slot UTXO commit)
  lastCycleSeq: number;
  cyclesBehind: number;
  walletBalanceSats: string;             // bigint stringified
  cyclesOfRunway: number;
  runwayDurationSec: number;
  status: SlotStatus;
  /** notary index (0..6) that signed this slot's most recent attest;
   *  null when the slot UTXO's birthing tx is an Oracle.update consume
   *  (cycle just closed) or we couldn't parse the script. */
  currentCycleNotaryIdx: number | null;
  operatorReported: OperatorReported | null;
}

export interface Stats {
  fetchedAt: number;
  network: string;
  deployedAt: string;
  cycleStrideSec: number;
  oracle: {
    seq: number;
    lastTs: number;
    medianUsd: number;
    scaledValueLeU64: string;
    activeCount: number;
    ageSec: number;
  } | null;
  health: {
    healthy: boolean;
    fulcrum: { ok: boolean; tipHeight: number | null };
    stalenessThresholdSec: number;
  };
  slots: SlotRow[];
  aggregate: {
    slotsCurrent: number;
    slotsLagging: number;
    slotsStalled: number;
    slotsUnfunded: number;
    quorumOk: boolean;
    medianRunwayCycles: number;
    /** picks per notary (index 0..6) summed across the 13 slots' currentCycleNotaryIdx
     *  values. Slots whose currentCycleNotaryIdx is null contribute nothing. */
    notaryHistogram: number[];
    /** Slots whose birthing tx revealed a notaryIdx — out of 13. */
    slotsWithNotaryIdx: number;
  };
  /** Last N cycles (capped at 100). Frontend uses for sparklines + drift. */
  recent: HistoryEntry[];
  errors: string[];
}

// ─── helpers ─────────────────────────────────────────────────────────────

const networkPrefix = (network: string): CashAddressNetworkPrefix =>
  network === 'mainnet'
    ? CashAddressNetworkPrefix.mainnet
    : CashAddressNetworkPrefix.testnet;

const pkhToP2PKH = (pkh: Uint8Array, network: string): string =>
  encodeCashAddress({
    payload: pkh,
    prefix: networkPrefix(network),
    type: CashAddressType.p2pkh,
  }).address;

const sumNonTokenSats = (utxos: ScripthashUtxo[]): bigint =>
  utxos.filter((u) => !u.token_data).reduce((s, u) => s + BigInt(u.value), 0n);

const classify = (cyclesBehind: number, cyclesOfRunway: number): SlotStatus => {
  // Underfunded operators stop being useful long before their wallet hits
  // zero (the attest tx fee buffer requires ≥ 2000 sats per cycle), so
  // flag at < 5 cycles of runway — even if they're caught up right now.
  if (cyclesOfRunway < 5) return 'unfunded';
  if (cyclesBehind > 3) return 'stalled';
  if (cyclesBehind > 0) return 'lagging';
  return 'ok';
};

const median = (xs: number[]): number => {
  if (xs.length === 0) return 0;
  const sorted = [...xs].sort((a, b) => a - b);
  return sorted[Math.floor((sorted.length - 1) / 2)]!;
};

// ─── snapshot builder ────────────────────────────────────────────────────

const DEPLOYED_AT_SEC = Math.floor(new Date(contracts.deployedAt).getTime() / 1000);

async function buildSnapshot(): Promise<Stats> {
  const errors: string[] = [];
  const fetchedAt = Math.floor(Date.now() / 1000);

  // Run independent queries in parallel; collect errors per-section so a
  // single Fulcrum hiccup never blanks the whole page.
  const [oracleResult, slotResult, pingResult, operatorResult] = await Promise.allSettled([
    getAddressUtxos(contracts.oracle.address),
    getAddressUtxos(contracts.slot.address),
    electrumPing(),
    fetchAllOperatorStats(),
  ]);

  // ─── oracle ─────────────────────────────────────────────────────────
  let oracleState: Stats['oracle'] = null;
  if (oracleResult.status === 'fulfilled') {
    const o = oracleResult.value.find(
      (u) => u.token_data?.category === contracts.oracle.category && u.token_data?.nft?.commitment,
    );
    if (o?.token_data?.nft?.commitment) {
      try {
        const decoded = decodeOracleCommitment(o.token_data.nft.commitment);
        oracleState = {
          seq: decoded.seq,
          lastTs: decoded.lastLocktime,
          medianUsd: decoded.medianUsd,
          scaledValueLeU64: decoded.medianPriceScaled.toString(),
          activeCount: decoded.activeCount,
          ageSec: Math.max(0, fetchedAt - decoded.lastLocktime),
        };
      } catch (e) {
        errors.push(`oracle decode: ${(e as Error).message}`);
      }
    } else {
      errors.push('oracle UTXO not found');
    }
  } else {
    errors.push(`oracle fetch: ${(oracleResult.reason as Error)?.message ?? 'unknown'}`);
  }

  // ─── slots ──────────────────────────────────────────────────────────
  // Decode all 13 commits; pkh is in bytes [3..23] of the commit. tx_hash is
  // the slot UTXO's birthing tx, used downstream to extract notaryIdx.
  interface DecodedSlot {
    sourceId: number; pkh: Uint8Array;
    timestamp: number; cycleSeq: number;
    txHash: string; txVout: number;
  }
  const decodedSlots: DecodedSlot[] = [];
  if (slotResult.status === 'fulfilled') {
    for (const u of slotResult.value) {
      if (u.token_data?.category !== contracts.slot.category) continue;
      if (!u.token_data.nft?.commitment) continue;
      if (u.token_data.nft.capability !== 'mutable') continue;
      const c = decodeSlotCommit(hexToBin(u.token_data.nft.commitment));
      if (c) decodedSlots.push({
        sourceId: c.sourceId, pkh: c.pkh,
        timestamp: c.timestamp, cycleSeq: c.cycleSeq,
        txHash: u.tx_hash, txVout: u.tx_pos,
      });
    }
  } else {
    errors.push(`slots fetch: ${(slotResult.reason as Error)?.message ?? 'unknown'}`);
  }

  // ─── publisher wallet balances + notary-idx parses in parallel ──────
  // Both are per-slot Fulcrum reads; fan-out together.
  const [balanceResults, notaryIdxResults] = await Promise.all([
    Promise.allSettled(decodedSlots.map((s) => getAddressUtxos(pkhToP2PKH(s.pkh, contracts.network)))),
    Promise.allSettled(decodedSlots.map((s) => fetchNotaryIdxForSlot(s.txHash, s.txVout))),
  ]);

  // ─── compose ────────────────────────────────────────────────────────
  // Cycle stride: prefer the measured average; fall back to 60 s.
  let cycleStrideSec = DEFAULT_CYCLE_STRIDE_SEC;
  if (oracleState && oracleState.seq > 0 && oracleState.lastTs > DEPLOYED_AT_SEC) {
    cycleStrideSec = Math.max(30, Math.round((oracleState.lastTs - DEPLOYED_AT_SEC) / oracleState.seq));
  }

  // ─── operator-reported (Phase B, may be empty) ──────────────────────
  const operatorMap = operatorResult.status === 'fulfilled' ? operatorResult.value.map : new Map();
  if (operatorResult.status === 'fulfilled') {
    for (const e of operatorResult.value.errors) errors.push(e);
  } else if (operatorResult.status === 'rejected') {
    errors.push(`operator-poll: ${(operatorResult.reason as Error)?.message ?? 'unknown'}`);
  }

  // Slot index = position in SOURCES (slot 0 = kraken, slot 1 = coinbase, …),
  // derived from the sourceId baked into each commit. Fulcrum returns UTXOs in
  // arbitrary order (and each slot.attest produces a new txid, so that order
  // changes every cycle), so we MUST NOT use the array index as the slot.
  const oracleSeq = oracleState?.seq ?? 0;
  const slotsByIndex = new Map<number, SlotRow>();
  for (let i = 0; i < decodedSlots.length; i += 1) {
    const d = decodedSlots[i]!;
    const slot = SOURCES.findIndex((s) => s.id === d.sourceId);
    if (slot < 0) {
      errors.push(`slot UTXO has unknown sourceId ${d.sourceId}`);
      continue;
    }
    if (slotsByIndex.has(slot)) {
      errors.push(`duplicate slot ${slot} (sourceId ${d.sourceId}) — keeping first`);
      continue;
    }
    const balanceRes = balanceResults[i];
    let walletBalanceSats: bigint;
    if (balanceRes && balanceRes.status === 'fulfilled') {
      walletBalanceSats = sumNonTokenSats(balanceRes.value);
    } else {
      walletBalanceSats = 0n;
      errors.push(`wallet slot ${slot} fetch: ${(balanceRes?.reason as Error)?.message ?? 'unknown'}`);
    }
    const notaryIdxRes = notaryIdxResults[i];
    const currentCycleNotaryIdx =
      notaryIdxRes && notaryIdxRes.status === 'fulfilled' ? notaryIdxRes.value : null;
    const cyclesOfRunway = Number(walletBalanceSats / EXPECTED_SATS_PER_CYCLE);
    const cyclesBehind = Math.max(0, oracleSeq - d.cycleSeq);
    const source = SOURCES[slot]!;
    slotsByIndex.set(slot, {
      slot,
      sourceId: d.sourceId,
      sourceName: source.name,
      publisherPkh: binToHex(d.pkh),
      publisherAddress: pkhToP2PKH(d.pkh, contracts.network),
      lastAttestTs: d.timestamp,
      lastCycleSeq: d.cycleSeq,
      cyclesBehind,
      walletBalanceSats: walletBalanceSats.toString(),
      cyclesOfRunway,
      runwayDurationSec: cyclesOfRunway * cycleStrideSec,
      status: classify(cyclesBehind, cyclesOfRunway),
      currentCycleNotaryIdx,
      operatorReported: operatorMap.get(slot) ?? null,
    });
  }

  // Stable UI order: slot 0 first, slot 12 last.
  const slots: SlotRow[] = Array.from(slotsByIndex.values()).sort((a, b) => a.slot - b.slot);

  // ─── aggregate + health ─────────────────────────────────────────────
  const slotsCurrent  = slots.filter((s) => s.cyclesBehind === 0).length;
  const slotsLagging  = slots.filter((s) => s.cyclesBehind > 0 && s.cyclesBehind <= 3).length;
  const slotsStalled  = slots.filter((s) => s.cyclesBehind > 3).length;
  const slotsUnfunded = slots.filter((s) => s.status === 'unfunded').length;
  const quorumOk = slotsCurrent >= 7;
  const notaryHistogram = [0, 0, 0, 0, 0, 0, 0];
  let slotsWithNotaryIdx = 0;
  for (const s of slots) {
    if (s.currentCycleNotaryIdx !== null && s.currentCycleNotaryIdx >= 0 && s.currentCycleNotaryIdx < 7) {
      notaryHistogram[s.currentCycleNotaryIdx]! += 1;
      slotsWithNotaryIdx += 1;
    }
  }

  const fulcrum =
    pingResult.status === 'fulfilled'
      ? { ok: pingResult.value.tip !== null, tipHeight: pingResult.value.tip }
      : { ok: false, tipHeight: null };
  const healthy =
    fulcrum.ok &&
    oracleState !== null &&
    oracleState.ageSec < STALENESS_THRESHOLD_SEC &&
    quorumOk;

  if (oracleState) {
    recordHistory({
      seq: oracleState.seq,
      lastTs: oracleState.lastTs,
      slotsCurrent,
      cycleStrideSec,
    });
  }

  return {
    fetchedAt,
    network: contracts.network,
    deployedAt: contracts.deployedAt,
    cycleStrideSec,
    oracle: oracleState,
    health: {
      healthy,
      fulcrum,
      stalenessThresholdSec: STALENESS_THRESHOLD_SEC,
    },
    slots,
    recent: history.slice(-50),
    aggregate: {
      slotsCurrent,
      slotsLagging,
      slotsStalled,
      slotsUnfunded,
      quorumOk,
      notaryHistogram,
      slotsWithNotaryIdx,
      medianRunwayCycles: median(slots.map((s) => s.cyclesOfRunway)),
    },
    errors,
  };
}

// ─── public entry — cached snapshot ──────────────────────────────────────

let cached: { snapshot: Stats; at: number } | null = null;
let inFlight: Promise<Stats> | null = null;

export async function getStats(): Promise<Stats> {
  const now = Date.now();
  if (cached && now - cached.at < STATS_TTL_MS) return cached.snapshot;
  if (inFlight) return inFlight;
  inFlight = (async () => {
    try {
      const snapshot = await buildSnapshot();
      cached = { snapshot, at: Date.now() };
      return snapshot;
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}
