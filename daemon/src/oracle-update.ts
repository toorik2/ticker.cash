// Oracle.update builder.
//
// Spends:                  the Oracle UTXO + ≥ 7 distinct VerifiedAttestations
//                          + funder UTXO(s).
// Emits at outputs[0]:     Oracle UTXO re-emit (minting capability), new commit.
// Emits at outputs[1..5):  4 Mutable Ticker NFTs carrying the new commit.
// Emits at outputs[5]:     funder change (optional).
//
// The Ticker chain is the consumer-facing read path: each cycle's Tickers
// become chain-descendants of the Oracle.update that produced them, so
// spending a Ticker in a consumer tx is atomically co-final with the
// price update.

import { binToHex, hexToBin } from '@bitauth/libauth';
import type { Contract, ElectrumNetworkProvider, Utxo, SignatureTemplate, Unlocker } from 'cashscript';
import { TransactionBuilder } from 'cashscript';
import { ORACLE_DUST, TICKER_DUST, u16LE, u32LE, u64LE, concatBytes } from './helpers.js';
import { TICKER_HEAD_COUNT } from './load-artifacts.js';

// ── Commit encoders ────────────────────────────────────────────────
export interface OracleState {
  seq: number;
  lastTs: number;
  medianUsd: bigint;
  activeCount: number;
}

export const encodeOracleCommit = (s: OracleState): Uint8Array =>
  concatBytes(
    Uint8Array.from([0x60]),
    u32LE(s.seq),
    u32LE(s.lastTs),
    u64LE(s.medianUsd),
    u16LE(s.activeCount),
  );  // 19 B

export const decodeOracleCommit = (bytes: Uint8Array): OracleState => {
  if (bytes.length !== 19) throw new Error(`Oracle commit must be 19 B, got ${bytes.length}`);
  if (bytes[0] !== 0x60) throw new Error(`Oracle version must be 0x60, got 0x${bytes[0]?.toString(16)}`);
  const dv = new DataView(bytes.buffer, bytes.byteOffset);
  return {
    seq: dv.getUint32(1, true),
    lastTs: dv.getUint32(5, true),
    medianUsd: dv.getBigUint64(9, true),
    activeCount: dv.getUint16(17, true),
  };
};

export const encodeTickerCommit = (s: Pick<OracleState, 'seq' | 'lastTs' | 'medianUsd'>): Uint8Array =>
  concatBytes(
    Uint8Array.from([0x80]),
    u32LE(s.seq),
    u32LE(s.lastTs),
    u64LE(s.medianUsd),
  );  // 17 B

// ── Builder ────────────────────────────────────────────────────────────
export interface OracleUpdateBuildArgs {
  oracle: Contract;
  ticker: Contract;
  oracleUtxo: Utxo;
  vaUtxos: ReadonlyArray<Utxo>;
  vaUnlocker: Unlocker;
  funderUtxos: ReadonlyArray<Utxo>;
  funderSig: SignatureTemplate;
  funderAddress: string;
  prevState: OracleState;
  claimedNewTs: number;
  provider: ElectrumNetworkProvider;
  budgetPadBytes?: number;
}

export interface OracleUpdateBuildResult {
  builder: TransactionBuilder;
  newState: OracleState;
  pricesBlob: Uint8Array;
  claimedMedian: bigint;
  newSeq: number;
}

const TX_FEE_BUFFER = 10_000n;

const extractPrice = (commitmentHex: string): bigint => {
  const bytes = hexToBin(commitmentHex);
  if (bytes.length !== 51) throw new Error(`VA commitment must be 51 B, got ${bytes.length}`);
  return new DataView(bytes.buffer.slice(bytes.byteOffset + 35, bytes.byteOffset + 43)).getBigUint64(0, true);
};

const computeLowerMedian = (prices: ReadonlyArray<bigint>): bigint => {
  const sorted = [...prices].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const k = Math.floor((sorted.length - 1) / 2);
  return sorted[k]!;
};

export const buildOracleUpdate = (args: OracleUpdateBuildArgs): OracleUpdateBuildResult => {
  const {
    oracle, ticker, oracleUtxo, vaUtxos, funderUtxos, funderSig, funderAddress,
    prevState, claimedNewTs, provider, budgetPadBytes = 0,
  } = args;

  const N = vaUtxos.length;
  if (N < 7) throw new Error(`need ≥ 7 VAs; got ${N}`);
  if (N > 100) throw new Error(`max 100 VAs; got ${N}`);

  const prices = vaUtxos.map((u) => {
    if (!u.token?.nft?.commitment) throw new Error(`VA UTXO missing nftCommitment`);
    return extractPrice(u.token.nft.commitment);
  });
  const pricesBlob = concatBytes(...prices.map(u64LE));
  const claimedMedian = computeLowerMedian(prices);

  const newSeq = prevState.seq + 1;
  const decayed = Math.floor(prevState.activeCount * 9 / 10);
  const newActiveCount = Math.max(7, decayed, N);

  const newState: OracleState = {
    seq: newSeq,
    lastTs: claimedNewTs,
    medianUsd: claimedMedian,
    activeCount: newActiveCount,
  };
  const newOracleCommit = encodeOracleCommit(newState);
  const newTickerCommit = encodeTickerCommit(newState);

  const funderBalance = funderUtxos.reduce((s, u) => s + u.satoshis, 0n);
  // Oracle dust + K Ticker dust + fee
  const requiredDust = ORACLE_DUST + BigInt(TICKER_HEAD_COUNT) * TICKER_DUST;
  if (funderBalance < requiredDust + TX_FEE_BUFFER) {
    throw new Error(`funder has ${funderBalance} sats; need ≥ ${requiredDust + TX_FEE_BUFFER}`);
  }

  const builder = new TransactionBuilder({ provider });
  const budgetPad = budgetPadBytes > 0 ? new Uint8Array(budgetPadBytes) : new Uint8Array(0);

  // input[0]: Oracle
  builder.addInput(
    oracleUtxo,
    oracle.unlock.update(
      binToHex(pricesBlob),
      binToHex(u64LE(claimedMedian)),
      binToHex(u32LE(claimedNewTs)),
      binToHex(budgetPad),
    ),
  );

  // input[1..N+1]: VAs (sorted by pkh ascending)
  for (let i = 0; i < vaUtxos.length; i += 1) {
    builder.addInput(vaUtxos[i]!, args.vaUnlocker);
  }

  // input[N+1..]: funder
  for (const u of funderUtxos) {
    builder.addInput(u, funderSig.unlockP2PKH());
  }

  // output[0]: Oracle re-emit (minting capability)
  if (!oracleUtxo.token) throw new Error(`oracleUtxo missing token data`);
  builder.addOutput({
    to: oracle.tokenAddress,
    amount: ORACLE_DUST,
    token: {
      amount: 0n,
      category: oracleUtxo.token.category,
      nft: { capability: 'minting', commitment: binToHex(newOracleCommit) },
    },
  });

  // outputs[1..1+K): K Mutable Ticker heads
  for (let k = 0; k < TICKER_HEAD_COUNT; k += 1) {
    builder.addOutput({
      to: ticker.tokenAddress,
      amount: TICKER_DUST,
      token: {
        amount: 0n,
        category: oracleUtxo.token.category,
        nft: { capability: 'mutable', commitment: binToHex(newTickerCommit) },
      },
    });
  }

  // output[1+K]: funder change (optional)
  const change = funderBalance - requiredDust - TX_FEE_BUFFER;
  if (change >= 546n) {
    builder.addOutput({ to: funderAddress, amount: change });
  }

  builder.setLocktime(0);
  return { builder, newState, pricesBlob, claimedMedian, newSeq };
};

export const recommendClaimedNewTs = (vaUtxos: ReadonlyArray<Utxo>): number => {
  const tss = vaUtxos.map((u) => {
    if (!u.token?.nft?.commitment) throw new Error('VA missing commitment');
    const bytes = hexToBin(u.token.nft.commitment);
    return new DataView(bytes.buffer.slice(bytes.byteOffset + 43, bytes.byteOffset + 47)).getUint32(0, true);
  });
  const sorted = [...tss].sort((a, b) => a - b);
  return sorted[Math.floor((sorted.length - 1) / 2)]!;
};
