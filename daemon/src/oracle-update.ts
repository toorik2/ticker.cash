// Commit encoders for the v12 Oracle + Ticker NFTs.
//
// The Oracle.update tx is built inline in publisher.ts (v12 spends ≥ 7
// PublisherSlot inputs and re-emits each one at the matching output index,
// so the builder is per-cycle-shape rather than a reusable helper).

import { hexToBin } from '@bitauth/libauth';
import { u16LE, u32LE, u64LE, concatBytes } from './helpers.js';

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
