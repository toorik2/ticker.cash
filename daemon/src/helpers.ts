// Shared encoding + source registry for the ticker daemons.
//
// All byte layouts here match the on-chain covenants in /contracts.

import {
  binToHex,
  hexToBin,
  hash160,
  sha256,
  type Sha256,
} from '@bitauth/libauth';

const sha256Hash = (data: Uint8Array): Uint8Array => (sha256 as Sha256).hash(data);

// ─── Source registry ──────────────────────────────────────────────────────
//
// sourceId → canonical server name. The TLSNotaryGateway constructor pins
// HASH160(canonicalCN) for each sourceId. Adding a new source requires a
// new Gateway deployment (the source-CN hash blob is baked into bytecode).
//
// 13 endpoints, operator-diverse, USD-anchored:
//   IDs 1..9  → USD-quoted spot markets (4 US, 5 non-US)
//   IDs 10..11 → USDC-quoted
//   IDs 12..13 → USDT-quoted
//
// No two entries share an operator family. No quote-currency dominates.
// A position-checked median across ≥ 7 distinct publishers absorbs up to
// 6 outliers without bias.

export interface SourceConfig {
  readonly id: number;          // u16 — sourceId on-chain
  readonly name: string;        // human label
  readonly canonicalCN: string; // exact server name (DNS) — must match notary's TLS observation
}

export const SOURCES: ReadonlyArray<SourceConfig> = [
  // USD-quoted (real bank-USD spot markets) — 9 sources
  { id: 1,  name: 'kraken',              canonicalCN: 'api.kraken.com' },
  { id: 2,  name: 'coinbase',            canonicalCN: 'api.coinbase.com' },
  { id: 3,  name: 'gemini',              canonicalCN: 'api.gemini.com' },
  { id: 4,  name: 'binance_us',          canonicalCN: 'api.binance.us' },
  { id: 5,  name: 'bitstamp',            canonicalCN: 'www.bitstamp.net' },
  { id: 6,  name: 'cryptocom',           canonicalCN: 'api.crypto.com' },
  { id: 7,  name: 'bitfinex',            canonicalCN: 'api-pub.bitfinex.com' },
  { id: 8,  name: 'exmo',                canonicalCN: 'api.exmo.com' },
  { id: 9,  name: 'independentreserve',  canonicalCN: 'api.independentreserve.com' },
  // USDC-quoted — 2 sources
  { id: 10, name: 'okx_usdc',            canonicalCN: 'www.okx.com' },
  { id: 11, name: 'kucoin_usdc',         canonicalCN: 'api.kucoin.com' },
  // USDT-quoted — 2 sources
  { id: 12, name: 'bybit',               canonicalCN: 'api.bybit.com' },
  { id: 13, name: 'htx',                 canonicalCN: 'api.huobi.pro' },
];
export const SOURCE_COUNT = SOURCES.length;

export const sourceCNHashHex = (sc: SourceConfig): string =>
  binToHex(hash160(new TextEncoder().encode(sc.canonicalCN)));

/**
 * Pack all source CN hashes into a single (N × 20)-byte blob for the
 * TLSNotaryGateway constructor. The Gateway verification does
 * `sourceCNHashes.slice((sid - 1) * 20, sid * 20)`.
 */
export const packedSourceCNHashes = (): string => {
  const parts: string[] = [];
  for (const src of SOURCES) parts.push(sourceCNHashHex(src));
  return parts.join('');
};

// ─── Byte primitives ──────────────────────────────────────────────────────

export const u16LE = (n: number): Uint8Array => {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n, true);
  return out;
};

export const u32LE = (n: number): Uint8Array => {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, true);
  return out;
};

export const u64LE = (n: bigint): Uint8Array => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
};

export const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

// On-chain tokenCategory is stored LITTLE-ENDIAN. Display txids are BIG-ENDIAN.
// CashScript constructor args expect the same byte order as on-chain (LE).
export const reverseHex = (hex: string): string => binToHex(hexToBin(hex).reverse());

// ─── Signature payloads ───────────────────────────────────────────────────

// Notary signs: sha256(serverName || sourceId(2) || price(8) || timestamp(4) || cycleSeq(4))
// cycleSeq binds each notary attestation to exactly one Oracle cycle (no replay
// across cycles within the freshness window).
export const notarySigDigest = (
  serverName: string,
  sourceId: number,
  price: bigint,
  timestamp: number,
  cycleSeq: number,
): Uint8Array => {
  const msg = concatBytes(
    new TextEncoder().encode(serverName),
    u16LE(sourceId),
    u64LE(price),
    u32LE(timestamp),
    u32LE(cycleSeq),
  );
  return sha256Hash(msg);
};

// Publisher signs: sha256(sourceId(2) || price(8) || ts(4) || pkh(20) || cycleSeq(4) || cnHash(20))
export const publisherSigDigest = (
  sourceId: number,
  price: bigint,
  timestamp: number,
  pubkeyHash: Uint8Array,
  cycleSeq: number,
  cnHash20: Uint8Array,
): Uint8Array => {
  if (pubkeyHash.length !== 20) throw new Error('pubkeyHash must be 20 B');
  if (cnHash20.length !== 20) throw new Error('cnHash20 must be 20 B');
  const msg = concatBytes(
    u16LE(sourceId),
    u64LE(price),
    u32LE(timestamp),
    pubkeyHash,
    u32LE(cycleSeq),
    cnHash20,
  );
  return sha256Hash(msg);
};

// ─── Cycle constants ──────────────────────────────────────────────────────

export const ORACLE_DUST = 2000n;
export const TICKER_DUST = 1500n;
export const GATEWAY_DUST = 2000n;
export const VA_DUST = 1500n;

export const VA_EXPIRY_OFFSET = 600;  // VA stays valid for 10 min after mint
export const CYCLE_STRIDE_SEC = 60;
export const THR_FLOOR = 7;            // T_floor — covenant minimum quorum
