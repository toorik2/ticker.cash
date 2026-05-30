// Protocol byte layouts + source registry — vendored from the (removed) TS
// daemon so the public dashboard at stats.ticker.cash can decode on-chain
// state without depending on daemon/.
//
// The authoritative copy now lives in the Rust crate at
// `ticker-node-rs/crates/ticker-core/src/chain/`. Keep both in sync if the
// protocol ever evolves (current v12 has been stable since genesis).

// ─── PublisherSlot NFT commit (39 B, v0x72) ───────────────────────────────

export const SLOT_COMMIT_LEN = 39;
export const SLOT_VERSION_BYTE = 0x72;

export interface SlotCommit {
  readonly sourceId: number;
  readonly pkh: Uint8Array;        // 20 B
  readonly price: bigint;
  readonly timestamp: number;
  readonly cycleSeq: number;
}

/** Decode a 39-byte slot commit. Returns undefined for the wrong length/version. */
export const decodeSlotCommit = (commit: Uint8Array): SlotCommit | undefined => {
  if (commit.length !== SLOT_COMMIT_LEN || commit[0] !== SLOT_VERSION_BYTE) return undefined;
  const dv = new DataView(commit.buffer, commit.byteOffset);
  return {
    sourceId: dv.getUint16(1, true),
    pkh: commit.slice(3, 23),
    price: dv.getBigUint64(23, true),
    timestamp: dv.getUint32(31, true),
    cycleSeq: dv.getUint32(35, true),
  };
};

// ─── Source registry ──────────────────────────────────────────────────────
//
// 13 endpoints, operator-diverse, USD-anchored. sourceId is committed on chain
// (PublisherSlot constructor takes hash160 of canonicalCN per slot). Reordering
// requires a covenant migration.

export interface SourceConfig {
  readonly id: number;
  readonly name: string;
  readonly canonicalCN: string;
}

export const SOURCES: ReadonlyArray<SourceConfig> = [
  // USD-quoted (9)
  { id: 1,  name: 'kraken',              canonicalCN: 'api.kraken.com' },
  { id: 2,  name: 'coinbase',            canonicalCN: 'api.coinbase.com' },
  { id: 3,  name: 'gemini',              canonicalCN: 'api.gemini.com' },
  { id: 4,  name: 'binance_us',          canonicalCN: 'api.binance.us' },
  { id: 5,  name: 'bitstamp',            canonicalCN: 'www.bitstamp.net' },
  { id: 6,  name: 'cryptocom',           canonicalCN: 'api.crypto.com' },
  { id: 7,  name: 'bitfinex',            canonicalCN: 'api-pub.bitfinex.com' },
  { id: 8,  name: 'exmo',                canonicalCN: 'api.exmo.com' },
  { id: 9,  name: 'independentreserve',  canonicalCN: 'api.independentreserve.com' },
  // USDC-quoted (2)
  { id: 10, name: 'okx_usdc',            canonicalCN: 'www.okx.com' },
  { id: 11, name: 'kucoin_usdc',         canonicalCN: 'api.kucoin.com' },
  // USDT-quoted (2)
  { id: 12, name: 'bybit',               canonicalCN: 'api.bybit.com' },
  { id: 13, name: 'htx',                 canonicalCN: 'api.huobi.pro' },
];
