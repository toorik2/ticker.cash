// PublisherSlot NFT commit encoder/decoder.
//
// The 39-byte slot commit pins one publisher to one source, and carries
// the most recent (price, timestamp, cycleSeq) that publisher's daemon
// pushed via `PublisherSlot.attest()`. Layout:
//
//   byte    field
//   ────    ──────────────────────────────────────
//   0       version (0x72)
//   1..3    sourceId (u16 LE)
//   3..23   publisherPkh (HASH160 of publisher pubkey, 20 B)
//   23..31  price (u64 LE, USD scaled by 1e8)
//   31..35  timestamp (u32 LE, notary-attested unix sec)
//   35..39  cycleSeq (u32 LE, strict-monotonic per publisher)
//
// Both the publisher daemon (slot rewrite per cycle) and the chain-derived
// observability reader (`web/server/stats.ts`) decode this — extracting
// the publisher pkh straight from the commit is how stats.ts derives the
// list of publisher wallets without a separate config field.

import { u16LE, u32LE, u64LE } from './helpers.js';
import { SLOT_COMMIT_LEN } from './load-artifacts.js';

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

/** Encode a slot commit. Throws if `pkh` is not 20 B. */
export const encodeSlotCommit = (
  sourceId: number,
  pkh: Uint8Array,
  price: bigint,
  timestamp: number,
  cycleSeq: number,
): Uint8Array => {
  if (pkh.length !== 20) throw new Error(`pkh ${pkh.length} != 20`);
  const c = new Uint8Array(SLOT_COMMIT_LEN);
  c[0] = SLOT_VERSION_BYTE;
  c.set(u16LE(sourceId), 1);
  c.set(pkh, 3);
  c.set(u64LE(price), 23);
  c.set(u32LE(timestamp), 31);
  c.set(u32LE(cycleSeq), 35);
  return c;
};
