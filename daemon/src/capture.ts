// Capture hook — feature-flagged JSON-Lines logging of per-cycle inputs/outputs.
//
// Enables byte-level parity testing of the Rust rebuild (ticker-node-rs) against
// the canonical TS implementation. When `TICKER_CAPTURE_DIR` is unset the hook
// is a no-op; when set, each cycle is written to
// `${TICKER_CAPTURE_DIR}/cycle-${seq}.jsonl` with one record per `recordCycle`
// call.
//
// Record shapes (all keys camelCase, matching the on-the-wire vocabulary of
// publisher.ts):
//
//   { kind: "input",   ...snapshot fields...      cycleSeq: N }
//   { kind: "attest",  raw: hex,    txid?: string, ...inputs }
//   { kind: "update",  raw: hex,    txid?: string, ...inputs }
//
// Captures are write-only; nothing in the daemon reads them back.

import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const CAPTURE_DIR = process.env.TICKER_CAPTURE_DIR;

let dirEnsured = false;
const ensureDir = (): void => {
  if (!CAPTURE_DIR || dirEnsured) return;
  if (!existsSync(CAPTURE_DIR)) mkdirSync(CAPTURE_DIR, { recursive: true });
  dirEnsured = true;
};

export const isCaptureEnabled = (): boolean => Boolean(CAPTURE_DIR);

/**
 * Append one record to the current cycle's JSONL file. Silently no-ops when
 * TICKER_CAPTURE_DIR is unset. The `cycleSeq` is used to choose the per-cycle
 * file path; pass the same value for all records of one cycle.
 */
export const recordCycle = (
  cycleSeq: number,
  kind: 'input' | 'attest' | 'update',
  payload: Record<string, unknown>,
): void => {
  if (!CAPTURE_DIR) return;
  ensureDir();
  const path = join(CAPTURE_DIR, `cycle-${cycleSeq}.jsonl`);
  const line = JSON.stringify({ kind, ts: Math.floor(Date.now() / 1000), ...payload });
  try {
    appendFileSync(path, line + '\n');
  } catch {
    // Capture is best-effort observability — never crash the publisher loop
    // on a write failure. The replay rig will notice the gap.
  }
};
