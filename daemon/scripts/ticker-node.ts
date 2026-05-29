#!/usr/bin/env tsx
/**
 * ticker-node — unified single-process entry point.
 *
 * Runs notary + publisher (one of each, or both) IN THIS process. Replaces
 * the previous child-spawning model: one Node, one PID, one log stream,
 * one systemd unit per operator.
 *
 * Credentials are loaded by each role's resolveIdentity helper from the
 * standard .ticker/ paths (notary.key + manifest.json on the new install;
 * seed.hex + deploy-state.json on the legacy layout). All flags below are
 * optional in the new layout — slot is derived from the operator's key.
 *
 * Usage:
 *   ticker-node --notary                          # notary only, slot from key
 *   ticker-node --publisher                       # publisher only, slot from key
 *   ticker-node --notary --publisher              # both roles, one process
 *
 *   ticker-node --notary --publisher --slot 0     # legacy: explicit slot for both
 *   ticker-node --notary --notary-slot 0 \
 *               --publisher --publisher-slot 5    # legacy: different slots per role
 *
 * Optional flags:
 *   --notary-port 8081       (default per slot: 8081 + slot)
 *   --notary-url URL         (publisher: notary endpoints; repeatable;
 *                             default: http://127.0.0.1:8081..8087)
 *   --stats-bind ADDR:PORT   opt-in: mount a tiny /stats HTTP endpoint
 *                             that returns this operator's process-level
 *                             signal (uptime, per-slot lastAttestTxid,
 *                             lastCycleSeq, lastUpdateTxid, error count).
 *                             Off by default. CORS open so the
 *                             stats.ticker.cash aggregator can fetch from
 *                             a browser if desired.
 *
 * Lifecycle: SIGINT / SIGTERM trigger a clean exit. Either role throwing
 * during start-up or runtime takes the process down — systemd handles
 * restart per Restart=on-failure.
 */
import { createServer } from 'node:http';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { runNotary } from './notary.js';
import { runPublisher } from './publisher.js';
import { getCycleErrorCount } from '../src/error-counter.js';

const argv = process.argv.slice(2);

const flagPresent = (name: string): boolean => argv.includes(name);
const flagValue = (...names: string[]): string | undefined => {
  for (const n of names) {
    const i = argv.indexOf(n);
    if (i >= 0 && argv[i + 1] !== undefined) return argv[i + 1];
  }
  return undefined;
};
const flagAll = (name: string): string[] => {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === name && argv[i + 1] !== undefined) out.push(argv[i + 1]!);
  }
  return out;
};

const wantNotary = flagPresent('--notary');
const wantPublisher = flagPresent('--publisher');

if (!wantNotary && !wantPublisher) {
  console.error('ticker-node: must specify --notary and/or --publisher');
  console.error('  examples:');
  console.error('    ticker-node --notary');
  console.error('    ticker-node --publisher');
  console.error('    ticker-node --notary --publisher');
  process.exit(2);
}

// Per-role argv assembly. Both runners parse their own flags; we pass only
// what's relevant to each. --slot is forwarded only when the operator
// supplied an explicit override (the new layout derives it from the key).
const sharedSlot = flagValue('--slot');
const notaryPort = flagValue('--notary-port');
const notaryUrls = flagAll('--notary-url');

const notaryArgv: string[] = [];
const notarySlot = flagValue('--notary-slot') ?? sharedSlot;
if (notarySlot !== undefined) notaryArgv.push('--slot', notarySlot);
if (notaryPort !== undefined) notaryArgv.push('--port', notaryPort);

const publisherArgv: string[] = [];
const publisherSlot = flagValue('--publisher-slot') ?? sharedSlot;
if (publisherSlot !== undefined) publisherArgv.push('--slot', publisherSlot);
for (const u of notaryUrls) publisherArgv.push('--notary-url', u);
if (flagPresent('--once')) publisherArgv.push('--once');

const tasks: Array<{ label: string; promise: Promise<void> }> = [];

if (wantNotary) {
  console.log(`[ticker-node] starting notary: ${notaryArgv.join(' ') || '(no flags)'}`);
  tasks.push({ label: 'notary', promise: runNotary(notaryArgv) });
}
if (wantPublisher) {
  console.log(`[ticker-node] starting publisher: ${publisherArgv.join(' ') || '(no flags)'}`);
  tasks.push({ label: 'publisher', promise: runPublisher(publisherArgv) });
}

// If either role exits (resolves or rejects), bring the whole process down.
// On rejection, log the error; on resolve, log a notice — both are unusual
// (these are meant to be long-running) and warrant systemd noticing.
let shuttingDown = false;
const shutdown = (code: number): void => {
  if (shuttingDown) return;
  shuttingDown = true;
  // Give in-flight HTTP responses + tx broadcasts a brief window, then exit.
  setTimeout(() => process.exit(code), 1500).unref();
};

for (const { label, promise } of tasks) {
  promise
    .then(() => {
      if (shuttingDown) return;
      console.error(`[ticker-node] ${label} resolved unexpectedly; shutting down`);
      shutdown(1);
    })
    .catch((err) => {
      if (shuttingDown) return;
      console.error(`[ticker-node] ${label} failed:`, err instanceof Error ? err.message : String(err));
      shutdown(1);
    });
}

process.on('SIGINT',  () => { console.log('[ticker-node] SIGINT');  shutdown(130); });
process.on('SIGTERM', () => { console.log('[ticker-node] SIGTERM'); shutdown(143); });

// ─── /stats endpoint (opt-in via --stats-bind ADDR:PORT) ─────────────────
//
// Exposes minimal process-level signal so a community aggregator can enrich
// stats.ticker.cash with operator-reported data. Off by default; only mounts
// when --stats-bind is supplied. Returns 200 application/json on /stats,
// 404 elsewhere, with CORS-* response headers.

const STATE_DIR = '.ticker';
const STATE_RE = /^publisher-state-(\d+)\.json$/;

interface PublisherStateOnDisk {
  lastCycleSeq?: number;
  lastAttestTxid?: string;
  lastUpdateTxid?: string;
}
interface PublisherSummary {
  slot: number;
  lastAttestTxid: string | null;
  lastUpdateTxid: string | null;
  lastCycleSeq: number | null;
  errorsSinceStart: number;
}

const readPublisherStates = (): PublisherSummary[] => {
  if (!existsSync(STATE_DIR)) return [];
  const out: PublisherSummary[] = [];
  for (const f of readdirSync(STATE_DIR)) {
    const m = f.match(STATE_RE);
    if (!m) continue;
    const slot = parseInt(m[1]!, 10);
    try {
      const j = JSON.parse(readFileSync(join(STATE_DIR, f), 'utf8')) as PublisherStateOnDisk;
      out.push({
        slot,
        lastAttestTxid: j.lastAttestTxid ?? null,
        lastUpdateTxid: j.lastUpdateTxid ?? null,
        lastCycleSeq: j.lastCycleSeq ?? null,
        errorsSinceStart: getCycleErrorCount(),
      });
    } catch {
      // Skip malformed files silently — the next cycle will rewrite them.
    }
  }
  return out.sort((a, b) => a.slot - b.slot);
};

const statsBind = flagValue('--stats-bind');
const procStartMs = Date.now();
if (statsBind) {
  const m = statsBind.match(/^(.+):(\d+)$/);
  if (!m) {
    console.error('--stats-bind: expected ADDR:PORT, got:', statsBind);
    process.exit(2);
  }
  const host = m[1]!;
  const port = parseInt(m[2]!, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error(`--stats-bind: port must be 1..65535 (got ${port})`);
    process.exit(2);
  }
  const statsServer = createServer((req, res) => {
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-methods', 'GET, OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    if (req.method === 'GET' && req.url === '/stats') {
      try {
        const payload = {
          uptimeSec: Math.floor((Date.now() - procStartMs) / 1000),
          fetchedAt: Math.floor(Date.now() / 1000),
          publishers: readPublisherStates(),
        };
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: msg }));
      }
      return;
    }
    res.writeHead(404); res.end();
  });
  statsServer.on('error', (err) => {
    console.error('[ticker-node] /stats server error:', err.message);
    shutdown(1);
  });
  statsServer.listen(port, host, () => {
    console.log(`[ticker-node] /stats serving on http://${host}:${port}`);
  });
}
