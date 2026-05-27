/**
 * Ticker web server — serves the React SPA + a minimal JSON API.
 *
 * Endpoints:
 *   GET /api/v1/price   — current Oracle snapshot
 *   GET /api/v1/health  — component health + staleness flag
 *   GET /              — static SPA (any non-/api/* path)
 *
 * Designed to replace the previous Astro SSR. The API code is identical
 * to what Astro was serving; just packaged into a 60-line express app.
 */
import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { electrumPing } from './electrum.js';
import { getOracleState } from './oracle-state.js';
import contracts from './contracts.json' with { type: 'json' };

const PORT = Number(process.env.PORT ?? 3001);
const HOST = process.env.HOST ?? '127.0.0.1';
const TTL_MS = Number(process.env.TICKER_SNAPSHOT_TTL_MS ?? 5000);
// v10: sub-minute cadence → 5 min is loose enough to handle brief jitter
// but tight enough to catch real publisher/notary/chain outages.
const STALENESS_THRESHOLD_SEC = 300;

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST_DIR = join(__dirname, '..', 'dist');

// ─── snapshot cache ────────────────────────────────────────────────────

interface Snapshot {
  fetchedAt: number;
  network: string;
  deployedAt: string;
  tipHeight: number | null;
  oracleLive: Awaited<ReturnType<typeof getOracleState>>['decoded'] | null;
  errors: string[];
}

let cached: { snapshot: Snapshot; at: number } | null = null;
let inFlight: Promise<Snapshot> | null = null;

function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e ?? 'unknown');
}

async function build(): Promise<Snapshot> {
  const errors: string[] = [];
  const fetchedAt = Date.now();

  let tipHeight: number | null = null;
  try {
    const ping = await electrumPing();
    tipHeight = ping.tip;
  } catch (e) {
    errors.push(`fulcrum-ping: ${errorMessage(e)}`);
  }

  let oracleLive: Snapshot['oracleLive'] = null;
  try {
    const { decoded } = await getOracleState();
    oracleLive = decoded;
  } catch (e) {
    errors.push(`oracle: ${errorMessage(e)}`);
  }

  return {
    fetchedAt,
    network: 'chipnet',
    deployedAt: contracts.deployedAt,
    tipHeight,
    oracleLive,
    errors,
  };
}

async function getSnapshot(): Promise<Snapshot> {
  const now = Date.now();
  if (cached && now - cached.at < TTL_MS) return cached.snapshot;
  if (inFlight) return inFlight;
  inFlight = build()
    .then((snapshot) => {
      cached = { snapshot, at: Date.now() };
      return snapshot;
    })
    .finally(() => {
      inFlight = null;
    });
  return inFlight;
}

// ─── app ───────────────────────────────────────────────────────────────

const app = express();

app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-methods', 'GET, OPTIONS');
  next();
});

app.get('/api/v1/price', async (_req, res) => {
  try {
    const snap = await getSnapshot();
    const o = snap.oracleLive;
    if (o == null) {
      res.status(503).json({
        medianUsd: null,
        seq: null,
        lastLocktime: null,
        activeCount: null,
        scaledValue: null,
        network: snap.network,
        deployedAt: snap.deployedAt,
        fetchedAt: snap.fetchedAt,
        stub: true,
        errors: snap.errors,
      });
      return;
    }
    res.setHeader('cache-control', 'no-store');
    res.json({
      medianUsd: o.medianUsd,
      scale: 'usd-e8',
      scaledValue: o.medianPriceScaled.toString(),
      lastLocktime: o.lastLocktime,  // v9: notary-attested time (kept field name for API stability)
      seq: o.seq,
      activeCount: o.activeCount,
      // v9: history removed from on-chain commit (was redundant — covenant
      // never read it). Use an off-chain indexer to walk past Oracle.update
      // txs if a rolling history is needed.
      deployedAt: snap.deployedAt,
      fetchedAt: snap.fetchedAt,
      network: snap.network,
      stub: false,
    });
  } catch (e) {
    res.status(500).json({ error: errorMessage(e) });
  }
});

app.get('/api/v1/health', async (_req, res) => {
  try {
    const snap = await getSnapshot();
    const nowSec = Math.floor(Date.now() / 1000);
    const ageSec = snap.oracleLive != null ? nowSec - snap.oracleLive.lastLocktime : null;
    const healthy =
      snap.tipHeight != null &&
      snap.oracleLive != null &&
      ageSec != null &&
      ageSec < STALENESS_THRESHOLD_SEC;
    res.setHeader('cache-control', 'no-store');
    res.json({
      healthy,
      stalenessThresholdSec: STALENESS_THRESHOLD_SEC,
      node: { ok: snap.tipHeight != null, blockHeight: snap.tipHeight },
      fulcrum: { ok: snap.tipHeight != null, tipHeight: snap.tipHeight },
      lastCycle: {
        seq: snap.oracleLive?.seq ?? null,
        locktime: snap.oracleLive?.lastLocktime ?? null,
        ageSec,
        activeCount: snap.oracleLive?.activeCount ?? null,
      },
      network: snap.network,
      deployedAt: snap.deployedAt,
      fetchedAt: snap.fetchedAt,
      stub: snap.oracleLive == null,
      errors: snap.errors,
    });
  } catch (e) {
    res.status(500).json({ error: errorMessage(e) });
  }
});

// ─── static SPA ────────────────────────────────────────────────────────

app.use(express.static(DIST_DIR, {
  index: 'index.html',
  // extensions: ['html'] lets /docs serve dist/docs.html without the URL
  // suffix. Same revalidation policy applies to all .html pages.
  extensions: ['html'],
  maxAge: '1h',
  setHeaders(res, path) {
    if (path.endsWith('.html')) {
      res.setHeader('cache-control', 'no-store');
    }
  },
}));

// SPA fallback — any non-/api GET serves index.html
app.get(/^(?!\/api\/).*/, (_req, res) => {
  res.setHeader('cache-control', 'no-store');
  res.sendFile(join(DIST_DIR, 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`ticker-web listening on http://${HOST}:${PORT}`);
});
