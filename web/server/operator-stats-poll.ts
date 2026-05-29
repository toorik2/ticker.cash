/**
 * Phase B — opt-in operator /stats poller.
 *
 * Reads the comma-separated URL list from TICKER_OPERATOR_STATS_URLS (empty
 * default ⇒ pure-chain-derived dashboard, no operator polling). On each
 * stats.ts cache refresh, fans out GET requests to every URL with a 1.5 s
 * per-URL timeout. URLs that fail or time out are logged into errors[] so
 * the dashboard can surface them, but never block the chain-derived view.
 *
 * The ticker-node /stats response shape (per PR8e):
 *   { uptimeSec, fetchedAt, publishers: [{slot, lastAttestTxid, ...}] }
 *
 * One URL can report multiple slots (an operator bundling several slots),
 * so we flatten into a Map<slot, OperatorReported> for stats.ts to look up
 * during composition.
 */

export interface OperatorReported {
  uptimeSec: number;
  errorsSinceStart: number;
  lastAttestTxid: string | null;
  lastUpdateTxid: string | null;
  fetchedAt: number;
}

export type OperatorReportedBySlot = Map<number, OperatorReported>;

interface OperatorStatsResponse {
  uptimeSec: number;
  fetchedAt: number;
  publishers: Array<{
    slot: number;
    lastAttestTxid: string | null;
    lastUpdateTxid: string | null;
    lastCycleSeq: number | null;
    errorsSinceStart: number;
  }>;
}

const URLS: ReadonlyArray<string> = (process.env.TICKER_OPERATOR_STATS_URLS ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const TIMEOUT_MS = Number(process.env.TICKER_OPERATOR_STATS_TIMEOUT_MS ?? 1500);
const PUBLISHER_COUNT = 13;

async function pollOne(url: string): Promise<OperatorStatsResponse | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctl.signal });
    if (!res.ok) return null;
    const data = (await res.json()) as OperatorStatsResponse;
    if (
      typeof data?.uptimeSec !== 'number' ||
      typeof data?.fetchedAt !== 'number' ||
      !Array.isArray(data?.publishers)
    ) {
      return null;  // shape mismatch — drop, don't poison the map
    }
    return data;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Whether any operator URLs are configured (off-by-default helper for tests/UI). */
export const operatorPollingEnabled = (): boolean => URLS.length > 0;

export async function fetchAllOperatorStats(): Promise<{
  map: OperatorReportedBySlot;
  errors: string[];
}> {
  const map: OperatorReportedBySlot = new Map();
  const errors: string[] = [];
  if (URLS.length === 0) return { map, errors };

  const results = await Promise.all(
    URLS.map(async (url) => ({ url, response: await pollOne(url) })),
  );
  for (const { url, response } of results) {
    if (response === null) {
      errors.push(`operator-poll ${url}: failed or timed out`);
      continue;
    }
    for (const p of response.publishers) {
      if (!Number.isInteger(p.slot) || p.slot < 0 || p.slot >= PUBLISHER_COUNT) continue;
      // First-write wins if two URLs claim the same slot — operators should
      // not double-publish a slot, and silently merging hides the conflict.
      if (map.has(p.slot)) continue;
      map.set(p.slot, {
        uptimeSec: response.uptimeSec,
        errorsSinceStart: p.errorsSinceStart,
        lastAttestTxid: p.lastAttestTxid,
        lastUpdateTxid: p.lastUpdateTxid,
        fetchedAt: response.fetchedAt,
      });
    }
  }
  return { map, errors };
}
