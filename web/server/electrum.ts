/**
 * Fulcrum (Electrum-Cash) client. Lazily connects on first call and
 * reuses the same connection across requests within the process.
 *
 * Defaults to the local local-fulcrum Fulcrum at `127.0.0.1:50001`
 * via plain TCP. Both the webapp (operator-host) and the node (local-fulcrum)
 * are private hosts under our control; TCP is fine on the inter-VPS
 * route. When DNS for `node.layer1.cash` is in place we'll switch to
 * WSS:50004 with proper cert validation.
 *
 * Override via env vars:
 *   TICKER_ELECTRUM_HOST       (default: 127.0.0.1)
 *   TICKER_ELECTRUM_PORT       (default: 50001)
 *   TICKER_ELECTRUM_TLS  (default: false; "true" to enable TLS — but for that you
 *                                 also need a host whose cert matches)
 *
 * `request()` in @electrum-cash/network can RESOLVE with an Error object
 * (not throw) — we normalize that to a thrown Error so callers don't have
 * to discriminate.
 */
import { ElectrumClient, ConnectionStatus } from '@electrum-cash/network';
import type { ElectrumClientEvents } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';

const HOST = process.env.TICKER_ELECTRUM_HOST ?? '127.0.0.1';
const PORT = Number(process.env.TICKER_ELECTRUM_PORT ?? 50001);
const ENCRYPTED = (process.env.TICKER_ELECTRUM_TLS ?? 'false') === 'true';
const REQUEST_TIMEOUT_MS = Number(process.env.TICKER_FULCRUM_TIMEOUT_MS ?? 8000);
const HOST_LABEL = `${HOST}:${PORT}${ENCRYPTED ? ' (tls)' : ''}`;

let client: ElectrumClient<ElectrumClientEvents> | null = null;
let connectingPromise: Promise<void> | null = null;

function newClient(): ElectrumClient<ElectrumClientEvents> {
  const socket = new ElectrumTcpSocket(HOST, PORT, ENCRYPTED, REQUEST_TIMEOUT_MS);
  // '1.4.1' is the Electrum protocol version (NOT our app version); Fulcrum
  // 2.x answers server.version with "1.5" and accepts "1.4.1" as a client.
  return new ElectrumClient<ElectrumClientEvents>('ticker-site', '1.4.1', socket, {
    sendKeepAliveIntervalInMilliSeconds: 30_000,
    reconnectAfterMilliSeconds: 5000,
    verifyConnectionTimeoutInMilliSeconds: REQUEST_TIMEOUT_MS,
  });
}

async function ensureConnected(): Promise<ElectrumClient<ElectrumClientEvents>> {
  if (client && client.status === ConnectionStatus.CONNECTED) return client;
  if (connectingPromise) {
    try {
      await connectingPromise;
    } catch {
      // fall through, build a fresh client below
    }
    if (client && client.status === ConnectionStatus.CONNECTED) return client;
  }

  // Drop a stuck client so we don't re-enter connect() on a dirty instance
  // (the lib throws "Cannot initiate a new socket connection when an
  // existing connection exists" otherwise).
  if (client && client.status !== ConnectionStatus.CONNECTED) {
    try {
      await client.disconnect(true, false);
    } catch {
      // best-effort
    }
    client = null;
  }

  client = newClient();
  const c = client;
  connectingPromise = (async () => {
    try {
      await c.connect();
    } catch (e) {
      // The lib rejects with `undefined` on disconnect, with a string on
      // protocol-version mismatch, and with an Error on socket errors.
      // Normalize all three so callers get a useful message.
      const msg =
        e instanceof Error
          ? e.message
          : typeof e === 'string'
            ? e
            : `connect failed for ${HOST_LABEL}`;
      throw new Error(`fulcrum connect: ${msg}`);
    } finally {
      connectingPromise = null;
    }
  })();
  await connectingPromise;
  return c;
}

export async function electrumRequest<T = unknown>(
  method: string,
  ...params: unknown[]
): Promise<T> {
  const c = await ensureConnected();
  const result = (await c.request(method, ...(params as never[]))) as Error | T;
  if (result instanceof Error) {
    throw new Error(`fulcrum ${method}: ${result.message}`);
  }
  return result;
}

let cachedTip: { height: number; at: number } | null = null;
const TIP_CACHE_MS = 5000;

export async function electrumPing(): Promise<{ host: string; tip: number | null }> {
  try {
    if (cachedTip && Date.now() - cachedTip.at < TIP_CACHE_MS) {
      return { host: HOST_LABEL, tip: cachedTip.height };
    }
    const headers = await electrumRequest<{ height: number; hex: string }>(
      'blockchain.headers.subscribe',
    );
    cachedTip = { height: headers.height, at: Date.now() };
    return { host: HOST_LABEL, tip: headers.height };
  } catch {
    return { host: HOST_LABEL, tip: null };
  }
}
