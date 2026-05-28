#!/usr/bin/env tsx
/**
 * Notary daemon — HTTP service that:
 *   1. Receives a sign request for (sourceId, cycleSeq, publisherPkh).
 *   2. Fetches the live price from sourceId's canonical CEX endpoint.
 *   3. Signs (server_name || sourceId || price || timestamp || cycleSeq || publisherPkh)
 *      with the notary's Schnorr key.
 *   4. Returns: { sourceId, cycleSeq, price, timestamp, serverName, notarySig, notaryPubkey }.
 *
 * Two credential layouts are accepted at start-up (auto-detected):
 *
 *   New (per-operator install):
 *     .ticker/notary.key       32-byte private key, this operator's slot only
 *     .ticker/manifest.json    public bundle (contracts + 7 notary pubkeys + ...)
 *   Slot derived from pubkey match against manifest.notaryPubkeys.
 *   --slot is ignored on this path.
 *
 *   Legacy (coordinator's seed-derived layout):
 *     .ticker/seed.hex         32-byte master seed; all 20 keys derivable
 *   --slot N selects wallets.notaries[N].
 *
 * --port defaults to 8081 + slot when omitted (loopback only).
 *
 * Endpoints:
 *   POST /sign  { sourceId, cycleSeq, pubkeyHash }
 *     → 200 { sourceId, cycleSeq, price, timestamp, serverName, notarySig, notaryPubkey }
 *     → 4xx { error: ... }
 *   GET /health → 200 { ok: true, slot, address, pubkey, mode }
 */
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { secp256k1, sha256, binToHex, hexToBin, type Sha256, type Secp256k1 } from '@bitauth/libauth';
import { ElectrumNetworkProvider, Network } from 'cashscript';
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';
import { deriveWallets, loadSeed, NOTARY_COUNT } from '../src/keys.js';
import { loadOperatorKey, type Wallet } from '../src/operator-key.js';
import { loadManifest } from '../src/manifest.js';
import { SOURCES, notarySigDigest } from '../src/helpers.js';

// Point at a Fulcrum you control. Public chipnet Fulcrums drop idle
// connections without warning, which the electrum-cash client does not
// retry — running against a self-hosted Fulcrum is strongly recommended.
const ELECTRUM_HOST = process.env.TICKER_ELECTRUM_HOST ?? '127.0.0.1';
const ELECTRUM_PORT = Number(process.env.TICKER_ELECTRUM_PORT ?? 50001);
const ELECTRUM_TLS = (process.env.TICKER_ELECTRUM_TLS ?? 'false') === 'true';
const buildLocalProvider = (): ElectrumNetworkProvider => {
  const socket = new ElectrumTcpSocket(ELECTRUM_HOST, ELECTRUM_PORT, ELECTRUM_TLS, 8000);
  const client = new ElectrumClient('ticker-notary', '1.4.1', socket, {
    sendKeepAliveIntervalInMilliSeconds: 30_000,
    reconnectAfterMilliSeconds: 5000,
  });
  return new ElectrumNetworkProvider(Network.CHIPNET, { electrum: client });
};

const sha256Hash = (data: Uint8Array): Uint8Array => (sha256 as Sha256).hash(data);

// The notary stamps wall-clock time. The Oracle covenant enforces
// `newTs > prevTs` AND `newTs - prevTs >= 30` on the median of these
// stamps (no upper ceiling — the chain self-heals from idle gaps in a
// single catch-up cycle). Chain time (MTP, tx.locktime) is not in the
// trust path anywhere — this lets cycles run at notary cadence (~60 s)
// without being gated by chipnet block production.

type Mode = 'operator-key' | 'seed-derived';
interface Identity {
  readonly slot: number;
  readonly notary: Wallet;
  readonly mode: Mode;
}

const flagValue = (argv: ReadonlyArray<string>, name: string): string | undefined => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};

const resolveIdentity = (argv: ReadonlyArray<string>): Identity => {
  const hasManifest = existsSync('.ticker/manifest.json');
  const hasSeed = existsSync('.ticker/seed.hex');

  // New layout — preferred when manifest is present.
  if (hasManifest) {
    if (!existsSync('.ticker/notary.key')) {
      throw new Error(
        `manifest is present but .ticker/notary.key is not.\n` +
        `if you are running publisher-only, run the publisher binary instead.\n` +
        `if you should be running a notary, re-install or restore notary.key.`,
      );
    }
    const manifest = loadManifest();
    const notary = loadOperatorKey('.ticker/notary.key', 'notary', manifest.network);
    const myPubHex = binToHex(notary.publicKey);
    const slot = manifest.notaryPubkeys.indexOf(myPubHex);
    if (slot < 0) {
      throw new Error(
        `notary.key pubkey ${myPubHex} is not in this manifest's notary list.\n` +
        `wrong installer? wrong manifest? verify with your coordinator.`,
      );
    }
    return { slot, notary, mode: 'operator-key' };
  }

  // Legacy layout — fall back to seed-derived.
  if (hasSeed) {
    const slotFlag = flagValue(argv, '--slot') ?? '0';
    const slot = parseInt(slotFlag, 10);
    if (!Number.isInteger(slot) || slot < 0 || slot >= NOTARY_COUNT) {
      throw new Error(`--slot must be 0..${NOTARY_COUNT - 1}`);
    }
    const seed = loadSeed();
    const wallets = deriveWallets(seed);
    return { slot, notary: wallets.notaries[slot]!, mode: 'seed-derived' };
  }

  throw new Error(
    `no credentials found. expected one of:\n` +
    `  .ticker/notary.key + .ticker/manifest.json   (per-operator install)\n` +
    `  .ticker/seed.hex                              (legacy seed-derived layout)\n`,
  );
};

const resolvePort = (argv: ReadonlyArray<string>, slot: number): number => {
  const override = flagValue(argv, '--port');
  const port = override !== undefined ? parseInt(override, 10) : 8081 + slot;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`--port must be 1..65535 (got ${override ?? port})`);
  }
  return port;
};

interface SourceFetcher {
  url: string;
  extract: (body: string) => number;  // USD float
}

// 13 BCH-USD endpoints, one per publisher slot, operator-diverse.
// Layout matches SOURCES in src/helpers.ts:
//   IDs  1..9  → USD-quoted spot markets (4 US, 5 non-US)
//   IDs 10..11 → USDC-quoted
//   IDs 12..13 → USDT-quoted
// extract() reads the response body and returns a USD float; the notary then
// scales to USD×1e8 for signing.
const num = (s: string | undefined): number => Number(s);

const FETCHERS: Record<number, SourceFetcher> = {
  // ── USD-quoted (bank-USD spot markets) ─────────────────────────────
  1:  { url: 'https://api.kraken.com/0/public/Ticker?pair=BCHUSD',
        extract: (b) => num(b.match(/"BCHUSD":\{[^}]*"c":\["([0-9.]+)"/)?.[1]) },
  2:  { url: 'https://api.coinbase.com/v2/prices/BCH-USD/spot',
        extract: (b) => num(b.match(/"amount":"([0-9.]+)"/)?.[1]) },
  3:  { url: 'https://api.gemini.com/v1/pubticker/bchusd',
        extract: (b) => num(b.match(/"last":"([0-9.]+)"/)?.[1]) },
  4:  { url: 'https://api.binance.us/api/v3/ticker/price?symbol=BCHUSD',
        extract: (b) => num(b.match(/"price":"([0-9.]+)"/)?.[1]) },
  5:  { url: 'https://www.bitstamp.net/api/v2/ticker/bchusd',
        extract: (b) => num(b.match(/"last":"([0-9.]+)"/)?.[1]) },
  6:  { url: 'https://api.crypto.com/v2/public/get-ticker?instrument_name=BCH_USD',
        extract: (b) => num(b.match(/"a":"([0-9.]+)"/)?.[1]) },
  7:  { url: 'https://api-pub.bitfinex.com/v2/tickers?symbols=tBCHN:USD',
        extract: (b) => num(b.match(/,([0-9.]+),[^,]*\]$/)?.[1] ?? b.match(/\[[^,]+,[0-9.]+,[0-9.]+,[0-9.]+,[0-9.]+,[0-9.]+,[0-9.]+,([0-9.]+)/)?.[1]) },
  8:  { url: 'https://api.exmo.com/v1.1/ticker',
        extract: (b) => num(b.match(/"BCH_USD":\{[^}]*"last_trade":"([0-9.]+)"/)?.[1]) },
  9:  { url: 'https://api.independentreserve.com/Public/GetMarketSummary?primaryCurrencyCode=Bch&secondaryCurrencyCode=Usd',
        extract: (b) => num(b.match(/"LastPrice":([0-9.]+)/)?.[1]) },
  // ── USDC-quoted ────────────────────────────────────────────────────
  10: { url: 'https://www.okx.com/api/v5/market/ticker?instId=BCH-USDC',
        extract: (b) => num(b.match(/"last":"([0-9.]+)"/)?.[1]) },
  11: { url: 'https://api.kucoin.com/api/v1/market/orderbook/level1?symbol=BCH-USDC',
        extract: (b) => num(b.match(/"price":"([0-9.]+)"/)?.[1]) },
  // ── USDT-quoted ────────────────────────────────────────────────────
  12: { url: 'https://api.bybit.com/v5/market/tickers?category=spot&symbol=BCHUSDT',
        extract: (b) => num(b.match(/"lastPrice":"([0-9.]+)"/)?.[1]) },
  13: { url: 'https://api.huobi.pro/market/detail?symbol=bchusdt',
        extract: (b) => num(b.match(/"close":([0-9.]+)/)?.[1]) },
};

interface SignBody {
  sourceId: number;
  cycleSeq: number;
  pubkeyHash: string;   // hex (40 chars = 20 B); publisher's HASH160(publisherPubkey)
  fresh?: boolean;
}

interface SignedResult {
  sourceId: number;
  cycleSeq: number;
  price: string;          // u64 as decimal string
  timestamp: number;
  serverName: string;
  notarySig: string;      // hex (DER-encoded ECDSA over the 32B digest)
  notaryPubkey: string;   // hex (33-byte compressed)
}

const fetchAndSign = async (
  sourceId: number,
  cycleSeq: number,
  pubkeyHash20: Uint8Array,
  notaryPriv: Uint8Array,
  notaryPub: Uint8Array,
): Promise<SignedResult> => {
  if (pubkeyHash20.length !== 20) throw new Error('pubkeyHash20 must be 20 B');
  const source = SOURCES.find((s) => s.id === sourceId);
  if (!source) throw new Error(`unknown sourceId ${sourceId}`);
  const fetcher = FETCHERS[sourceId];
  if (!fetcher) throw new Error(`no fetcher for sourceId ${sourceId}`);
  if (!Number.isInteger(cycleSeq) || cycleSeq < 1 || cycleSeq > 0xffffffff) {
    throw new Error(`cycleSeq must be u32 ≥ 1, got ${cycleSeq}`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  let body: string;
  try {
    const res = await fetch(fetcher.url, {
      headers: { 'User-Agent': 'ticker-notary/0.1.0' },
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`fetch ${fetcher.url}: HTTP ${res.status}`);
    body = await res.text();
  } finally {
    clearTimeout(timer);
  }
  const usd = fetcher.extract(body);
  if (!Number.isFinite(usd) || usd <= 0) throw new Error(`${source.name}: extract failed (got ${usd})`);
  const price = BigInt(Math.round(usd * 1e8));
  if (price <= 0n) throw new Error(`parsed price ${price} <= 0`);
  const timestamp = Math.floor(Date.now() / 1000);

  const digest = notarySigDigest(source.canonicalCN, sourceId, price, timestamp, cycleSeq, pubkeyHash20);
  const sigResult = (secp256k1 as Secp256k1).signMessageHashSchnorr(notaryPriv, digest);
  if (typeof sigResult === 'string') throw new Error(`sign: ${sigResult}`);

  return {
    sourceId,
    cycleSeq,
    price: price.toString(),
    timestamp,
    serverName: source.canonicalCN,
    notarySig: binToHex(sigResult),
    notaryPubkey: binToHex(notaryPub),
  };
};

/**
 * Start the notary HTTP server. Returns a Promise that resolves only when
 * the server closes (typically: signal-induced shutdown by the caller, or
 * the unified ticker-node entry point invoking server.close()).
 *
 * `argv` lets the caller override CLI flags when invoking in-process from
 * ticker-node. Direct CLI invocation passes `process.argv.slice(2)`.
 */
export const runNotary = (argv: ReadonlyArray<string>): Promise<void> => {
  const { slot, notary, mode } = resolveIdentity(argv);
  const port = resolvePort(argv, slot);

  console.log(`ticker-notary slot=${slot} mode=${mode}`);
  console.log(`  address=${notary.address}`);
  console.log(`  pubkey=${binToHex(notary.publicKey)}`);
  console.log(`  electrum: ${ELECTRUM_HOST}:${ELECTRUM_PORT}${ELECTRUM_TLS ? ' (tls)' : ''} (fresh per /sign)`);
  console.log(`  serving on http://127.0.0.1:${port}`);

  const server = createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true, slot, address: notary.address, pubkey: binToHex(notary.publicKey), mode,
      }));
      return;
    }
    if (req.method === 'POST' && req.url === '/sign') {
      try {
        const chunks: Buffer[] = [];
        for await (const c of req) chunks.push(c as Buffer);
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as SignBody;
        if (typeof body.pubkeyHash !== 'string' || !/^[0-9a-fA-F]{40}$/.test(body.pubkeyHash)) {
          throw new Error('pubkeyHash must be a 40-char hex string (HASH160 of publisher pubkey)');
        }
        const pubkeyHash20 = hexToBin(body.pubkeyHash);
        const result = await fetchAndSign(body.sourceId, body.cycleSeq, pubkeyHash20, notary.privateKey, notary.publicKey);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: msg }));
      }
      return;
    }
    res.writeHead(404); res.end();
  });
  // Bind to loopback only — publishers are co-located on each host. Defense
  // in depth on top of ufw rules; if ufw is ever disabled the notary doesn't
  // become a public sign-oracle.
  return new Promise<void>((resolve, reject) => {
    server.on('error', reject);
    server.on('close', () => resolve());
    server.listen(port, '127.0.0.1');
  });
};

// Direct CLI invocation: run the notary in this process. Importers (e.g.
// ticker-node.ts in unified single-process mode) should NOT trigger this
// auto-call; they call `runNotary(argv)` themselves with a tailored argv.
const isDirect = import.meta.url === `file://${process.argv[1]}`;
if (isDirect) {
  runNotary(process.argv.slice(2)).catch((err) => {
    console.error('notary:', err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
