// ticker.cash browser client — shared by /, /stats, and any future pages.
//
// Exports (as window globals):
//   TickerClient.ElectrumWS                — pool-aware, subscribe-aware WS client
//   TickerClient.decodeOracleCommit(hex)   — 18-byte Oracle commit → object (v20)
//   TickerClient.decodeSlotCommit(hex)     — 36-byte Slot commit → object (v19)
//   TickerClient.cashaddrEncodeP2PKH(...)  — pkh20 → bchtest:q…
//   TickerClient.CONSTANTS                  — addresses, categories, sources, fulcrum pool

(function () {
  'use strict';

  // ─── Constants — single source of truth ──────────────────────────────
  const CONSTANTS = {
    // Endpoint pool — ordered by preference. Each entry declares a `mode`:
    //   'subscribe' — the WSS endpoint sends server-initiated push frames
    //                 on blockchain.address.subscribe (the normal case).
    //   'poll'      — the WSS endpoint accepts subscribe but never pushes
    //                 (bch.ninja's :50004 behaves this way — its reverse
    //                 proxy drops server-initiated frames). The client
    //                 falls back to listunspent polling on this endpoint.
    // Polling is a degraded mode reserved for last-resort fallbacks where
    // push is broken; a working `subscribe` endpoint is always preferred.
    FULCRUM_WSS_POOL: [
      { url: 'wss://chipnet.layer1.cash:50004',    mode: 'subscribe' },
      { url: 'wss://chipnet.imaginary.cash:50004', mode: 'subscribe' },
      { url: 'wss://chipnet.bch.ninja:50004',      mode: 'poll', pollMs: 12000 },
    ],
    ORACLE_ADDR: 'bchtest:pdrd4e0tnxr7hfx6nwrylh9h4v5l6r0gwlw780h6fm6pledt88sfjlm4mekcw',
    ORACLE_CATEGORY: '6ec7af2f0853d3cefb48935e169f972450ff830ebef33a3a2572e43dcab4d434',
    // v20: per-source slot addresses (new from re-genesis). Covenant drops
    // length checks + consensus-redundant tokenAmount pins + Oracle 0x65
    // version byte; replaces F-OC7 tier-split with single 21-B BIN2NUM
    // (BCH-2026 BigInt). Oracle commit shrinks 19 → 18 B.
    SLOT_ADDRS: [
      'bchtest:pvzzh5u4ftn92t8d7u2fm8wr6a3l5nklz9xss4e7je5r4rxvkxsgx7chdju8n', // 1 kraken
      'bchtest:pdfhr2jyu22v6gnsnj2nu6nwdwraz0pt5ggy9k92cf6yksx76llkk86ghufer', // 2 coinbase
      'bchtest:pvltturrmyrn7xjtg3wc0ae9j662dg46n2l6a4esvzn4yw0ne4htwwn9jgd64', // 3 gemini
      'bchtest:pdknh9k6fkhgdwht2ux5cq3v66ywwtcsgnujp6rjzenfk3x5wtzqyw74r7nxl', // 4 binance_us
      'bchtest:pv2pcc9a09h4c59yc57r3rdum9mqex380sxzgk0ukyuv0f66l9av2lc2z8qdg', // 5 bitstamp
      'bchtest:pd7ft2fgmtyedt0mckymxksq9g4v7ul2q0crs6qk88ftpmge70nqw3jzjs68f', // 6 cryptocom
      'bchtest:p056vcjlyz70w5wypwjvd5xh5283hpl0tfyxr7www0qrqj5wykht29ursv2hq', // 7 bitfinex
      'bchtest:pvkdqupvgnqevlsnurvpvh9yy6hs8l0ex4xg4t2g7hxh2uv48rwpxqz0kcqk2', // 8 exmo
      'bchtest:pdwq49wjk4f986qx709dgmcqksy35q406rkhpxa9t0heq0ld0jd5j7k696nuz', // 9 independentreserve
      'bchtest:pvevutsygxxkupx4af0uv4jdj3nzwv8d0d4vgscw0ej3ag6jt0zl6rr3wcpr7', // 10 okx_usdc
      'bchtest:pwzjrct7x89jvrf59k5l8akvw8xsjl4q376j25lcjxrtewhvclgtjrlxcw6p8', // 11 kucoin_usdc
      'bchtest:pw5w8uyxja2ut4lt9r0n5kvuucnzhdxfs3w4qqn4a5jvwj97e5gscrpt3uhnw', // 12 bybit
      'bchtest:pddtmvpfgma0satpfysnh9fxeaj5yyg8w2g5fd8q7dm9ru6fa547z4cpc2hsd', // 13 htx
    ],
    SLOT_CATEGORY: '573e119754a82c68ed01968bfd39365238c511c7a44bcabf43b387c8d709ed25',
    // v17: per-source publisher pkhs (in source-id order). Used by stats.html
    // to map a decoded slot commit's pkh to a slot index (since v17 commits
    // no longer carry sourceId).
    PUBLISHER_PKHS: [
      '8ce2d07b5632a5855f5411d3b085c1bcd1c07a17', // 1 kraken
      '333e5c6321f963622336421a64667f298e31c052', // 2 coinbase
      'ef369feaf80c0ea5f65b607922fa2c11193ebb18', // 3 gemini
      'c8c5c285fd133916ccdb53331e68fd051e341727', // 4 binance_us
      'b6393b181ee9bc9fa564ade5ca3de3b2717f15d8', // 5 bitstamp
      '106a3f53111da5cb54976307542e64b1f93f8c68', // 6 cryptocom
      'eac45f0cd5778181c5a4bcb18c1ce458f0b79cbd', // 7 bitfinex
      'f243ebed13ebf300cb5bdb92bf97506b1607d9a0', // 8 exmo
      'c0511a6957eef70e5a6eba11a9ccfa32c878b6f4', // 9 independentreserve
      '89b1e1fe6a5a919be23a6170c84ecfb9e00dd03c', // 10 okx_usdc
      '9cbb6d8c01689148d9a4ce7955fc58441f251623', // 11 kucoin_usdc
      '9070a8927a8d4df33eae5d9a08548639ee377529', // 12 bybit
      '22ad206df10bad67d59ae108910193188b0ae6d5', // 13 htx
    ],
    CASHADDR_PREFIX: 'bchtest',
    STALE_SEC: 300,
    STRIDE_FLOOR_SEC: 60,
    DEPLOYED_AT_SEC: Math.floor(new Date('2026-06-02T12:23:55.000Z').getTime() / 1000),
    EXPECTED_SATS_PER_CYCLE: 2000n + (20000n + 2n * 1500n) / 13n, // ~3769
    SOURCES: [
      { id: 1,  name: 'kraken' },
      { id: 2,  name: 'coinbase' },
      { id: 3,  name: 'gemini' },
      { id: 4,  name: 'binance_us' },
      { id: 5,  name: 'bitstamp' },
      { id: 6,  name: 'cryptocom' },
      { id: 7,  name: 'bitfinex' },
      { id: 8,  name: 'exmo' },
      { id: 9,  name: 'independentreserve' },
      { id: 10, name: 'okx_usdc' },
      { id: 11, name: 'kucoin_usdc' },
      { id: 12, name: 'bybit' },
      { id: 13, name: 'htx' },
    ],
  };

  // ─── Hex + cashaddr ──────────────────────────────────────────────────
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function cashaddrPolymod(values) {
    let c = 1n;
    for (const v of values) {
      const c0 = c >> 35n;
      c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(v);
      if (c0 & 0x01n) c ^= 0x98f2bc8e61n;
      if (c0 & 0x02n) c ^= 0x79b76d99e2n;
      if (c0 & 0x04n) c ^= 0xf33e5fb3c4n;
      if (c0 & 0x08n) c ^= 0xae2eabe2a8n;
      if (c0 & 0x10n) c ^= 0x1e4f43e470n;
    }
    return c ^ 1n;
  }
  function cashaddrTo5Bit(bytes) {
    const result = []; let acc = 0, bits = 0;
    for (const b of bytes) {
      acc = (acc << 8) | b; bits += 8;
      while (bits >= 5) { bits -= 5; result.push((acc >> bits) & 0x1f); }
    }
    if (bits > 0) result.push((acc << (5 - bits)) & 0x1f);
    return result;
  }
  function cashaddrEncodeP2PKH(prefix, pkh20) {
    const payload = new Uint8Array(21);
    payload[0] = 0; payload.set(pkh20, 1);
    const data5 = cashaddrTo5Bit(payload);
    const prefix5 = [...prefix].map(c => c.charCodeAt(0) & 0x1f);
    const polyInput = [...prefix5, 0, ...data5, 0, 0, 0, 0, 0, 0, 0, 0];
    const poly = cashaddrPolymod(polyInput);
    const checksum = [];
    for (let i = 0; i < 8; i++) checksum.push(Number((poly >> BigInt(5 * (7 - i))) & 0x1fn));
    const ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    return prefix + ':' + [...data5, ...checksum].map(v => ALPHABET[v]).join('');
  }

  // ─── Commit decoders ─────────────────────────────────────────────────
  function decodeOracleCommit(hex) {
    // v20: 18-byte commit, no version byte. Layout:
    //   seq(4) + lastTs(4) + median(8) + activeCount(2)
    if (hex.length !== 36) return null; // 18 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const scaled = dv.getBigUint64(8, true);
    return {
      seq: dv.getUint32(0, true),
      lastTs: dv.getUint32(4, true),
      medianPrice: scaled,
      medianUsd: Number(scaled) / 1e8,
      activeCount: dv.getUint16(16, true),
    };
  }
  function decodeSlotCommit(hex) {
    // v19: 36-byte commit. Layout: pkh(20) + price(8) + ts(4) + seq(4).
    // No version byte (v18's 0x75 dropped as redundant). Caller derives
    // sourceId by matching pkh against the manifest's per-source pkh table.
    if (hex.length !== 72) return null; // 36 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return {
      pkh: b.slice(0, 20),
      price: dv.getBigUint64(20, true),
      timestamp: dv.getUint32(28, true),
      cycleSeq: dv.getUint32(32, true),
    };
  }

  // ─── ElectrumWS — pool, subscribe, heartbeat, reconnect ──────────────
  //
  // Design notes (the "doing it right" checklist):
  //   * Endpoint pool: tries URLs in order on connect; on failure, advances
  //     `current` so a permanently-dead endpoint doesn't get retried first.
  //   * Subscriptions: persisted in `this.subscriptions` (address → handler).
  //     On every (re)connect, ALL subscriptions are re-established and the
  //     handler is fired once to let the caller refetch state — because we
  //     don't know what was missed during the disconnect.
  //   * Heartbeat: server.ping every `heartbeatMs` (default 30 s). If the
  //     ping fails or times out (request() has its own 12 s timeout), the
  //     WS is force-closed; the onclose handler triggers reconnect.
  //   * Reconnect: exponential backoff (1 s → 2 → 4 → 8 → 16 → 30 cap),
  //     resets on success. Fires `onStatus({ state, endpoint, err })` so
  //     pages can render connectivity state in the UI.
  //   * Initial render seed: subscribe() returns the current status hash
  //     but NOT the data. Pages call subscribeAndFetch() which issues both
  //     subscribe and listunspent in parallel and renders the listunspent
  //     result. Subsequent renders are notification-driven.
  //
  class ElectrumWS {
    constructor(endpoints, opts = {}) {
      // Accept either ['wss://…', …] or [{url, mode, pollMs?}, …]. Strings
      // default to {mode: 'subscribe'}.
      this.endpoints = endpoints.map(e =>
        typeof e === 'string' ? { url: e, mode: 'subscribe' } : { ...e });
      this.current = 0;
      this.ws = null;
      this.nextId = 1;
      this.pending = new Map();    // id → { resolve, reject, timeoutId }
      // Watches persist across reconnects — each is { params, onChange }.
      this.watches = new Map();    // address → { params, onChange }
      this.pollTimers = new Map(); // address → intervalId (poll-mode only)
      this.heartbeatMs = opts.heartbeatMs ?? 30000;
      this.requestTimeoutMs = opts.requestTimeoutMs ?? 12000;
      this.maxBackoffMs = opts.maxBackoffMs ?? 30000;
      this.heartbeatTimer = null;
      this.reconnectTimer = null;
      this.backoffMs = 1000;
      this.connecting = null;
      this.shouldRun = true;
      this.onStatus = opts.onStatus ?? (() => {});
      this.lastActivityMs = 0;
    }

    currentEndpoint() { return this.endpoints[this.current]; }
    currentMode() { return this.currentEndpoint().mode; }

    // Active connection's host:port (or null if not connected).
    activeEndpoint() {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return null;
      try { return new URL(this.currentEndpoint().url).host; } catch { return null; }
    }

    // Stop the client; flushes pending, disables heartbeat + reconnect + polls.
    close() {
      this.shouldRun = false;
      if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
      if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
      this.stopPolling();
      this.failAll(new Error('client closed'));
      try { this.ws && this.ws.close(); } catch {}
      this.ws = null;
    }

    // Public API — single entry point for watching an address. Internally
    // dispatches to subscribe (push) or poll (pull) based on the current
    // endpoint's mode. On reconnect or endpoint switch, the watch is
    // automatically re-established in whatever mode the new endpoint uses.
    async subscribeAndFetch(address, params, onChange) {
      this.watches.set(address, { params, onChange });
      await this.connect();
      // attachWatch was called from setupWatches() during connect, so by now
      // either a subscribe was issued or a poll timer is running. Do an
      // immediate seed fetch so the caller can render before the first push
      // (or first poll tick) arrives.
      try {
        const utxos = await this.request('blockchain.address.listunspent', address, ...params);
        onChange(utxos);
      } catch (e) { /* connection path retries; ignore */ }
    }

    async connect() {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) return;
      if (this.connecting) return this.connecting;
      this.connecting = (async () => {
        const n = this.endpoints.length;
        let lastErr;
        for (let offset = 0; offset < n; offset++) {
          if (!this.shouldRun) throw new Error('client closed');
          const idx = (this.current + offset) % n;
          const ep = this.endpoints[idx];
          this.onStatus({ state: 'connecting', endpoint: ep.url, mode: ep.mode });
          try {
            await this.dial(ep.url);
            this.current = idx;
            this.backoffMs = 1000;
            this.onStatus({ state: 'connected', endpoint: ep.url, mode: ep.mode });
            this.startHeartbeat();
            await this.setupWatches();
            return;
          } catch (e) { lastErr = e; }
        }
        throw lastErr || new Error('no endpoints');
      })();
      try { await this.connecting; }
      finally { this.connecting = null; }
    }

    dial(url) {
      return new Promise((resolve, reject) => {
        const ws = new WebSocket(url);
        const timer = setTimeout(() => {
          try { ws.close(); } catch {}
          reject(new Error('ws connect timeout: ' + url));
        }, 10000);
        ws.onopen = () => {
          clearTimeout(timer);
          this.ws = ws;
          this.lastActivityMs = Date.now();
          resolve();
        };
        ws.onerror = () => {
          clearTimeout(timer);
          reject(new Error('ws error: ' + url));
        };
        ws.onclose = () => {
          if (this.ws === ws) {
            this.ws = null;
            this.failAll(new Error('ws closed: ' + url));
            this.stopPolling();
            if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
            this.onStatus({ state: 'disconnected', endpoint: url });
            this.scheduleReconnect();
          }
        };
        ws.onmessage = (ev) => this.onMessage(ev.data);
      });
    }

    // Attach watching for every known address according to the current
    // endpoint's mode. Subscribe-mode: fires the handler once with the
    // current status (callers don't strictly need it — seed comes from
    // subscribeAndFetch's listunspent — but it's free signal). Poll-mode:
    // starts a per-address interval that does listunspent + onChange.
    async setupWatches() {
      this.stopPolling(); // belt-and-braces: clear any leftover polls
      const mode = this.currentMode();
      if (mode === 'subscribe') {
        for (const [addr, { params, onChange }] of this.watches) {
          try {
            await this.request('blockchain.address.subscribe', addr);
            // Refetch on reconnect so the caller refreshes whatever was
            // missed during the gap. Cheap; same call we'd do on push.
            this.request('blockchain.address.listunspent', addr, ...params)
              .then(onChange).catch(() => {});
          } catch (e) { /* connection path retries */ }
        }
      } else if (mode === 'poll') {
        const pollMs = this.currentEndpoint().pollMs ?? 12000;
        for (const [addr, { params, onChange }] of this.watches) {
          // Kick off one fetch right away; setInterval handles the rest.
          this.request('blockchain.address.listunspent', addr, ...params)
            .then(onChange).catch(() => {});
          const id = setInterval(() => {
            this.request('blockchain.address.listunspent', addr, ...params)
              .then(onChange).catch(() => {});
          }, pollMs);
          this.pollTimers.set(addr, id);
        }
      }
    }

    stopPolling() {
      for (const id of this.pollTimers.values()) clearInterval(id);
      this.pollTimers.clear();
    }

    startHeartbeat() {
      if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = setInterval(async () => {
        try {
          await this.request('server.ping');
        } catch {
          try { this.ws && this.ws.close(); } catch {}
        }
      }, this.heartbeatMs);
    }

    scheduleReconnect() {
      if (!this.shouldRun) return;
      if (this.reconnectTimer) return;
      // Advance to the next endpoint so a dead primary doesn't keep
      // retrying first — failover semantics.
      this.current = (this.current + 1) % this.endpoints.length;
      const delay = this.backoffMs;
      this.backoffMs = Math.min(this.backoffMs * 2, this.maxBackoffMs);
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        this.connect().catch(() => this.scheduleReconnect());
      }, delay);
    }

    failAll(err) {
      for (const [, { reject, timeoutId }] of this.pending) {
        clearTimeout(timeoutId);
        reject(err);
      }
      this.pending.clear();
    }

    onMessage(data) {
      this.lastActivityMs = Date.now();
      let msg;
      try { msg = JSON.parse(data); } catch { return; }
      // Response to a request
      if (msg.id != null && this.pending.has(msg.id)) {
        const { resolve, reject, timeoutId } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        clearTimeout(timeoutId);
        if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
        else resolve(msg.result);
        return;
      }
      // Server-pushed notification — only consumed on subscribe-mode
      // endpoints. On poll-mode endpoints, the interval drives updates;
      // any stray notification is harmless.
      if (msg.method === 'blockchain.address.subscribe' && Array.isArray(msg.params)) {
        const [addr] = msg.params;
        const watch = this.watches.get(addr);
        if (watch) {
          this.request('blockchain.address.listunspent', addr, ...watch.params)
            .then(watch.onChange).catch(() => {});
        }
      }
    }

    async request(method, ...params) {
      await this.connect();
      const id = this.nextId++;
      return new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => {
          if (this.pending.has(id)) {
            this.pending.delete(id);
            reject(new Error('request timeout: ' + method));
          }
        }, this.requestTimeoutMs);
        this.pending.set(id, { resolve, reject, timeoutId });
        try {
          this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
        } catch (e) {
          this.pending.delete(id);
          clearTimeout(timeoutId);
          reject(e);
        }
      });
    }
  }

  // ─── Export ──────────────────────────────────────────────────────────
  window.TickerClient = {
    ElectrumWS,
    decodeOracleCommit,
    decodeSlotCommit,
    cashaddrEncodeP2PKH,
    hexToBytes,
    bytesToHex,
    CONSTANTS,
  };
})();
