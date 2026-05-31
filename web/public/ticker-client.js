// ticker.cash browser client — shared by /, /stats, and any future pages.
//
// Exports (as window globals):
//   TickerClient.ElectrumWS                — pool-aware, subscribe-aware WS client
//   TickerClient.decodeOracleCommit(hex)   — 19-byte Oracle commit → object
//   TickerClient.decodeSlotCommit(hex)     — 39-byte Slot commit → object
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
    ORACLE_ADDR: 'bchtest:pwzzq4paj82xv7uahmcwapqsvgjzw3sxs3qa0ewvd76naz3vf2yqzk88klyv2',
    ORACLE_CATEGORY: '826e9e629fa06573798c8585276ac496b56c2f8f143faa8f53b88c5d92c56869',
    SLOT_ADDR: 'bchtest:pw0fvs79puvjdk0vwzarly5zfkdtpfs2apngp8syhhwxdsrl8agd2nk6mg6dn',
    SLOT_CATEGORY: 'e31845983a715f33c07324d173a024efa49040173c7f9cf5d347560ace634023',
    CASHADDR_PREFIX: 'bchtest',
    STALE_SEC: 300,
    STRIDE_FLOOR_SEC: 60,
    DEPLOYED_AT_SEC: Math.floor(new Date('2026-05-30T15:05:00.000Z').getTime() / 1000),
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
    if (hex.length !== 38) return null; // 19 B
    const b = hexToBytes(hex);
    if (b[0] !== 0x65) return null; // v15 prefix (was 0x60 in v14)
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const scaled = dv.getBigUint64(9, true);
    return {
      seq: dv.getUint32(1, true),
      lastTs: dv.getUint32(5, true),
      medianPrice: scaled,
      medianUsd: Number(scaled) / 1e8,
      activeCount: dv.getUint16(17, true),
    };
  }
  function decodeSlotCommit(hex) {
    if (hex.length !== 78) return null; // 39 B
    const b = hexToBytes(hex);
    if (b[0] !== 0x75) return null; // v15 prefix (was 0x73 in v14)
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return {
      sourceId: dv.getUint16(1, true),
      pkh: b.slice(3, 23),
      price: dv.getBigUint64(23, true),
      timestamp: dv.getUint32(31, true),
      cycleSeq: dv.getUint32(35, true),
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
