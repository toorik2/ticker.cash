/* ticker.cash v25 web client — manifest-driven, on-chain consumption only.
 *
 * The page loads /manifest.json (written by `ticker-node genesis`) and derives everything it
 * needs from it: the head's P2SH-32 address, the Electrum scripthashes of the head lock and the
 * Ticker lock, and the token category. Live head state is read straight from Fulcrum over WSS;
 * notary health comes from /status.json, which the operator daemon refreshes every 10 seconds.
 *
 * Commit layout (head and every Ticker): seq u32 LE (Unix minute) ‖ price u64 LE (1e-8 USD).
 */
(function () {
  'use strict';

  const DEFAULTS = {
    FULCRUM_WSS_POOL: [
      { url: 'wss://chipnet.imaginary.cash:50004', mode: 'subscribe' },
      { url: 'wss://chipnet.bch.ninja:50004', mode: 'poll', pollMs: 12000 },
    ],
    QUORUM: 7,
    ROWS: 13,
    TICKER_SATS: 708,
    RESERVE_CAP_SATS: 5000,
    STALE_SEC: 180,
    STATUS_POLL_MS: 10000,
  };

  // ─── bytes ───────────────────────────────────────────────────────────
  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function sha256(bytes) {
    const h = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(h);
  }
  /** Electrum scripthash: sha256(lockingBytecode), reversed, hex. */
  async function scripthashOf(lockHex) {
    const h = await sha256(hexToBytes(lockHex));
    return bytesToHex(h.reverse());
  }

  // ─── cashaddr (P2PKH + P2SH-32) ──────────────────────────────────────
  const ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  function polymod(values) {
    const GEN = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
    let c = 1n;
    for (const v of values) {
      const c0 = c >> 35n;
      c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(v);
      for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= GEN[i];
    }
    return c ^ 1n;
  }
  function to5bit(bytes) {
    const out = []; let acc = 0, bits = 0;
    for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } }
    if (bits > 0) out.push((acc << (5 - bits)) & 31);
    return out;
  }
  function cashaddr(prefix, versionByte, payload) {
    const data5 = to5bit(new Uint8Array([versionByte, ...payload]));
    const prefix5 = [...prefix].map((c) => c.charCodeAt(0) & 0x1f);
    const poly = polymod([...prefix5, 0, ...data5, 0, 0, 0, 0, 0, 0, 0, 0]);
    const checksum = [];
    for (let i = 7; i >= 0; i--) checksum.push(Number((poly >> BigInt(i * 5)) & 31n));
    return prefix + ':' + [...data5, ...checksum].map((d) => ALPHABET[d]).join('');
  }
  function p2pkhAddress(prefix, pkh20) { return cashaddr(prefix, 0x00, pkh20); }
  function p2sh32Address(prefix, lockHex) { return cashaddr(prefix, 0x0b, hexToBytes(lockHex).slice(2, 34)); }

  // ─── commit codec ────────────────────────────────────────────────────
  /** @returns {{seq:number, minuteStartUnix:number, price:bigint, priceUsd:number}|null} */
  function decodeCommit(hex) {
    if (!hex || hex.length !== 24) return null;
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const seq = dv.getUint32(0, true);
    const price = dv.getBigUint64(4, true);
    return { seq, minuteStartUnix: seq * 60, price, priceUsd: Number(price) / 1e8 };
  }

  // ─── manifest ────────────────────────────────────────────────────────
  async function loadManifest(url = '/manifest.json') {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('manifest.json: HTTP ' + res.status);
    const m = await res.json();
    if (m.version !== 25 || !m.category || !m.oracle_lock || !m.ticker_lock || !Array.isArray(m.table)) throw new Error('manifest.json: not a v25 manifest');
    const prefix = m.network === 'mainnet' ? 'bitcoincash' : 'bchtest';
    return {
      ...m,
      prefix,
      headAddress: p2sh32Address(prefix, m.oracle_lock),
      headScripthash: await scripthashOf(m.oracle_lock),
      tickerScripthash: await scripthashOf(m.ticker_lock),
      explorerAddress: (addr) => `https://bchexplorer.cash/${m.network === 'mainnet' ? '' : 'chipnet/'}address/${addr}`,
      explorerTx: (txid) => `https://bchexplorer.cash/${m.network === 'mainnet' ? '' : 'chipnet/'}tx/${txid}`,
    };
  }

  async function loadStatus(url = '/status.json') {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('status.json: HTTP ' + res.status);
    return res.json();
  }

  /** Pick the head UTXO out of a listunspent result for the head scripthash. */
  function pickHead(utxos, category) {
    let best = null;
    for (const u of utxos) {
      const td = u.token_data;
      if (!td || td.category !== category || !td.nft || td.nft.capability !== 'minting') continue;
      const d = decodeCommit(td.nft.commitment);
      if (!d) continue;
      if (!best || d.seq > best.commit.seq) best = { utxo: u, commit: d, reserveSats: BigInt(u.value) };
    }
    return best;
  }

  // ─── ElectrumWS — pool, subscribe, heartbeat, reconnect ──────────────
  class ElectrumWS {
    constructor(endpoints, opts = {}) {
      this.endpoints = endpoints.map((e) => (typeof e === 'string' ? { url: e, mode: 'subscribe' } : e));
      this.current = 0;
      this.ws = null;
      this.nextId = 1;
      this.pending = new Map();
      this.watches = new Map();
      this.onStatus = opts.onStatus || (() => {});
      this.backoffMs = 1000;
      this.pollTimer = null;
      this.state = 'disconnected';
      this.connect();
    }
    activeEndpoint() { return this.state === 'connected' ? this.endpoints[this.current] : null; }
    currentEndpoint() { return this.endpoints[this.current]; }
    setState(state, extra) { this.state = state; try { this.onStatus({ state, endpoint: this.currentEndpoint(), ...extra }); } catch (_) {} }
    connect() {
      const ep = this.currentEndpoint();
      this.setState('connecting');
      let ws;
      try { ws = new WebSocket(ep.url); } catch (e) { this.scheduleReconnect(); return; }
      const timer = setTimeout(() => { try { ws.close(); } catch (_) {} }, 8000);
      ws.onopen = () => {
        clearTimeout(timer);
        this.ws = ws;
        this.backoffMs = 1000;
        this.setState('connected');
        this.request('server.version', 'ticker-web/25', '1.4').catch(() => {});
        for (const [key, w] of this.watches) this.arm(key, w);
        this.heartbeat();
      };
      ws.onmessage = (ev) => this.onMessage(ev.data);
      ws.onerror = () => {};
      ws.onclose = () => {
        clearTimeout(timer);
        if (this.ws === ws) this.ws = null;
        for (const [, p] of this.pending) { clearTimeout(p.timeoutId); p.reject(new Error('socket closed')); }
        this.pending.clear();
        if (this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; }
        this.setState('disconnected');
        this.current = (this.current + 1) % this.endpoints.length;
        this.scheduleReconnect();
      };
    }
    scheduleReconnect() {
      const delay = this.backoffMs;
      this.backoffMs = Math.min(this.backoffMs * 2, 30000);
      setTimeout(() => this.connect(), delay);
    }
    heartbeat() {
      const ws = this.ws;
      const id = setInterval(() => {
        if (this.ws !== ws) { clearInterval(id); return; }
        this.request('server.ping').catch(() => { try { ws.close(); } catch (_) {} });
      }, 45000);
    }
    onMessage(raw) {
      let msg;
      try { msg = JSON.parse(raw); } catch (_) { return; }
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject, timeoutId } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        clearTimeout(timeoutId);
        if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
        else resolve(msg.result);
        return;
      }
      if (msg.method === 'blockchain.scripthash.subscribe') {
        const [sh] = msg.params;
        const w = this.watches.get(sh);
        if (w) this.refetch(sh, w);
      }
    }
    request(method, ...params) {
      return new Promise((resolve, reject) => {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) { reject(new Error('not connected')); return; }
        const id = this.nextId++;
        const timeoutId = setTimeout(() => { this.pending.delete(id); reject(new Error('timeout: ' + method)); }, 15000);
        this.pending.set(id, { resolve, reject, timeoutId });
        this.ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
      });
    }
    async refetch(sh, w) {
      try {
        const utxos = await this.request('blockchain.scripthash.listunspent', sh, 'include_tokens');
        w.handler(utxos);
      } catch (e) { /* reconnect path retries */ }
    }
    arm(sh, w) {
      const mode = this.currentEndpoint().mode || 'subscribe';
      if (mode === 'subscribe') {
        this.request('blockchain.scripthash.subscribe', sh).then(() => this.refetch(sh, w)).catch(() => this.refetch(sh, w));
      } else {
        this.refetch(sh, w);
        if (!this.pollTimer) this.pollTimer = setInterval(() => { for (const [k, ww] of this.watches) this.refetch(k, ww); }, this.currentEndpoint().pollMs || 12000);
      }
    }
    /** Subscribe to a scripthash; `handler(utxos)` runs on every change and reconnect. */
    watchScripthash(sh, handler) {
      const w = { handler };
      this.watches.set(sh, w);
      if (this.state === 'connected') this.arm(sh, w);
    }
  }

  // ─── cost meter: recent update transactions on the head scripthash ───
  async function measureRecentUpdates(client, headScripthash, sample = 12) {
    const hist = await client.request('blockchain.scripthash.get_history', headScripthash);
    const recent = hist.slice(-sample);
    const sizes = [];
    for (const h of recent) {
      try { const hex = await client.request('blockchain.transaction.get', h.tx_hash); sizes.push(Math.floor(hex.length / 2)); } catch (_) {}
    }
    sizes.sort((a, b) => a - b);
    if (!sizes.length) return null;
    const median = sizes[Math.floor(sizes.length / 2)];
    return { count: hist.length, medianSize: median, feeSats: median + 1, perDaySats: (median + 1) * 1440 };
  }

  window.TickerClient = { DEFAULTS, hexToBytes, bytesToHex, sha256, scripthashOf, p2pkhAddress, p2sh32Address, decodeCommit, loadManifest, loadStatus, pickHead, ElectrumWS, measureRecentUpdates };
})();
