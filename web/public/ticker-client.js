/* ticker.cash v27 web client — manifest-driven, on-chain consumption only.
 *
 * The page loads /manifest.json (written by `ticker-node`) and derives everything it needs from
 * it: the head's P2SH-32 address, the Electrum scripthashes of the head lock and the Ticker lock,
 * the token category, and the hash160 of the notary table (what the head commitment carries).
 * Live head state is read straight from Fulcrum over WSS; notary health comes from /status.json,
 * which the operator daemon refreshes every 10 seconds.
 *
 * Commitments: head = timestamp u32 LE ‖ messageSequence u32 LE ‖ dataSequence u32 LE ‖ price u32 LE (cents) ‖ k u8
 * ‖ tableHash (37 B); Ticker = the first 17 B. The first 16 bytes are a General Protocols price message.
 */
(function () {
  'use strict';

  const DEFAULTS = {
    FULCRUM_WSS_POOL: [
      { url: 'wss://chipnet.imaginary.cash:50004', mode: 'subscribe' },
      { url: 'wss://chipnet.bch.ninja:50004', mode: 'poll', pollMs: 12000 },
    ],
    QUORUM: 7,
    TICKER_SATS: 792,
    TOLL_SATS: 1000,
    TICKER_LIFE_SECS: 86400,
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

  // ─── RIPEMD-160 (WebCrypto has none); hash160 = ripemd160(sha256(x)) ───
  function ripemd160(bytes) {
    const K1 = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    const K2 = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
    const R1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
    const R2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
    const S1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
    const S2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
    const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
    const f = (j, x, y, z) => j < 16 ? (x ^ y ^ z) : j < 32 ? ((x & y) | (~x & z)) : j < 48 ? ((x | ~y) ^ z) : j < 64 ? ((x & z) | (y & ~z)) : (x ^ (y | ~z));
    const len = bytes.length;
    const msg = new Uint8Array((((len + 9) + 63) >> 6) << 6);
    msg.set(bytes);
    msg[len] = 0x80;
    const dv = new DataView(msg.buffer);
    const bitLen = len * 8;
    dv.setUint32(msg.length - 8, bitLen >>> 0, true);
    dv.setUint32(msg.length - 4, Math.floor(bitLen / 0x100000000), true);
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    for (let off = 0; off < msg.length; off += 64) {
      const X = new Array(16);
      for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + 4 * i, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        const round = j >> 4;
        let t = (al + f(j, bl, cl, dl) + X[R1[j]] + K1[round]) >>> 0;
        t = (rotl(t, S1[j]) + el) >>> 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
        t = (ar + f(79 - j, br, cr, dr) + X[R2[j]] + K2[round]) >>> 0;
        t = (rotl(t, S2[j]) + er) >>> 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
      }
      const t = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0; h2 = (h3 + el + ar) >>> 0; h3 = (h4 + al + br) >>> 0; h4 = (h0 + bl + cr) >>> 0; h0 = t;
    }
    const out = new Uint8Array(20);
    const o = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((h, i) => o.setUint32(4 * i, h, true));
    return out;
  }
  async function hash160(bytes) { return ripemd160(await sha256(bytes)); }

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

  // ─── commit codecs ───────────────────────────────────────────────────
  /** The 17-byte snapshot: a GP price message (timestamp, messageSequence, dataSequence, price in cents) plus k.
   *  @returns {{ts:number, minuteStartUnix:number, seq:number, msgSeq:number, price:number, priceUsd:number, k:number, keysToForge:number}|null} */
  function decodeSnapshot(hex) {
    if (!hex || hex.length < 34) return null;
    const b = hexToBytes(hex.slice(0, 34));
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const ts = dv.getUint32(0, true);
    const msgSeq = dv.getUint32(4, true);
    const seq = dv.getUint32(8, true);
    const price = dv.getUint32(12, true);
    const k = b[16];
    return { ts, minuteStartUnix: ts, seq, msgSeq, price, priceUsd: price / 100, k, keysToForge: keysToForge(k) };
  }
  /** Head commitment: snapshot plus the notary table's hash160 (hex). */
  function decodeHeadCommit(hex) {
    if (!hex || hex.length !== 74) return null;
    const s = decodeSnapshot(hex);
    return s ? { ...s, tableHash: hex.slice(34) } : null;
  }
  /** Keys that must collude to write a minute signed by k rows: the lower median's rank plus one. */
  function keysToForge(k) { return k > 0 ? Math.floor((k - 1) / 2) + 1 : 0; }

  // ─── manifest ────────────────────────────────────────────────────────
  async function loadManifest(url = '/manifest.json') {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('manifest.json: HTTP ' + res.status);
    const m = await res.json();
    if (m.version !== 27 || !m.category || !m.oracle_lock || !m.ticker_lock || !m.table_hash || !Array.isArray(m.table)) throw new Error('manifest.json: not a v27 manifest');
    const prefix = m.network === 'mainnet' ? 'bitcoincash' : 'bchtest';
    const tableBytes = new Uint8Array(m.table.length * 34);
    m.table.forEach((r, i) => { tableBytes.set(hexToBytes(r.pubkey), i * 34); tableBytes[i * 34 + 33] = r.source; });
    const tableHash = bytesToHex(await hash160(tableBytes));
    return {
      ...m,
      prefix,
      tableHashComputed: tableHash,
      tableHashOk: tableHash === m.table_hash,
      headAddress: p2sh32Address(prefix, m.oracle_lock),
      headScripthash: await scripthashOf(m.oracle_lock),
      tickerScripthash: await scripthashOf(m.ticker_lock),
      explorerAddress: (addr) => `${m.network === 'mainnet' ? 'https://explorer.salemkode.com' : 'https://chipnet.imaginary.cash'}/address/${addr}`,
      explorerTx: (txid) => `${m.network === 'mainnet' ? 'https://explorer.salemkode.com' : 'https://chipnet.imaginary.cash'}/tx/${txid}`,
    };
  }

  async function loadStatus(url = '/status.json') {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('status.json: HTTP ' + res.status);
    return res.json();
  }

  /** Pick the head UTXO out of a listunspent result for the head scripthash (every v26 oracle
   *  shares the lock, so the category is what selects this deployment). */
  function pickHead(utxos, category) {
    let best = null;
    for (const u of utxos) {
      const td = u.token_data;
      if (!td || td.category !== category || !td.nft || td.nft.capability !== 'minting') continue;
      const d = decodeHeadCommit(td.nft.commitment);
      if (!d) continue;
      if (!best || d.seq > best.commit.seq || (d.seq === best.commit.seq && d.ts > best.commit.ts)) best = { utxo: u, commit: d, reserveSats: BigInt(u.value) };
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
        this.request('server.version', 'ticker-web/27', '1.4').catch(() => {});
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
  // Every v26 oracle shares the head lock, so the history is filtered to transactions that carry
  // this category's minting NFT: a decoded output with capability 'minting' and our category.
  async function measureRecentUpdates(client, headScripthash, category, sample = 12) {
    const hist = await client.request('blockchain.scripthash.get_history', headScripthash);
    const recent = hist.slice(-sample * 2);
    const sizes = [];
    const catLe = bytesToHex(hexToBytes(category).reverse());
    for (const h of recent) {
      try {
        const hex = await client.request('blockchain.transaction.get', h.tx_hash);
        if (!hex.includes('ef' + catLe)) continue;
        sizes.push(Math.floor(hex.length / 2));
      } catch (_) {}
    }
    const mine = sizes.slice(-sample).sort((a, b) => a - b);
    if (!mine.length) return null;
    const median = mine[Math.floor(mine.length / 2)];
    return { count: hist.length, medianSize: median, feeSats: median + 1, perDaySats: (median + 1) * 1440 };
  }

  window.TickerClient = { DEFAULTS, hexToBytes, bytesToHex, sha256, scripthashOf, ripemd160, hash160, p2pkhAddress, p2sh32Address, decodeSnapshot, decodeHeadCommit, keysToForge, loadManifest, loadStatus, pickHead, ElectrumWS, measureRecentUpdates };
})();
