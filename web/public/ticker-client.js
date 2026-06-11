// ticker.cash browser client — shared by /, /stats, and any future pages.
//
// Exports (as window globals):
//   TickerClient.ElectrumWS                — pool-aware, subscribe-aware WS client
//   TickerClient.decodeOracleCommit(hex)   — 18-byte Oracle commit → object (v24)
//   TickerClient.decodeSlotCommit(hex)     — 18-byte Slot commit → object (v24)
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
    ORACLE_ADDR: 'bchtest:pvgts6s4qkmpjsalyqmc02dqu7zce0kfszkct2cssewhj0hvgtlrqhfqpj7q0',
    ORACLE_CATEGORY: '9c18d35925fd5a4a9af274b2a0555a83efec7488006fdf8db3a20ee6d3ec54ab',
    // v22/v23: P2S slot addresses (CHIP-2024-12). Each slot's LB IS its compiled
    // body (per-source specialized with pkh + cnHash + oracleCatHash inlined
    // as script literals). Fulcrum 2.x doesn't decode P2S cashaddrs yet, so
    // the dashboard subscribes by SCRIPTHASH (see SLOT_SCRIPTHASHES below).
    // SLOT_ADDRS kept for display + cashaddr generation.
    SLOT_ADDRS: [
      'bchtest:zpmqp8rrcpmv79yvutg8k43j5kz474q36wcgtsdu68q8596k0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu99lu2f35sdqvdypf6w3upf95ykpwyhnu0r72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsaje9sr4x', // 1 kraken
      'bchtest:zpmqp8rrcpmv79pn8ewxxg0evd3zxdjzrfjxvlef3ccuq5jk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9x93at73xzhdtlgzk9ja5ecxcpumdzth2n72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsxvkssyqy', // 2 coinbase
      'bchtest:zpmqp8rrcpmv7980x60747qvp6jlvkmq0y305tq3ryltkxzk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu989x3jmhul928rh67vxmrpevwfhwtpeprr72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsxeyewpnd', // 3 gemini
      'bchtest:zpmqp8rrcpmv79xgchpgtlgn8ytvek6nxv0x3lg9rc6pwf6k0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu99sspy3d723v6vz64e9f3wv8840ly042qm72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxskanm29ve', // 4 binance_us
      'bchtest:zpmqp8rrcpmv799k8ya3s8hfhj062e9duh9rmcajw9l3tkzk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu98x28refjz8cmgtyfptynh6z7222l4yset72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxs7zlqthwu', // 5 bitstamp
      'bchtest:zpmqp8rrcpmv79qsdgl4xyga5h94f9mrqa2zue93lylcc6zk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9qgdz6udlmm8wycwsl8jxxqs8syfmamdtr72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxs983r20qq', // 6 cryptocom
      'bchtest:zpmqp8rrcpmv7982c30se4thsxqutf9ukxxpeezc7zmee02k0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9z9n7z4mct4twzj95el4tr6scmekunl39t72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxs52d627xc', // 7 bitfinex
      'bchtest:zpmqp8rrcpmv798jg0476ylt7vqvkk7mj2lew5rtzcrangzk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9yepk5mt6p8x9t0atyprk0dg84xvld7fum72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxstjn5dk9m', // 8 exmo
      'bchtest:zpmqp8rrcpmv79xq2ydxj4lw7u895m46zx5ue73jeputdazk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9x2dnk4j5h23jhpu7fnfmfvm99853zhnlm72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsxjuv983e', // 9 independentreserve
      'bchtest:zpmqp8rrcpmv79yfk8slu6j6jxd7ywnpwryyanaeuqxaq0zk0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu98mjhs7ds0ju6fqgejwns7zrkg45raccrt72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsdw60mmdz', // 10 okx_usdc
      'bchtest:zpmqp8rrcpmv79yuhdkccqtgj9ydnfxw092lckzyruj3vg6k0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu98x3p3zeaeqh8u2tq4h7vdmdt2usmd679t72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxspqsqpuny', // 11 kucoin_usdc
      'bchtest:zpmqp8rrcpmv79yswz5fy75dfhenatjangy9fp3eacmh222k0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9ptk5w7e07ejnac09hsd6ljdyzz5z2c3fn72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsww2t4ts9', // 12 bybit
      'bchtest:zpmqp8rrcpmv79pz45sxmugt44natxhppzgsrycc3v9wd42k0x5h3zzc0xqhkqgj0a646lmhsxsxj5me24uhulr72auhu9r4wez5wxk5zvqp42ug08fj33ssnna9vqr72ea8c4n6hde8cljn0fl83n2j08rcs7x32fuuazrc62y8dnruc6w8we63nhqqpnspypl49z9fz37nzwxcjvre9gfvl7g29tn65l4h9wmp9wy8dntcc7y8d5tce6y8d5nce7y8dnruc6wxsvpg4z926', // 13 htx
    ],
    // v22/v23: scripthashes for Fulcrum subscription (P2S addresses not yet
    // decoded by Fulcrum 2.x). Each is sha256(slot_LB) reversed-bytes hex.
    SLOT_SCRIPTHASHES: [
      '32b5a6765a5ef1f73cc439702a48dfe0ffa16b4fa802c0d4e46da22f9d3d83a3', // 1 kraken
      '52f1f1c2fc1e996bc82a051e3ab324526ebc1b84cd04418be9aac3482af1f658', // 2 coinbase
      'd14c18f13f9cb519fbb3b071f72dfaaebffb6c521401354668d4d8fe33957a12', // 3 gemini
      '94a25469e985de1f12621b543f4fcdbc3400f37332dbfe4abbf13b2174645171', // 4 binance_us
      '344f69285583867e0dc718fb54def5c642a3bd82ce54c89478b7b5fd49526db3', // 5 bitstamp
      '66b40ef1694f17d428029d9ec1a7728f5167a5c4599c6ba4d71b651459c72573', // 6 cryptocom
      'b25ba8a2545b0cab310fe92b6b08690ed5df0d3123c9f4c4811fc2f9e76b64d1', // 7 bitfinex
      '63dc21193d438adbc2381b8458666478d8cdb8bbbed1ba20f65fc2f1d091a17d', // 8 exmo
      '0e8e74ed2fd18cf57f4cd0c8539626fdd25737b56bac6db7fa469fede8922103', // 9 independentreserve
      '27483adc081d268e1e295d5bfe180ab45d289a552bf179c802ac2a2ba8c0929d', // 10 okx_usdc
      '4118ce97f5753783f51b800ed6ad09814e48b3fc48c20e9bdcf7b9d2ffefa33c', // 11 kucoin_usdc
      '2edc59bf893cb41ae1d3a0ae28184effa23cffc0e8bffc4d76596d2471fc4134', // 12 bybit
      'e3795de6886b04b7c1d20c3f58f115dee284a046c559415e10d0afa15ee71849', // 13 htx
    ],
    SLOT_CATEGORY: 'ad44838456f7a026a46de4fe6025b30194dc0773b051409e53258e0ab001555f',
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
    DEPLOYED_AT_SEC: Math.floor(new Date('2026-06-11T16:26:00.000Z').getTime() / 1000),
    // Per-publisher per-cycle expected cost in sats (used for runway display).
    // This is a FALLBACK constant — the dashboard calls
    // `measureExpectedSatsPerCycle(client)` on init to derive the live value
    // from recent on-chain tx sizes. The fallback applies only if the
    // measurement RPC fails (e.g., empty history, all subs down).
    // Formula: own_attest_fee + (Oracle.update + 2*Ticker_dust) / 13.
    EXPECTED_SATS_PER_CYCLE: 615n + (5041n + 2n * 1500n) / 13n, // ~1234 (v22 fallback)
    TICKER_DUST_SATS: 1500n,
    TICKER_HEAD_COUNT: 2,
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
  // v24 P01: seq/lastTs/cycleSeq/timestamp widened u32→u40 (5-byte LE) to
  // close F-OC12 Y2038. JS has no getUint40, so read 5 LE bytes by hand
  // (u40 max 2^40 < 2^53, safe as a Number).
  function readU40LE(dv, off) {
    let v = 0;
    for (let i = 4; i >= 0; i--) v = v * 256 + dv.getUint8(off + i);
    return v;
  }
  function decodeOracleCommit(hex) {
    // v24: 18-byte commit, no version, no activeCount. Layout:
    //   seq(5 u40) + lastTs(5 u40) + median(8)
    //
    // F15: activeCount was removed in v22 (T2). Returns null explicitly so
    // callers distinguish "no signal" from "everyone's healthy" — consumers
    // needing federation health read the on-chain quorum count (slot inputs
    // spent) from the latest Oracle.update tx.
    if (hex.length !== 36) return null; // 18 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const scaled = dv.getBigUint64(10, true);
    return {
      seq: readU40LE(dv, 0),
      lastTs: readU40LE(dv, 5),
      medianPrice: scaled,
      medianUsd: Number(scaled) / 1e8,
      activeCount: null,  // F15: explicit null (was synthetic 13 in v22)
    };
  }
  function decodeSlotCommit(hex) {
    // v24: 18-byte commit. Layout: price(8) + ts(5 u40) + cycleSeq(5 u40).
    // No pkh field — pkh lives in the slot's P2S locking_bytecode literal.
    // Caller derives sourceId by matching the UTXO's address against the
    // manifest's per-source SLOT_ADDRS table (positional).
    if (hex.length !== 36) return null; // 18 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return {
      price: dv.getBigUint64(0, true),
      timestamp: readU40LE(dv, 8),
      cycleSeq: readU40LE(dv, 13),
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
      this.watches.set(address, { params, onChange, kind: 'address' });
      await this.connect();
      try {
        const utxos = await this.request('blockchain.address.listunspent', address, ...params);
        onChange(utxos);
      } catch (e) { /* connection path retries; ignore */ }
    }

    // Like subscribeAndFetch but addresses Fulcrum by scripthash directly —
    // required for P2S (CHIP-2024-12) UTXOs since Fulcrum 2.x does NOT yet
    // decode `bchtest:z…` style P2S cashaddrs (it returns "Invalid address").
    // Compute scripthash = sha256(lockingBytecode) reversed; pass hex here.
    async subscribeAndFetchByScripthash(scripthashHex, params, onChange) {
      this.watches.set('sh:' + scripthashHex, { params, onChange, kind: 'scripthash', scripthashHex });
      await this.connect();
      try {
        const utxos = await this.request('blockchain.scripthash.listunspent', scripthashHex, ...params);
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
        for (const [key, w] of this.watches) {
          try {
            if (w.kind === 'scripthash') {
              await this.request('blockchain.scripthash.subscribe', w.scripthashHex);
              this.request('blockchain.scripthash.listunspent', w.scripthashHex, ...w.params)
                .then(w.onChange).catch(() => {});
            } else {
              await this.request('blockchain.address.subscribe', key);
              this.request('blockchain.address.listunspent', key, ...w.params)
                .then(w.onChange).catch(() => {});
            }
          } catch (e) { /* connection path retries */ }
        }
      } else if (mode === 'poll') {
        const pollMs = this.currentEndpoint().pollMs ?? 12000;
        for (const [key, w] of this.watches) {
          const doFetch = () => {
            if (w.kind === 'scripthash') {
              this.request('blockchain.scripthash.listunspent', w.scripthashHex, ...w.params)
                .then(w.onChange).catch(() => {});
            } else {
              this.request('blockchain.address.listunspent', key, ...w.params)
                .then(w.onChange).catch(() => {});
            }
          };
          doFetch();
          const id = setInterval(doFetch, pollMs);
          this.pollTimers.set(key, id);
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
      } else if (msg.method === 'blockchain.scripthash.subscribe' && Array.isArray(msg.params)) {
        const [sh] = msg.params;
        const watch = this.watches.get('sh:' + sh);
        if (watch) {
          this.request('blockchain.scripthash.listunspent', sh, ...watch.params)
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

  // ─── Dynamic per-cycle cost measurement ──────────────────────────────
  // Reads recent on-chain tx sizes (median over a small sample) to derive
  // the per-publisher per-cycle expected cost in sats. Uses any slot's
  // scripthash history — every cycle that slot appears as input in one
  // Oracle.update tx AND as output in one of its publisher's attest txs,
  // so classifying recent tx sizes by a ~1500 B threshold separates the
  // two populations.
  //
  // Returns BigInt sats or null on failure (caller should fall back to
  // CONSTANTS.EXPECTED_SATS_PER_CYCLE).
  async function measureExpectedSatsPerCycle(client, opts = {}) {
    const {
      slotScripthashHex = CONSTANTS.SLOT_SCRIPTHASHES?.[0],
      sampleSize = 16,
      tickerDustTotalSats = CONSTANTS.TICKER_DUST_SATS * BigInt(CONSTANTS.TICKER_HEAD_COUNT),
      publisherCount = 13n,
      attestUpdateThresholdBytes = 1500,
    } = opts;
    if (!slotScripthashHex) return null;
    try {
      const hist = await client.request('blockchain.scripthash.get_history', slotScripthashHex);
      if (!Array.isArray(hist) || hist.length < 4) return null;
      const recent = hist.slice(-sampleSize);
      const rawHexes = await Promise.all(recent.map(
        e => client.request('blockchain.transaction.get', e.tx_hash, false)
      ));
      const sizes = rawHexes.map(h => Math.floor(h.length / 2));
      const attest = sizes.filter(s => s < attestUpdateThresholdBytes).sort((a, b) => a - b);
      const update = sizes.filter(s => s >= attestUpdateThresholdBytes).sort((a, b) => a - b);
      if (attest.length === 0 || update.length === 0) return null;
      const medianAttest = BigInt(attest[Math.floor(attest.length / 2)]);
      const medianUpdate = BigInt(update[Math.floor(update.length / 2)]);
      // Per-publisher: own attest fee + 1/N share of (update fee + ticker dust)
      // Fee assumption: 1 sat/byte at mainnet relay floor.
      return medianAttest + (medianUpdate + tickerDustTotalSats) / publisherCount;
    } catch (_) {
      return null;
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
    measureExpectedSatsPerCycle,
    CONSTANTS,
  };
})();
