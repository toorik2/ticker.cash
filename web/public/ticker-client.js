// ticker.cash browser client — shared by /, /stats, and any future pages.
//
// Exports (as window globals):
//   TickerClient.ElectrumWS                — pool-aware, subscribe-aware WS client
//   TickerClient.decodeOracleCommit(hex)   — 16-byte Oracle commit → object (v22)
//   TickerClient.decodeSlotCommit(hex)     — 16-byte Slot commit → object (v22)
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
    ORACLE_ADDR: 'bchtest:p0gf2c5mtatyz9cf5v6exafy363u7q7537ep6xvf0tmu7xxtjy87st9pt7k3n',
    ORACLE_CATEGORY: '59fc5d4f6f3ce872792ec537c0efb9b8a04fafe359883c51f27851e35753016a',
    // v22/v23: P2S slot addresses (CHIP-2024-12). Each slot's LB IS its compiled
    // body (per-source specialized with pkh + cnHash + oracleCatHash inlined
    // as script literals). Fulcrum 2.x doesn't decode P2S cashaddrs yet, so
    // the dashboard subscribes by SCRIPTHASH (see SLOT_SCRIPTHASHES below).
    // SLOT_ADDRS kept for display + cashaddr generation.
    SLOT_ADDRS: [
      'bchtest:zpmqp8rrcpmv79yvutg8k43j5kz474q36wcgtsdu68q8596k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpf0lzjvdyrgrrfq2wn50q2fdp9st39ulrcljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qk3uvh2pf', // 1 kraken
      'bchtest:zpmqp8rrcpmv79pn8ewxxg0evd3zxdjzrfjxvlef3ccuq5jk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpf3v02l5fs4m2l6q43vhdxwpkq0xmgja65ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qw9jq46ze', // 2 coinbase
      'bchtest:zpmqp8rrcpmv7980x60747qvp6jlvkmq0y305tq3ryltkxzk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfef5vkal8e23ca7hnpkccwtrjdmjcwggcljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qvf5c8mf4', // 3 gemini
      'bchtest:zpmqp8rrcpmv79xgchpgtlgn8ytvek6nxv0x3lg9rc6pwf6k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfvyqfyt0j5txnqk4wf2vtnpeatlera2sxljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qz6a4xuk4', // 4 binance_us
      'bchtest:zpmqp8rrcpmv799k8ya3s8hfhj062e9duh9rmcajw9l3tkzk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfej3c72vs37x6zezg2eya7shjjjhafyx2ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q6tcf5ule', // 5 bitstamp
      'bchtest:zpmqp8rrcpmv79qsdgl4xyga5h94f9mrqa2zue93lylcc6zk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpgzrgkhr077em3xr58eu33sypupzwlwm2cljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q87sqde68', // 6 cryptocom
      'bchtest:zpmqp8rrcpmv7982c30se4thsxqutf9ukxxpeezc7zmee02k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpg3vls4w7za2ms53dx0a2c75xx7dhyluf2ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q54jzatf9', // 7 bitfinex
      'bchtest:zpmqp8rrcpmv798jg0476ylt7vqvkk7mj2lew5rtzcrangzk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfxgd4x67sfe32ml2eqganm2pafn8m0j0xljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q8a0q3vfy', // 8 exmo
      'bchtest:zpmqp8rrcpmv79xq2ydxj4lw7u895m46zx5ue73jeputdazk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfjnva4v4965v4c08jv6w6txeffayg4ul7ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qsjdr6xpa', // 9 independentreserve
      'bchtest:zpmqp8rrcpmv79yfk8slu6j6jxd7ywnpwryyanaeuqxaq0zk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpf7u4u8nvruhxjgzxvn5u8ssaj9dqlwxq6ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qyuz3f0c4', // 10 okx_usdc
      'bchtest:zpmqp8rrcpmv79yuhdkccqtgj9ydnfxw092lckzyruj3vg6k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfe5gvgk0wg9elzjc9dlnrwm26hyxmwh32ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qau90pz6j', // 11 kucoin_usdc
      'bchtest:zpmqp8rrcpmv79yswz5fy75dfhenatjangy9fp3eacmh222k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpg2a4rhktlkv5lwredurwhunfqs4qjky2vljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qkzsz8daw', // 12 bybit
      'bchtest:zpmqp8rrcpmv79pz45sxmugt44natxhppzgsrycc3v9wd42k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpgatkg4r344qnqqd2hzre6v5vvyyulftqqljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5exuc05r2ea93vl6lg95ddxm93th2nyav3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qmu28rwpp', // 13 htx
    ],
    // v22/v23: scripthashes for Fulcrum subscription (P2S addresses not yet
    // decoded by Fulcrum 2.x). Each is sha256(slot_LB) reversed-bytes hex.
    SLOT_SCRIPTHASHES: [
      '3305151af8abf383b2b30df0c24ef8ef906d4438d7617ed19072a254d8494263', // 1 kraken
      'c26a217af56e2a8b868c2868f40db05979df086ec4bbb9ccba614a94f25d71c9', // 2 coinbase
      '1809b48903f9fde101d976a3da37c26e26448958cd501d0d26b753239cced1ec', // 3 gemini
      '4e191f3043997a8c7ca8f73a052a09465ae8ca5838ed810b37798b763f72b35c', // 4 binance_us
      'f2e454fec0cfc332c6c8e56126afb023be4c58d67b1665a66e9c1048e284a52d', // 5 bitstamp
      '1d37663ef0ea6320e32b287480117e2e1430a855a11fd0c97446fa70112aa37f', // 6 cryptocom
      '8c382d8670beeb7eac66dbfa16c500aeec363b62814a8fd468d475375b4701e7', // 7 bitfinex
      '90bb349ded00f3c0cdae97f8c84de059fc22e47da1745d0eee8e5fb500d4d118', // 8 exmo
      '7d5ead6e337496683b0d8ad5e2b2d3201a4e65bd8bd592f919ff6e8dc38f757f', // 9 independentreserve
      '3056ebce28862bfae629ff393e0446f611f7729e699087111735843918c79a9c', // 10 okx_usdc
      'a878de27a476a962c0485cf70c9b4c078b7d82faea08fe64142924ff8b3efa8a', // 11 kucoin_usdc
      'e02ecaa37bd7068fe7e62482512f45b304c1deab8037f8050dc0427d120a2b99', // 12 bybit
      '7aa0b7d970c54007f75dacfba792b404f64efd700637ff55b6d9d48708da509e', // 13 htx
    ],
    SLOT_CATEGORY: '6de0906ddcb196bfc3908c7312f104d44542cc9e67678303c051e275679913eb',
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
    DEPLOYED_AT_SEC: Math.floor(new Date('2026-06-03T04:32:01.000Z').getTime() / 1000),
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
  function decodeOracleCommit(hex) {
    // v22: 16-byte commit, no version, no activeCount. Layout:
    //   seq(4) + lastTs(4) + median(8)
    //
    // F15 (v23): activeCount was removed from the Oracle commit in v22 (T2).
    // Previously this function returned synthetic 13 — a silent lie that
    // hid federation-degradation signal from consumers. v23 returns null
    // explicitly so callers can distinguish "no signal available" from
    // "everyone's healthy." Consumers needing federation health MUST read
    // the on-chain quorum count from the most recent Oracle.update tx
    // (count of slot inputs spent).
    if (hex.length !== 32) return null; // 16 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const scaled = dv.getBigUint64(8, true);
    return {
      seq: dv.getUint32(0, true),
      lastTs: dv.getUint32(4, true),
      medianPrice: scaled,
      medianUsd: Number(scaled) / 1e8,
      activeCount: null,  // F15: explicit null (was synthetic 13 in v22)
    };
  }
  function decodeSlotCommit(hex) {
    // v22: 16-byte commit. Layout: price(8) + ts(4) + seq(4).
    // No pkh field — pkh lives in the slot's P2S locking_bytecode literal.
    // Caller derives sourceId by matching the UTXO's address against the
    // manifest's per-source SLOT_ADDRS table (positional).
    if (hex.length !== 32) return null; // 16 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return {
      price: dv.getBigUint64(0, true),
      timestamp: dv.getUint32(8, true),
      cycleSeq: dv.getUint32(12, true),
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
