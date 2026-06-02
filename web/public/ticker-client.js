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
    ORACLE_ADDR: 'bchtest:pw5j9jpl3qazcl3rljm69dhpxfdq5jgq0lcm7x7n3laj7lj026rrkz8yqpcpm',
    ORACLE_CATEGORY: '3f341d39cf06e78d2caaf39431471fcf529d20f80e334ce7843701c1e25c1f80',
    // v22: P2S slot addresses (CHIP-2024-12). Each slot's LB IS its compiled
    // body (per-source specialized with pkh + cnHash + oracleCatHash inlined
    // as script literals). Fulcrum 2.x doesn't decode P2S cashaddrs yet, so
    // the dashboard subscribes by SCRIPTHASH (see SLOT_SCRIPTHASHES below).
    // SLOT_ADDRS kept for display + cashaddr generation.
    SLOT_ADDRS: [
      'bchtest:zpmqp8rrcpmv79yvutg8k43j5kz474q36wcgtsdu68q8596k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpf0lzjvdyrgrrfq2wn50q2fdp9st39ulrcljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qnynu57a7', // 1 kraken
      'bchtest:zpmqp8rrcpmv79pn8ewxxg0evd3zxdjzrfjxvlef3ccuq5jk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpf3v02l5fs4m2l6q43vhdxwpkq0xmgja65ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qtsaskw7w', // 2 coinbase
      'bchtest:zpmqp8rrcpmv7980x60747qvp6jlvkmq0y305tq3ryltkxzk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfef5vkal8e23ca7hnpkccwtrjdmjcwggcljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qfumgy04z', // 3 gemini
      'bchtest:zpmqp8rrcpmv79xgchpgtlgn8ytvek6nxv0x3lg9rc6pwf6k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfvyqfyt0j5txnqk4wf2vtnpeatlera2sxljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q80j99g2z', // 4 binance_us
      'bchtest:zpmqp8rrcpmv799k8ya3s8hfhj062e9duh9rmcajw9l3tkzk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfej3c72vs37x6zezg2eya7shjjjhafyx2ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35ql7hehgrw', // 5 bitstamp
      'bchtest:zpmqp8rrcpmv79qsdgl4xyga5h94f9mrqa2zue93lylcc6zk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpgzrgkhr077em3xr58eu33sypupzwlwm2cljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qztlswdxs', // 6 cryptocom
      'bchtest:zpmqp8rrcpmv7982c30se4thsxqutf9ukxxpeezc7zmee02k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpg3vls4w7za2ms53dx0a2c75xx7dhyluf2ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q3qaj7l4j', // 7 bitfinex
      'bchtest:zpmqp8rrcpmv798jg0476ylt7vqvkk7mj2lew5rtzcrangzk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfxgd4x67sfe32ml2eqganm2pafn8m0j0xljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qzgqsjc4n', // 8 exmo
      'bchtest:zpmqp8rrcpmv79xq2ydxj4lw7u895m46zx5ue73jeputdazk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfjnva4v4965v4c08jv6w6txeffayg4ul7ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q48zneja2', // 9 independentreserve
      'bchtest:zpmqp8rrcpmv79yfk8slu6j6jxd7ywnpwryyanaeuqxaq0zk0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpf7u4u8nvruhxjgzxvn5u8ssaj9dqlwxq6ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qpfdp2myz', // 10 okx_usdc
      'bchtest:zpmqp8rrcpmv79yuhdkccqtgj9ydnfxw092lckzyruj3vg6k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpfe5gvgk0wg9elzjc9dlnrwm26hyxmwh32ljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qcf2lzkx9', // 11 kucoin_usdc
      'bchtest:zpmqp8rrcpmv79yswz5fy75dfhenatjangy9fp3eacmh222k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpg2a4rhktlkv5lwredurwhunfqs4qjky2vljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35qnhljyepe', // 12 bybit
      'bchtest:zpmqp8rrcpmv79pz45sxmugt44natxhppzgsrycc3v9wd42k0x5h3zzc0xqhkcrlw4w87aup5p54x72409l8cljh09lpgatkg4r344qnqqd2hzre6v5vvyyulftqqljk0f79v74mwf78u5m60euv65nec7y8352j088gs7xj3pmvclxxn3mkw5vacqqvuqfq0afg32g5wpfc5jfu22ah45mwlmwnnf27pjyes47g3pm9rgrrwmrsz8tlw4v87aup0zxvwqga0a64slmhs9h2q6tddpmv67x83pmdz7xw3pmdy7x03pmvclxxn35q7f9hq6ak', // 13 htx
    ],
    // v22: scripthashes for Fulcrum subscription (P2S addresses not yet
    // decoded by Fulcrum 2.x). Each is sha256(slot_LB) reversed-bytes hex.
    SLOT_SCRIPTHASHES: [
      '308556302d5ec33a19bb9936639d9957894e93c45fc005ae5439c9d197d4c51d', // 1 kraken
      'ab5e65ea632c09475ee7fb82ed503eb1f5d92b4702d2f9fd951cc73a594f535d', // 2 coinbase
      '4f9171ef60641b1849bf8390ca204a3960d3ce213af89381bddf54d4326f7f58', // 3 gemini
      '381ef3dace49ea14aa96edebc4f93f8e36ba5257dcde08256045c98613b5e180', // 4 binance_us
      '869f2104a4a7a7220be11206a4c7b3fd9700961aad4e06a2414c1510742db178', // 5 bitstamp
      '8d6ee5d6badb23b2670381a89bcd7416c31f47ce79e365f30b2ac022e99a6852', // 6 cryptocom
      '0a115a9e2d7cac148d01b56fabf19814e104d31cc3cca1179fa52504e8b77d43', // 7 bitfinex
      '6b99293784c41b6c5477df04cb214d5855a416f9966b408a771d5c861b61691f', // 8 exmo
      '52095bab93aa9df7a381cda42e06043bce437fe0e64d62e4ddd3063caad36515', // 9 independentreserve
      'c61b004d514befaf8b6d017f74c690ec8b70f7abc137e8a23028279a059d58b1', // 10 okx_usdc
      'c331783b3e021feeb1644689844a6e6be361d711464825038caabad45994ff82', // 11 kucoin_usdc
      '88f59868c03699baf69276fef8fe8c944e0c0702c75983f4b7f4850bd754c8a6', // 12 bybit
      '8ee4c472e41499276db3ecbf44ac44a32c2052c5f852a662f88a6e6a75bc0c55', // 13 htx
    ],
    SLOT_CATEGORY: 'f701fd8bf84c35c8adeb3ba268f065736805dac9c148571340176f78797a7929',
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
    DEPLOYED_AT_SEC: Math.floor(new Date('2026-06-02T18:09:00.000Z').getTime() / 1000),
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
    // v22: 16-byte commit, no version, no activeCount. Layout:
    //   seq(4) + lastTs(4) + median(8)
    if (hex.length !== 32) return null; // 16 B × 2 hex chars
    const b = hexToBytes(hex);
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const scaled = dv.getBigUint64(8, true);
    return {
      seq: dv.getUint32(0, true),
      lastTs: dv.getUint32(4, true),
      medianPrice: scaled,
      medianUsd: Number(scaled) / 1e8,
      activeCount: 13,  // v22: activeCount dropped; consumers see synthetic constant
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
