# ticker.cash v26 — the minute says how many rows stand behind it

Status: **deployed on chipnet** (2026-10-25; record in §11). Supersedes v25 (`v25-plan.md`), whose
weaknesses were established by the red team of the same day (`../security/red-team-2026-10-25.md`).
Covenants and the VM suite live in `contracts/`; the exchange registry in `node/core/src/sources.rs`.

---

## 0. The design in one screen

* **One commitment is the whole state.** The head NFT carries 33 bytes:
  `seq(4) ‖ price(8) ‖ k(1) ‖ tableHash(20)`. `seq` is the Unix minute the rows observed in, `price`
  the lower median of the included statements, `k` how many rows signed, `tableHash` the hash160
  of the notary table. Tickers carry the first 13 bytes.
* **The floor is seven; the bar is the reader's.** The chain accepts a minute once seven rows signed
  it, and writes the count. A minute signed by all thirteen takes seven colluding keys to forge; one
  signed by seven takes four, and says so. A consumer contract reads the byte and sets its own bar.
  The oracle never goes dark while seven rows are up, and never pretends a weak minute is strong.
* **The table is state, not code.** The Oracle script is one 506-byte body, the same for every
  deployment; the table rides in every spend's unlocking data and is checked against the commitment.
  A strict majority of current rows can rotate the table, migrate the head to a successor covenant,
  or retire it to a key, all through one `rotate()` function and without a new genesis.
* **Chain time bounds the minute from below.** `tx.time ≥ 60·seq − 6 h` (a time-mode locktime,
  untouched by Faster Blocks). No coalition can strand the head with a far-future minute.
* **Tickers live an hour and pay their way.** `consume()` re-emits the same snapshot with a
  1,000-sat toll. `recycle()` burns a Ticker only inside a head spend and only once its own minute
  is an hour old by median-time-past; the Oracle's value rule carries its sats into the reserve.
  No sweeper, no `this.age`, nothing a holder can reset.
* **Everything that comes in goes back to the reserve** except two Tickers and a fee bounded at
  1,000 sats plus two per byte of unlocking data. Top-ups, recycled dust and tolls all flow in; a
  griefing builder can waste at most about one honest fee per minute.
* **Notaries fetch the exchange themselves.** One TLS session to the pinned host with certificate
  validation against the Mozilla roots, one `GET`, one signature, under a second. No TLSNotary, no
  prover, no inbound session port, nothing to stall. A statement names the exchange, not a table row.
* **Honest numbers.** Update 1,936 B (k = 7) to 2,375 B (k = 13), 2,600 B with two recycled
  Tickers and a top-up; rotation 1,637 B. Fee exactly size + 1. 0.028–0.034 BCH a day at one
  update a minute, dust and tolls returned.

| Measured (cashscript 0.14 MockNetworkProvider, `BCH_2026_05`, libauth token validation) | v25 | v26 |
|---|---|---|
| Bytes per update | 1,701 (k = 7) … 2,140 (k = 13) | 1,936 … 2,375 (+ 43 per recycled Ticker) |
| Keys to forge a minute | 4 at any k ≥ 7, unlabeled | (k+1)/2, written in the commitment |
| Rows that may be down | 6 | 6 (the reader decides what it accepts meanwhile) |
| Changing the table | new genesis, new category | `rotate()` by a majority, same category |
| Ticker lifetime | reset by every re-emission; sweepable by anyone keeping the NFT | an hour from its own minute; burned only by an update |
| Far-future seq | bricks the head forever (7 keys) | bounded to 6 h ahead of chain time |
| Fee cap | 5,000 sats flat; any fee with a top-up input | 1,000 + 2 B⁻¹ over all inputs |
| Notary dependencies | tlsn alpha (MPC-TLS / proxy), inbound session port | rustls, outbound only |
| Oracle body / Ticker lock | 373 / 31 B | 506 / 57 B |

---

## 1. Why: the red team of 2026-10-25, finding by finding

| # | v25 weakness | v26 answer |
|---|---|---|
| 1 | Forgery threshold is 4 keys because the builder chooses the subset and every minute is treated as a seven | `k` in the commitment; consumers choose; reference consumer requires 11; builder waits for all rows until second 20 |
| 2 | Seven rows share one TLS terminator | Not a covenant matter. Table policy: publish terminator and quote per row; diversity caps below the forgery threshold are the row-admission rule (§8) |
| 3 | A keyless prover can hold a notary's minute open and choose the sampling instant | There is no session. The notary fetches at second two on its own schedule, re-checks the minute before signing, retries only inside the minute |
| 4 | Tickers never die (age reset by consume, sweep keeps the NFT); an update can burn last minute's Tickers through `consume()` | Lifetime keyed to the Ticker's own minute via `tx.time`; `recycle()` only inside a head spend, burns; `consume()` must keep the commitment and add a toll, so no update output can satisfy it |
| 5 | Seven keys brick the head with `seq = 0x7fffffff` | `tx.time ≥ 60·seq − 21600` |
| 6 | No budget, no exclusion, no migration; every repair is a new category | Majority rotation: table change, migration, retirement; tolls flow to the reserve; keys stay hot (unchanged) |
| 7 | tlsn is a shared alpha root of trust with no trust dividend | Removed. The notary's own TLS fetch gives the same guarantee the chain ever relied on |
| 8 | Fee cap arithmetic; replay of historical statements | Cap over all inputs, proportional to width; statements are per minute and the head's `seq` only moves forward, so a replay is just a stale update that loses to the current one |
| 9 | Data quality (stale "last" prices, stablecoin quotes) | Unchanged in code: the notary signs the pinned field. Registry policy stays the lever (retire quiet markets; mix of quotes) |

Settled principle behind item 1: with a builder-chosen subset of k statements, no aggregation rule
keeps the result inside the honest range against more than ⌊(k−1)/2⌋ liars. Forgery resistance and
outage tolerance share the same thirteen rows. The honest move is to write k and let the party that
knows the stakes choose; the dishonest move was to pick one number for everybody and call it seven.

---

## 2. Protocol

### 2.1 Roles

| Role | Count | Holds | Trusted for | Who can run it |
|---|---|---|---|---|
| Notary (row) | 13 today, 7..127 by covenant | a secp256k1 key in the table | signing what its exchange said, once per minute, with an honest clock; approving rotations with judgment | independent operators |
| Builder | any | nothing (optional coins for top-ups) | nothing (first-seen race) | anyone |
| Consumer | any | its own contract | choosing its `k` and freshness window | anyone |

### 2.2 Messages

```
statement = 0x4e ‖ category(32, VM byte order) ‖ source(1) ‖ seq(4, u32 LE) ‖ price(8, u64 LE)   (46 B)
approval  = 0x52 ‖ category(32) ‖ oldTableHash(20) ‖ nextLockingBytecode ‖ nextCommitment[13..]
signature = BCH Schnorr(secp256k1) over sha256(message), 64 B, CHECKDATASIG-compatible
table     = n × (pubkey(33) ‖ source(1)); hash160(table) in the head commitment
```

The row byte of v25 is gone: a notary is a key and a source, the table may move around it, and the
covenant verifies each statement against the key at the row index the builder names. Duplicate keys
in a table would let one signature count twice; only a majority can author a table, and a majority
already controls the price, so the tooling refuses duplicates and the covenant does not pay for the
check.

### 2.3 One minute

1. Second 2: every notary fetches its pinned endpoint over its own TLS session, checks `200`,
   parses the pinned field, confirms `60m ≤ now < 60m + 90`, signs once, serves
   `GET /v1/statement?seq=m`. Up to two retries six seconds apart, none after second 45.
2. The builder polls every row. When all rows have signed `m`, or at second 20 with at least
   seven, it builds: input 0 the head; inputs 1.. up to ten Tickers whose `60·seq + 3600` is below
   median-time-past, oldest first; then any top-up coin. Output 0 the head with
   `m ‖ median ‖ k ‖ tableHash`; outputs 1–2 Tickers with `m ‖ median ‖ k`, 786 sats each.
   Locktime = max(60m − 21600, recycle times); every input sequence `0xfffffffe`.
3. Fee exactly size + 1 from the reserve; recycled dust and tolls join it.
4. Slow block: the next minute spends the unconfirmed head. Reorg: rebroadcast.

### 2.4 Rotation

`ticker-node approval-request` prints `(category, oldTableHash, nextLock, tail)`; each row's
operator runs `ticker-notary sign-rotate` and returns an approval JSON; `ticker-node rotate` assembles
a strict majority into one transaction and rewrites `manifest.json`. Approvals bind the old table
hash, so a set is valid only against the table it was written for. Rule of operation: never rotate
back to a table that was used before, because an old approval set for that transition would be valid
again.

---

## 3. Covenants (`contracts/`)

### 3.1 `Oracle.cash` — 506 B body, 564 B redeem (constructor: the Ticker lock), P2SH-32

`update(table, seq, rows, prices, sigs, median)`:
1. `this.activeInputIndex == 0`; `seq.length == 4`; `median.length == 8`; `k = rows.length ≥ 7`.
2. Rank loop: `lower = Σ int(p < med)`, `upper = Σ int(p > med)`; require `lower ≤ (k−1)/2`,
   `upper ≤ k/2`, `lower + upper < k` (the lower median is present and unique).
3. `hash160(table) == commit[13..33)`; `int(seq) > int(commit[0..4))`;
   `tx.time ≥ 60·int(seq) − 21600`.
4. Signature loop: row indexes strictly ascending (distinct; an index past the table fails the
   split); `checkDataSig(sig_i, 0x4e ‖ cat ‖ table[row].source ‖ seq ‖ price_i, table[row].pubkey)`.
5. Exactly three outputs: head with the same lock, same category and capability, commitment
   `seq ‖ median ‖ k ‖ tableHash`; two Tickers at the pinned lock, category (immutable), snapshot,
   exactly 786 sats.
6. `out0.value ≥ Σ inputs − 1572 − 1000 − 2·len(unlockingBytecode)`.

`rotate(table, rows, sigs)`: input 0; table hashes to the commitment; `2·k > n`; exactly one
output keeping category and capability whose commitment begins with the current 13-byte snapshot;
every signer approved `0x52 ‖ cat ‖ tableHash ‖ out0.lock ‖ out0.commitment[13..]`;
`out0.value ≥ Σ inputs − 1000 − 2·len(unlockingBytecode)`.

Two cashc lessons that cut 180 bytes: count with `int(bool)` instead of `if` chains, and never
reassign a variable that sits deep in the stack inside a loop (cashc moves everything above it
through the altstack). The rank loop therefore runs first with its counters on top of the stack,
and the signature loop indexes buffers by a counter instead of consuming them.

### 3.2 `Ticker.cash` — 57 B, P2S

`consume()`: output at the same index has the same lock, category and commitment and
`value ≥ input value + 1000`. `recycle()`: `tx.inputs[0].tokenCategory == own category ‖ 0x02` and
`tx.time ≥ 60·seq + 3600` from its own commitment. A Ticker output is 114 B on the wire; the dust
floor is 3 × (114 + 148) = 786 sats, pinned exactly.

### 3.3 `PriceGated.cash` — 51 B, reference consumer

Pins the category only (every token of the category other than the head is a Ticker), requires
`c.length == 13`, `minSeq ≤ seq ≤ maxSeq`, `price ≥ strike`, `k ≥ minK`.

### 3.4 VM results (`npm test`)

55 scenarios green. Accepted: update k = 7 / 8 / 13 / 14 (after rotation); update recycling two
Tickers plus a top-up (reserve grows by exactly inputs − 2 Tickers − fee); the red-team subset
forgery, labeled k = 7; consume with the toll; rotation by 7 and 8 of 13, to a new table and to a
P2PKH; PriceGated release at k = 13 with minK = 11. Rejected at the expected `require`: k = 6,
duplicate row, row index past the table, stale seq, foreign exchange / deployment / key, wrong or
absent median, wrong commit price or k, Ticker commit mismatch, wrong table, head with a changed
table hash, drain beyond the cap, extra output, Ticker at 785 or 787, seq more than six hours
ahead of the locktime, final sequence, burning last minute's Tickers through `consume()`, early
recycle, recycle outside an update, consume without toll / changed commitment / re-locked, rotation
by 6, approvals for another lock or table, duplicate signer, changed state, second output,
PriceGated at k = 7 / stale / hoarded / low. `npm run vectors` writes deterministic transactions that
`node/core` rebuilds byte for byte (update, update with recycle and a P2PKH top-up, rotation).

---

## 4. Trust model

**Consensus enforces:** ≥ 7 distinct table rows signed `(category, source, seq, price_i)`; the
posted value is their lower median; `k` is their count; `seq` increases and stays within six hours
of chain time; the head, category, capability and reserve survive; exactly two Tickers of the
snapshot are minted; the table changes only by majority approval.

**The reader decides:** a minute signed by k rows needs ⌊(k−1)/2⌋ + 1 keys to forge. 7 → 4,
9 → 5, 11 → 6, 13 → 7. The reference consumer takes 11. On 2026-10-25 the live v25 oracle had all
thirteen rows signing in 90 % of minutes and eleven or more in 96 %, never two weak minutes in a row.

**Rows are trusted for:** signing what their exchange said, once per minute, with a sane clock, and
for approving rotations with judgment. A strict majority governs the oracle and its reserve, which
is why the reserve holds weeks of fees, not years.

**Table policy (not consensus):** rows are admitted so that no single TLS terminator, quote
currency, operator or jurisdiction covers more rows than the forgery threshold of the minutes
consumers rely on; the mix is published per row.

| Threat | Outcome |
|---|---|
| ≤ 3 rows lie or are stolen, all 13 signing | absorbed; the minute is labeled 13 |
| 4 keys build a k = 7 minute | postable, labeled k = 7, their forged statements on chain; consumers at k ≥ 11 skip it; the other rows rotate them out |
| 7 keys | control the price and the governance; same bound as any 13-row design |
| Builder posts only 7 of 13 available statements | labeled k = 7; the honest builder posts 13 the next minute |
| 3 rows down for a day | the oracle writes k = 10 minutes; k ≥ 11 consumers wait, others continue |
| Far-future seq | at most 6 h ahead of chain time; needs 7 keys anyway |
| Ticker hoarding | a Ticker lives an hour; consumers keep a `maxSeq` ceiling or settle in two steps |
| Griefing builder (≥ 4 keys) | at most ~1,900 extra sats per minute from the reserve |
| Exchange outage, geo-block, TLS change | that row is missing; the minute's k says so |
| Reorg | statements survive; rebroadcast |

---

## 5. Cost model

Fee exactly size + 1 sat (fixed-width transactions). Bytes at k = 13: redeem 567 (pushed) +
table 445 + signatures 835 + prices 106 + rows/seq/median/selector 29 + input overhead 43 + head
output 112 + two Ticker outputs 228 + overhead 10 = **2,375**. At k = 7: **1,936**. Each recycled
Ticker adds 43 B and returns at least 786 sats; steady state recycles two per minute.

| Per day, 1,440 updates | k = 7 | k = 13 |
|---|---|---|
| Update fees | 2.79 M sats | 3.42 M sats |
| Recycled-input bytes (2 per update) | 0.12 M sats | 0.12 M sats |
| Ticker float | returns after an hour | returns after an hour |
| **Reserve outflow** | **≈ 0.029 BCH** | **≈ 0.035 BCH** |

At BCH ≈ $270 that is $7.9–9.6 per day. Against v25's $7.5–9.3 (sweeps included) the extra buys
k in every commitment, chain-time bounds, rotation, migration, retirement and self-funding Tickers.

The redeem is 564 B for every deployment and is revealed every minute. Putting `rotate()` in a
separate NFT was measured on paper at about the same cost (+1 input and +1 output per minute) with
two UTXOs to keep consistent; one script won.

---

## 6. Off-chain architecture

```
node/core      commitments (13/33 B), statements + approvals, BCH Schnorr, registry, HTTPS fetch (rustls), tx builders, Electrum (+ median-time-past)
node/notary    ticker-notary: init | run | pubkey | sign-rotate. Fetches at second 2, retries to second 45, signs once, serves /v1/{info,statement,latest}
node/daemon    ticker-node: keygen | derive | genesis | run | build | topup | approval-request | rotate | status | status-json
contracts/     Oracle.cash, Ticker.cash, PriceGated.cash, artifacts, VM suite + vectors
web/           manifest-driven pages; the client decodes both commitments and checks the on-chain table hash (RIPEMD-160 in the browser)
deploy/        systemd units: 13 notaries + node as user units, web as a hardened system unit
```

The daemon's `collect` verifies every statement against the row's key and source before building;
`select_statements` in core maps statements to rows by source and signature. Fulcrum is untrusted:
head and Tickers are decoded against the manifest's locks, category and codecs.

---

## 7. Decisions (continuing v25's numbering)

| # | Decision | Outcome |
|---|---|---|
| D14 | Set rule | **Floor 7, k written to the commitment.** Not "all but two" (dark when three rows are down) and not more rows (the user's scope is thirteen). |
| D15 | Table as state | **hash160 in the commitment, table in the unlocking data, `rotate()` by a strict majority.** Two thirds was rejected: five silent rows could freeze the table while eight honest rows could not eject them; majority equals control already. |
| D16 | Chain-time bound | **`tx.time ≥ 60·seq − 21600`.** Six hours leaves room for a slow chipnet; a brick needs seven keys and lasts six hours at most. |
| D17 | Ticker lifetime and recycling | **One hour from its own minute; recycle only inside a head spend; no sweep; 1,000-sat toll on consume.** |
| D18 | Value rule | **`out0 ≥ Σ inputs − 2·786 − 1000 − 2·len(unlocking)`.** Proportional so the table can grow; about 2× the honest fee. |
| D19 | Notary fetch | **Direct TLS fetch, tlsn removed.** No trust dividend after D8 (open provers); one dependency fewer; no session surface. |
| D20 | Row byte in statements | **Dropped.** A notary is a key and a source; the table moves around it. |
| D21 | Ticker value | **786 sats**, the exact dust floor of the 114-byte output (3 × (114 + 148)), pinned. |
| D22 | One lock for all deployments | **Yes.** The head address is shared; the category selects. Clients filter by category. |
| D23 | Reference consumer | **PriceGated with minK (default 11)**; two-step settlement recommended in the docs for long-lived consumers. |
| D24 | Rotation replay | **Approvals bind the old table hash; operators never rotate back to a used table.** A per-head nonce would have made human-paced approval collection impossible. |
| D25 | Data policy (mid-price, spread, timestamps) | **Deferred.** Registry pointers stay "last"; changing thirteen extraction rules blind is riskier than the gain. |

---

## 8. Open items

* Hand rows to independent operators; publish terminator, quote, operator and jurisdiction per row;
  keep each below the forgery threshold of the minutes consumers rely on.
* A notary data policy (mid-price where offered, refuse stale exchange timestamps) is a registry and
  notary change with no consensus impact.
* Keys are hot files on servers that sign every minute. A signing sidecar or TPM is the next step
  for independent operators.
* Mainnet after independent rows exist. On ten-minute blocks the minute cadence forms unconfirmed
  chains inside each block, exactly as on chipnet before Faster Blocks.

---

## 9. Appendix — byte layouts

```
Snapshot (13 B):        seq u32 LE[4] ‖ price u64 LE[8] ‖ k u8[1]           (every Ticker)
Head commit (33 B):     snapshot ‖ tableHash[20]
Table:                  n × (compressed pubkey[33] ‖ source[1]), row order
Statement:              0x4e ‖ category_vm[32] ‖ source[1] ‖ seq[4] ‖ price[8]        (46 B)
Approval:               0x52 ‖ category_vm[32] ‖ oldTableHash[20] ‖ nextLock ‖ nextCommit[13..]
Unlocking (update):     push median[8] ‖ push sigs[64k] ‖ push prices[8k] ‖ push rows[k] ‖ push seq[4] ‖ push table ‖ OP_0 ‖ push redeem[564]
Unlocking (rotate):     push sigs[64k] ‖ push rows[k] ‖ push table ‖ OP_1 ‖ push redeem[564]
Ticker unlocking:       OP_0 (consume) | OP_1 (recycle)
Update tx:              in0 head (+ recycled Tickers, + top-ups) → out0 head, out1..2 Ticker (P2S 57 B, 786 sats); locktime ≥ 60·seq − 21600; sequences 0xfffffffe
```

## 10. Measurement sources

`contracts/test/v26.suite.mjs` (cashscript 0.14.0, libauth 3.0.0, cashc 0.14.0); `node/core`
unit tests against `contracts/test/v26-vectors.json`; the live v25 node's journal for the k
distribution of 2026-10-25 (1,290 updates: 1,161 at k = 13, 1,240 at k ≥ 11, longest run below 11
one minute, longest gap three minutes).

## 11. Deployment record (chipnet, 2026-10-25)

| | |
|---|---|
| network | chipnet |
| category | `8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b` |
| genesis | `1b0f8be2749e5b4454afba5465a9815f90ce8e1edba71b563aeb2d4925fac5af` (297 B, fee 298 sats) |
| head address | `bchtest:pwvqk78n47999y648vkpdm5r4m95rk96ezvm8yj7qaz6293zzkq6wqp0r9nnq` (the v26 lock, shared by every v26 deployment) |
| oracle lock | `aa20980b78f3af8a5293553b2c16ee83aecb41d8bac899b3925e0745a516221581a787` |
| Ticker lock | `76009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f7581013c9502100e93b1755168` |
| table hash | `f6118ff8061f8900a22b384f8275ea30888957de` |
| table | rows 0–12 → registry ids 1, 2, 3, 16, 5, 6, 7, 14, 15, 10, 11, 12, 13 (Kraken, Coinbase, Gemini, Binance·USDC, Bitstamp, Crypto.com, Bitfinex, Gate.io·USDT, Bitget·USDT, OKX·USDC, KuCoin·USDC, Bybit·USDT, HTX·USDT); fresh keys |
| reserve | 14,400,000 sats (≈ 6,000 updates at k = 13, about four days; the v25 head keeps its 35.4 M sats, which v25 had no way to release) |
| first update | `3221be3d36623b03d3eee7538647ae063ef352f40ffa9d606691a864e16f8e62`: minute 29882228, k = 13, 2,375 B, fee 2,376 sats, median 272.57, locktime 60·seq − 21600 = 1792912080 against median-time-past 1792929266 |
| operator | ticker.cash runs all 13 rows on one host (`deploy/systemd/`); the builder is the same daemon |
| web | https://usd.ticker.cash serves `manifest.json` and `status.json`; pages read the head from Fulcrum over WSS and check the table hash |

### 11.1 Live consumer test (13:21 UTC)

`contracts/tools/live-consume.mjs` funded a `PriceGated` coin (strike $100, window ±5 minutes,
`minK = 11`) in `1d750ea4baa01d33f2629923c9f22490a99f88db29f264c58c154a587414e7aa` (229 B) and
released it in `3a35fd323c10a2772e06455f1edf9a4901a3b498e41536e075ec3d3f2868adc5` (622 B) against
the Ticker of minute 29882240 (k = 13, $272.61), re-emitting the Ticker at output 1 with
1,786 sats. Both were accepted by the chipnet node on first broadcast: P2S Ticker spend, toll, k
gate and exact fees all hold on the real network. The re-emitted Ticker is recycled by an update
once its minute is an hour behind median-time-past, carrying the toll into the reserve.

### 11.2 First recycle (14:53 UTC)

Update `7059b14cc311c6a2b06e6159d0d86aab781ff8fe94899ef070d6ee2abbce9e10` (minute 29882332,
2,795 B) spent ten hour-old Tickers for 8,860 sats: nine at 786 and the consumer test's Ticker at
1,786, toll included. Its locktime 1792938120 was the newest recycle time among them, against
median-time-past 1792938246. The next update recycled four more and the reserve moved by 972 sats
net: fee 2,544 plus two new Tickers minus 3,144 recycled. From here the reserve pays fees only, as
designed. On ten-minute chipnet blocks the first recycle came 105 minutes after the first mint,
the hour plus median-time-past's lag behind the clock; on one-minute blocks it will be close to
an hour.

### 11.3 Cutover notes

* v25 units were stopped at 13:01 UTC; the v25 notary homes and manifest are archived under
  `~/archive/v25/`. The v25 head (category `16bc04ed…`) stays on chain, unspendable except through
  `update`, which nobody signs for any more.
* The v26 notary binaries were smoke-tested against Kraken, Bitfinex and OKX before the cutover:
  fetch and sign in 44–372 ms, three minutes each, no failures.
* The 13 notaries and the node run as the same user units as before; only the binaries, the unit
  descriptions and the homes changed. The host's security posture (Cloudflare Tunnel, Tailscale-only
  administration) is untouched.
