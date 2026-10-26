# ticker.cash v27 — the snapshot is a price message, and anyone may instantiate an oracle

Status: **deployed on chipnet by migration** (2026-10-25; record in §8). Supersedes v26
(`v26-plan.md`), which it reached by one `rotate()`: the same category, the same table, the same
reserve, a new covenant. Covenants and the VM suite live in `contracts/`.

---

## 0. What changed, in one screen

* **The 17-byte snapshot is an Oracles.cash price message plus one byte.**
  `timestamp(4) ‖ messageSequence(4) ‖ dataSequence(4) ‖ price(4) ‖ k(1)`, little-endian ints: the
  timestamp is the start of the observed minute, both sequences are the oracle's update counter
  (the covenant advances it by exactly one per update), the price is US cents per BCH, `k` is how
  many rows signed. Any reader of that format reads a Ticker as a price message; the signature is
  consensus rather than a key. Head commitment: snapshot ‖ tableHash, 37 bytes.
* **Notary statements name no deployment.** `0x4e ‖ source ‖ timestamp ‖ price`, 10 bytes. A
  statement is a public fact about one exchange at one minute, signed by a key. Any head whose
  table lists that key may consume it: anyone can genesis a head with their own table and reserve
  over the public notaries, and any builder can run it. Replay across instances is the point.
  Rotation approvals still bind the category, so each instance is governed by its own rows.
* **Tickers live a day.** `recycle()` opens 86,400 s after the Ticker's own timestamp, so a Ticker
  referenced by a slow multi-party flow (an XO invitation signed by humans) is still there at
  broadcast. The cost is float that returns: about 2.3 M sats parked across the day.
* **Migration instead of genesis.** The v26 head rotated into the v27 lock under v26's own rules,
  carrying category, reserve, price and k. v26 Tickers still alive are recycled by the v27 head.
* **Honest numbers.** Oracle 518 B body, 574 B redeem; Ticker 55 B; update 1,922 B (k = 7) to
  2,336 B (k = 13), 2,561 B with two recycled Tickers and a top-up; rotation 1,651 B; migration
  1,641 B. Fee exactly size + 1.

| Measured (cashscript 0.14, `BCH_2026_05`, libauth token validation) | v26 | v27 |
|---|---|---|
| Snapshot / head commitment | 13 / 33 B, own layout | 17 / 37 B, Oracles.cash message ‖ k ‖ tableHash |
| Price unit | 1e-8 USD, u64 | US cents, i32 (Oracles.cash scaling 100) |
| Statement | 46 B, binds the category | 10 B, binds nothing but the fact |
| Who can instantiate an oracle | the operator who runs the notaries | anyone, over any public notaries |
| Ticker lifetime | 1 h | 24 h |
| Update bytes k = 7 / 13 | 1,936 / 2,375 | 1,922 / 2,336 |
| Oracle body / Ticker lock | 506 / 57 B | 518 / 55 B |

---

## 1. Why

**Oracles.cash compatibility without a relay.** Oracles.cash is the price source of
AnyHedge and BCH Bull: one key signs a 16-byte message a minute, price in cents. Verified live on
2026-10-25: attestation period 60,000 ms, scaling 100, one message per minute. Nothing on chain can
produce a key signature, so an unmodified AnyHedge cannot read a Ticker; but a Ticker-aware contract
replaces `checkDataSig` with "input i is a Ticker of category X" and parses the identical bytes.
Every wallet, template and dashboard that already parses Oracles.cash messages parses ours. The user's rule
for this work was no extra layers; byte-level compatibility is how far that rule allows us to go.

**Contiguous counter.** AnyHedge v0.12 settles with two consecutive messages
(`settlementSequence − 1 == previousSequence`). Minute numbers skip when a minute is missed; a
counter the covenant advances by one never does. Notaries never see the counter.

**Permissionless instantiation.** The 13 rows are the costly part of an oracle; the head is one
UTXO and some reserve. With deployment-free statements the rows become shared infrastructure and a
head becomes something a wallet template can create. The Oracle lock is a constant, so such a
template hard-codes the audited covenant and takes only a table and a reserve. (The XO engine has no
CashTokens genesis primitive yet; see §7.)

---

## 2. Protocol

```
statement = 0x4e ‖ source(1) ‖ timestamp(4 LE) ‖ price(4 LE, cents)                       (10 B)
approval  = 0x52 ‖ category(32) ‖ oldTableHash(20) ‖ nextLockingBytecode ‖ nextCommitment[17..]
snapshot  = timestamp(4) ‖ messageSequence(4) ‖ dataSequence(4) ‖ price(4) ‖ k(1)         (17 B)
head      = snapshot ‖ tableHash(20)                                                        (37 B)
```

One minute: at second 2 every notary fetches its exchange over its own TLS session, converts the
price to cents (round half up), signs the statement for the minute start, serves it. The builder
posts when all rows have signed or at second 20 with at least seven; the transaction spends the
head, up to ten Tickers whose day is up by median-time-past (v27 or leftover v26), and any top-up
coin; its locktime is the latest of `timestamp − 6 h` and the recycle times.

---

## 3. Covenants

**Oracle.update(table, ts, rows, prices, sigs, median)**: head at input 0; `ts` 4 B, `median`
4 B, `k ≥ 7`; rank the median over the 4-byte prices; `hash160(table) == commit[17..37)`;
`int(ts) > int(commit[0..4))`; `tx.time ≥ int(ts) − 21600`; `sequence = commit[8..12) + 1`;
for each row, indexes strictly ascending and `checkDataSig(sig, 0x4e ‖ source ‖ ts ‖ price,
pubkey)`; exactly three outputs: head with `ts ‖ sequence ‖ sequence ‖ median ‖ k ‖ tableHash`,
two Tickers with the 17-byte snapshot at exactly 792 sats; `out0.value ≥ Σ inputs − 2·792 − 1000
− 2·len(unlocking data)`.

**Oracle.rotate(table, rows, sigs)**: as in v26 with a 17-byte state.

**Ticker**: `consume()` as before (same lock, category, commitment, +1,000 sats); `recycle()`
requires input 0 to be the category's minting head and `tx.time ≥ commit[0..4) + 86400`.

**PriceGated(recipient, strike cents, category, minTime, maxTime, minK)**: reads bytes 0..4
(timestamp), 12..16 (price), 16 (k) of a 17-byte Ticker commitment.

**Migration**: a v26 head's `rotate()` requires the next commitment to start with its 13-byte
state, so the tail is four filler bytes and the table hash: the hash lands at bytes 17..37 where the
v27 covenant reads it, and bytes 8..12, where v27 reads the counter, hold the high dword of the v26
price. The first v27 update continues the counter from there. For a 72 price that dword is 6, so
the live oracle's dataSequence runs from 7. Oracles.cash consumers require only contiguity and positivity.

VM suite (`npm test`): 64 scenarios green, including the migration path, a v26 Ticker recycled by a
v27 head, and a second instance with another category consuming the same 13 statements.
`node/core` replays the update, the recycle with both Ticker generations and a top-up, the
rotation and the migration byte for byte.

---

## 4. Trust model

Unchanged in substance from v26: consensus enforces ≥ 7 distinct rows signed
`(source, timestamp, price)`, the posted value is their lower median, `k` is their count, the
timestamp increases and stays within six hours of chain time, the counter advances by one, the
head and its reserve survive, two Tickers are minted, and the table changes only by majority. A
minute signed by k rows takes ⌊(k−1)/2⌋ + 1 keys to forge; readers choose their k.

New: a statement can be consumed by any instance. That is not a weakening. The fact was always
public, and an instance is trusted by its consumers through its category and table, not through
the notaries' intent. What notaries lose is the ability to refuse service to an instance they
dislike; what the ecosystem gains is that an oracle head is permissionless.

---

## 5. Cost

Update k = 13: redeem 577 (pushed) + table 445 + signatures 835 + prices 53 + rows/ts/median/
selector 25 + input overhead 43 + head output 116 + two Ticker outputs 232 + overhead 10 =
**2,336 B**; k = 7: **1,922 B**. One update a minute: 0.028–0.034 BCH a day, Ticker float returned
after a day. A recycled Ticker adds 43 B and returns at least 792 sats plus its tolls.

---

## 6. Decisions

| # | Decision | Outcome |
|---|---|---|
| D26 | Snapshot layout | **Oracles.cash price message ‖ k.** Byte-level compatibility; no relay. |
| D27 | Price unit | **US cents** (Oracles.cash scaling 100; what exchanges quote). |
| D28 | Sequences | **messageSequence = dataSequence = covenant counter, +1 per update.** Minute numbers skip; AnyHedge-style consumers need contiguity. |
| D29 | Statement binding | **Source, timestamp, price only.** Public facts; permissionless instances. |
| D30 | Ticker lifetime | **One day.** Multi-party flows need the Ticker to outlive human signing. |
| D31 | Path to v27 | **Migration by `rotate()`**, not genesis. First live use of governance. |
| D32 | Timestamp width | **32-bit, like Oracles.cash.** Both formats need revision before 2038; ours migrates by rotation. |
| D33 | A Ticker-aware AnyHedge | **Not built** (user's call). |

---

## 7. Open items

* XO templates: a read template for the Dev Wallet, a governance template for rotations, and an
  instantiation template once the engine can build a CashTokens genesis (category = txid of input 0)
  or fix input 0 to a prepared coin.
* Notary data policy (mid-price, stale timestamps) still deferred.
* Independent rows via `rotate()`.

## 8. Deployment record (chipnet, 2026-10-25)

| | |
|---|---|
| category | `8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b` (unchanged) |
| v27 head address | `bchtest:pw5lnsau7903l6t658xtuyl2wl9lwla4ehg0yrw7npuchx42cr58gxwak92zu` (the v27 lock, shared by every v27 deployment) |
| oracle lock | `aa20a9f9c3bcf15f1fe97aa1ccbe13ea77cbf77fb5cdd0f20dde98798b9aaac0e87487` |
| Ticker lock | `76009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f75810380510193b1755168` |
| table hash | `f6118ff8061f8900a22b384f8275ea30888957de` (unchanged) |
| migration | `55bd87c63040a64fb65bcfb2efec4f3b9aa5dda14bd7c6142f782cbf72608c6b` at 15:57 UTC: 2,031 B, all 13 rows approving, from v26 head `c9a1b76d…` (minute 29882397, k 13, $275.60); the v26 builder was stopped for the minute it took |
| first v27 update | `c80b7b2f01c22804e64e93caf9c4428c7d2e72c0d42da3392d5d7a86f1cd8b65`: timestamp 1792943880 (15:58 UTC), dataSequence 7 (the v26 price 27,560,000,000 has high dword 6), k = 13, $275.60, 2,336 B, fee 2,337 sats, reserve 18,786,242 sats |
| first legacy recycle | `266661e7c89c77794567d719e3900f7235f0f82f1f7ff4bef1efb4defdf95461` at 16:09 UTC (dataSequence 18): the v27 head recycled ten v26 Tickers of 786 sats each (7,860 sats back into the reserve) in a 2,756-B update; the next update did the same. v26 Tickers were an hour old by then, v27 ones need a day |
| first XO consumer | `cb2195f4ab719844c603124fd481466f2b3294d5b575071579e673f7aeba3c46` at 16:29 UTC: a headless `@xo-cash/engine` wallet running the `xo/templates/ticker-stamp.mjs` template consumed the counter-37 Ticker ($275.31, k 13), re-emitted it with the toll (1,792 sats) and paid 5,000 sats; 377 B, fee 560 sats (`xo/tools/stamp-live.mjs`) |
| second instance, from XO | genesis `03796b8feb6fa200dfdf5aee5e998eba92c1fd9d7f9c517428b64e3960c1dc47` at 16:43 UTC (category `ba3dfff8…`, 17,680 sats, same table), minted by a headless XO engine with `xo/templates/ticker-genesis.mjs` after funding coin `ba3dfff8…:0`; first update `26bfb3e8075cfdb496eb15a101e3771f3cc9a2c09970724dee25417f1b90a330` built by `ticker-node build --once` from a second home: counter 1, k 13, $275.30 at minute 1792946640, the same statements as the production head's counter-53 update. Permissionless instantiation shown end to end; the instance is not kept running |
| majority rotation, from XO | a third instance over the 13 test keys of `v27-vectors.json` (genesis `ff9d3010304fcc94ba427fd86a050cb70b09c603f29d1c9ea2cba70f55306405`, category `5bfd04fd…`, 25,600 sats) was rotated to a 12-row table by `310fa7aacd86…` (1,651 B, 7 of 13 approvals) assembled by eight XO wallets running `xo/templates/ticker-rotate.mjs`; the template's unlocking script is byte-identical to `build_rotate`'s. Governance by majority is expressible in XO today |
