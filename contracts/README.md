# contracts

Covenants of the v27 design (`docs/design/v27-plan.md`), deployed on chipnet. The v26 scripts stay under `artifacts/v26/` because the live migration spent a v26 head and the node still recycles v26 Tickers. Compiled with
cashc 0.14.0; exercised with cashscript 0.14.0's `MockNetworkProvider` on the `BCH_2026_05` VM
target plus libauth token-consensus validation.

| File | Role | Compiled size |
|---|---|---|
| `Oracle.cash` | head covenant: `update()` verifies k notary statements against the table whose hash160 the head carries, ranks the lower median in cents, writes a standard oracle price message (`timestamp ‖ counter ‖ counter ‖ price`) `‖ k ‖ tableHash`, pins two Tickers, returns every input to the reserve less a bounded fee; `rotate()` lets a majority of rows set the next lock and commitment tail | 518 B body, 574 B redeem (the 55-B Ticker lock pushed); the same redeem for every deployment |
| `Ticker.cash` | immutable 17-byte snapshot (792 sats, the dust floor); `consume()` re-emit with a 1,000-sat toll, `recycle()` only inside a head spend once the Ticker's timestamp is a day old | 55 B (P2S) |
| `PriceGated.cash` | reference consumer: strike in cents, freshness window in seconds and a minimum `k` | 53 B |

```
npm install
npm run build && npm run size
npm test              # VM suite
npm run vectors       # also writes test/v26-vectors.json, replayed byte for byte by node/core
```

`npm test` builds and VM-evaluates 64 scenarios: update k = 7 / 8 / 13 / 14 (after a rotation),
update recycling a day-old v27 Ticker with tolls plus an hour-old v26 Ticker plus a top-up, a
second oracle instance with another category consuming the same 13 statements, the red-team subset
forgery (accepted, labeled k = 7), consume with the toll, rotation by 7 and by 8 of 13 to a new
table and to a P2PKH, the migration of a v26 head into the v27 lock and its first v27 update
(counter continued from the v26 price's high dword), PriceGated release; and asserts rejection of:
k = 6, duplicate row, row index past the table, stale timestamp, counter not old + 1,
messageSequence ≠ dataSequence, statement for another exchange, forged signature, wrong or absent
median, commit price or k byte mismatch, Ticker commit mismatch, wrong table, head commit with a
changed table hash, reserve drain beyond the fee cap, extra output, Ticker at 791 or 793 sats,
timestamp more than six hours ahead of the locktime, final sequence number, an update burning last
minute's Tickers through `consume()`, recycling a Ticker younger than its lifetime or outside an
update, consume without the toll / with a changed commitment / re-locked elsewhere, rotation by
6 of 13, approvals for another lock or another table, duplicate signer, changed state, second
output, the first post-migration update with a wrong counter, and PriceGated refusing a k = 7
Ticker, a stale one, a hoarded one and a low price.

Fee policy in the suite: exactly `size + 1` sat. Measured: update 1,922 B (k = 7), 1,991 B
(k = 8), 2,336 B (k = 13), 2,561 B (k = 13 with two recycled Tickers and a top-up); rotation
1,651 B (7 approvals); migration 1,641 B. Op-cost at k = 13: 614 k of 1,581 k.

`tools/live-consume.mjs` exercises the consumer path on the deployed oracle: it funds a `PriceGated`
coin from the operator key, then releases it by co-spending the newest Ticker with the toll.
`node tools/live-consume.mjs --dry-run` builds without broadcasting. It reads
`~/.ticker-node/operator.key` (or `TICKER_OPERATOR_KEY`) and never prints it.

Constants shared with `node/core/src/lib.rs`: floor 7 rows, Ticker 792 sats, toll 1,000 sats,
Ticker life 86,400 s, timestamp may lead median-time-past by 21,600 s, fee cap 1,000 sats + 2 per
byte of the head input's unlocking data.
