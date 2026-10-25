# contracts

Covenants of the v26 design (`docs/design/v26-plan.md`), deployed on chipnet. Compiled with
cashc 0.14.0; exercised with cashscript 0.14.0's `MockNetworkProvider` on the `BCH_2026_05` VM
target plus libauth token-consensus validation.

| File | Role | Compiled size |
|---|---|---|
| `Oracle.cash` | head covenant: `update()` verifies k notary statements against the table whose hash160 the head carries, ranks the lower median, writes `seq ‖ price ‖ k ‖ tableHash`, pins two Tickers, returns every input to the reserve less a bounded fee; `rotate()` lets a majority of rows set the next lock and commitment tail | 506 B body, 564 B redeem (the 57-B Ticker lock pushed); the same redeem for every deployment |
| `Ticker.cash` | immutable price snapshot `seq ‖ price ‖ k` (786 sats, the dust floor); `consume()` re-emit with a 1,000-sat toll, `recycle()` only inside a head spend once the Ticker's minute is an hour old | 57 B (P2S) |
| `PriceGated.cash` | reference consumer: strike, freshness window and a minimum `k` | 51 B |

```
npm install
npm run build && npm run size
npm test              # VM suite
npm run vectors       # also writes test/v26-vectors.json, replayed byte for byte by node/core
```

`npm test` builds and VM-evaluates: update k = 7 / 8 / 13 / 14 (after a rotation), update
recycling two Tickers plus a top-up, the red-team subset forgery (accepted, labeled k = 7),
consume with the toll, rotation by 7 and by 8 of 13 to a new table and to a P2PKH, PriceGated
release; and asserts rejection of: k = 6, duplicate row, row index past the table, stale seq,
statement for another exchange, statement for another deployment, forged signature, wrong or
absent median, commit price or k byte mismatch, Ticker commit mismatch, wrong table, head commit
with a changed table hash, reserve drain beyond the fee cap, extra output, Ticker at 785 or 787
sats, seq more than six hours ahead of the locktime, final sequence number, an update burning last
minute's Tickers through `consume()`, recycling a Ticker younger than an hour or outside an
update, consume without the toll / with a changed commitment / re-locked elsewhere, rotation by
6 of 13, approvals for another lock or another table, duplicate signer, changed state, second
output, and PriceGated refusing a k = 7 Ticker, a stale one, a hoarded one and a low price.

Fee policy in the suite: exactly `size + 1` sat. Measured: update 1,936 B (k = 7), 2,009 B
(k = 8), 2,375 B (k = 13), 2,600 B (k = 13 with two recycled Tickers and a top-up); rotation
1,637 B (7 approvals). Op-cost at k = 13: 619 k of 1,618 k.

`tools/live-consume.mjs` exercises the consumer path on the deployed oracle: it funds a `PriceGated`
coin from the operator key, then releases it by co-spending the newest Ticker with the toll.
`node tools/live-consume.mjs --dry-run` builds without broadcasting. It reads
`~/.ticker-node/operator.key` (or `TICKER_OPERATOR_KEY`) and never prints it.

Constants shared with `node/core/src/lib.rs`: floor 7 rows, Ticker 786 sats, toll 1,000 sats,
Ticker life 3,600 s, seq may lead median-time-past by 21,600 s, fee cap 1,000 sats + 2 per byte
of the head input's unlocking data.
