# contracts

Covenants of the v25 design (`docs/design/v25-plan.md`), deployed on chipnet. Compiled with
cashc 0.14.0; exercised with cashscript 0.14.0's `MockNetworkProvider` on the `BCH_2026_05` VM
target plus libauth token-consensus validation.

| File | Role | Compiled size |
|---|---|---|
| `Oracle.cash` | head covenant: verifies k notary statements, lower median, monotonic seq, output pins, fee reserve | 373 B body (850 B redeem with the 442-B notary table and the Ticker lock pushed) |
| `Ticker.cash` | immutable price snapshot (708 sats, the dust floor); `consume()` re-emit, `sweep()` after 144 legacy units (~1 day) | 31 B (P2S) |
| `PriceGated.cash` | reference consumer | see `npm run size` |

```
npm install
npm run build && npm run size
npm test
```

`npm test` builds and VM-evaluates: update k=7/8/13, sweep, consume; and asserts rejection of:
quorum 6, duplicate row, stale seq, statement for another exchange (source byte), statement for
another deployment (category), forged signature, wrong median, commit/median mismatch, ticker commit
mismatch, reserve drain, extra output, ticker at 709 sats (overpaid dust), early sweep, consume with value changed.

Fee policy in the suite: exactly `size + 1` sat. Measured updates: 1,701 B (k = 7), 1,774 B (k = 8), 2,140 B (k = 13).

Decisions applied: D1 no rotation path (table is a constructor constant); D3 reserve-funded head;
D11 source byte per table row and in every signed statement. `seq` is a u32 Unix minute.
