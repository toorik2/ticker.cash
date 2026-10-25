# ticker.cash

A notarized BCH/USD price oracle on Bitcoin Cash. Thirteen notaries each fetch one exchange over
TLS every minute and sign the price they saw; a 506-byte covenant checks seven or more of those
signatures, takes the lower median, and writes it on chain together with **how many rows signed**,
once a minute, in one transaction. Nobody in the system chooses a number, and nobody chooses your
trust level: your contract reads the count and sets its own bar.

Live at [usd.ticker.cash](https://usd.ticker.cash) (chipnet). Reference at
[usd.ticker.cash/docs](https://usd.ticker.cash/docs). Design record in `docs/design/v26-plan.md`;
the red team that shaped it in `docs/security/red-team-2026-10-25.md`.

| Deployment (chipnet, 2026-10-25) | |
|---|---|
| category | `8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b` |
| head | [`bchtest:pwvqk78n47999y648vkpdm5r4m95rk96ezvm8yj7qaz6293zzkq6wqp0r9nnq`](https://chipnet.imaginary.cash/address/bchtest:pwvqk78n47999y648vkpdm5r4m95rk96ezvm8yj7qaz6293zzkq6wqp0r9nnq) (every v26 oracle shares this lock; the category selects ours) |
| genesis | [`1b0f8be2…25fac5af`](https://chipnet.imaginary.cash/tx/1b0f8be2749e5b4454afba5465a9815f90ce8e1edba71b563aeb2d4925fac5af) |
| table hash | `f6118ff8061f8900a22b384f8275ea30888957de` |
| manifest | [usd.ticker.cash/manifest.json](https://usd.ticker.cash/manifest.json) |

## How it works

```
exchange ──TLS (Mozilla roots)──► notary (one per row): GET <pinned path> on <pinned host>,
                                   parses the pinned field, signs once per minute:
                                     0x4e ‖ category ‖ source ‖ seq ‖ price
                                                       │
            builder (anyone) ── all rows, or ≥ 7 by second 20 ──► one transaction
                                                       in 0:  head (minting NFT, reserve)
                                                       in 1…: hour-old Tickers being recycled, top-ups
                                                       out 0: head′  commit = seq ‖ median ‖ k ‖ tableHash
                                                       out 1,2: Tickers (786 sats, P2S)  commit = seq ‖ median ‖ k
```

* **seq** is the Unix minute the notaries observed in. Consensus enforces `seq > previous` and
  `seq ≤ chain time + 6 h` (a time-mode locktime, unchanged by Faster Blocks).
* **k** is the number of rows that signed. A minute signed by k rows takes ⌊(k−1)/2⌋ + 1 keys to
  forge: 7 → 4, 11 → 6, 13 → 7. The floor is 7; the reference consumer requires 11.
* **The table is state.** Its hash160 sits in the commitment; a strict majority of rows can replace
  it, migrate the head to a successor covenant, or retire it, with no new genesis.
* **Fees** are exactly `size + 1` sat from the reserve. Updates measure 1,936 B (k = 7) to 2,375 B
  (k = 13). Tickers return to the reserve an hour after their minute, with the 1,000-sat toll every
  consumer adds.

## Layout

```
contracts/          Oracle.cash, Ticker.cash, PriceGated.cash, compiled artifacts, VM suite + byte vectors
node/               Rust workspace
  core/             commitments, statements and approvals, BCH Schnorr, exchange registry, HTTPS fetch,
                    transaction builders (replay the SDK vectors byte for byte), Electrum client
  notary/           ticker-notary: fetches one exchange, signs minute statements, signs rotation approvals
  daemon/           ticker-node: builder + recycler, genesis, rotation, status publisher
deploy/systemd/     units for an operator host (user units; the web server as a hardened system unit)
web/                static dashboard (manifest-driven, reads chain state from Fulcrum)
docs/design/        v26 record, the v25 record it supersedes, the first-principles notes
docs/security/      red team of v25 (2026-10-25)
```

## Trust model

The chain enforces: ≥ 7 distinct rows signed `(category, exchange, minute, price)`; the written
value is their lower median; `k` is their count; the minute strictly increases and stays within six
hours of chain time; the head, its category and minting capability survive; exactly two 786-sat
Tickers are minted; every input's value returns to the reserve less the Tickers and a bounded fee;
the table changes only by majority approval.

The thirteen rows read Kraken, Coinbase, Gemini, Binance (USDC), Bitstamp, Crypto.com, Bitfinex,
Gate.io, Bitget, OKX (USDC), KuCoin (USDC), Bybit and HTX; the registry in
`node/core/src/sources.rs` is append-only, so a source byte always means the same exchange.

A minute signed by all thirteen rows takes seven colluding keys to forge; one signed by seven takes
four, and the commitment says which it is. A notary never chooses a number: it validates the
exchange's certificate chain and signs what the exchange said. Builders are permissionless and hold
no keys. While ticker.cash runs all thirteen rows the honest description is "one operator who
cryptographically verified each exchange"; the design's value is that a row is light enough to hand
to an independent operator, and that the rows, not a deployer, decide who holds one.

## Build and test

```
cd node && cargo build --release --workspace && cargo test --workspace --release
cd contracts && npm install && npm test          # cashc 0.14 + VM suite on BCH_2026_05
cd contracts && npm run vectors                   # regenerates test/v26-vectors.json for the Rust tests
```

## Run

```
# one notary (source 14 = Gate.io)
ticker-notary --home ~/.ticker-notary-7 init --source 14 --category <hex> --api 0.0.0.0:7107 --operator "name"
ticker-notary --home ~/.ticker-notary-7 run

# operator: genesis once, then run (builder + recycler + status)
ticker-node keygen --network chipnet                 # fund the printed address
ticker-node genesis --reserve 40000000 --prepare     # prints the future category for the notaries
ticker-node genesis --reserve 40000000               # writes manifest.json
TICKER_PUBLISH_DIR=/path/to/web/dist ticker-node run
ticker-node status

# governance: a majority of rows approves a new table (or --retire-to ADDRESS)
ticker-node approval-request --table new-table.json
ticker-notary --home ~/.ticker-notary-N sign-rotate --old-table-hash … --next-lock … --tail … > approvals/N.json
ticker-node rotate --table new-table.json --approvals approvals/
```

Decisions and measurements are recorded in `docs/design/v26-plan.md`; the earlier evaluation of
TLSNotary and SolidCash is in `docs/design/proof-of-fetch-oracle.md`.

## License

MIT.
