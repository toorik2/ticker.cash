# ticker.cash

A notarized BCH/USD price oracle on Bitcoin Cash. Thirteen independent notaries each verify a
TLS session with one exchange and sign the price they saw; a 373-byte covenant checks seven or
more of those signatures, takes the lower median, and writes it on chain once a minute, in one
transaction. Nobody in the system chooses a number.

Live at [usd.ticker.cash](https://usd.ticker.cash) (chipnet). Reference at
[usd.ticker.cash/docs](https://usd.ticker.cash/docs). Design record in `docs/design/`.

## How it works

```
exchange ──TLS 1.2──► prover ◄──MPC-TLS / proxy──► notary (row r)
                                                      │ validates the certificate chain,
                                                      │ requires full disclosure, pins
                                                      │ GET <path> on <host>, parses the
                                                      │ price, signs once per minute:
                                                      │   0x4e ‖ category ‖ r ‖ source ‖ seq ‖ price
                                                      ▼
               builder (anyone) ── ≥ 7 statements, same minute ──► one transaction
                                                                     in 0: head (minting NFT, reserve)
                                                                     out 0: head′  commit = seq ‖ median
                                                                     out 1,2: Tickers (708 sats, P2S)
```

* **seq** is the Unix minute the notaries observed in. Consensus enforces only `seq > previous`;
  there is no timestamp, block height or timelock in the Oracle. That makes it indifferent to the
  Faster Blocks upgrade (May 2027), which redefines legacy lock units.
* **Fees** are exactly `size + 1` sat; the head pays them from its reserve (at most 5,000 sats per
  update). Updates measure 1,701 B (k = 7) to 2,140 B (k = 13).
* **Tickers** carry the same 12-byte commitment; consumers co-spend one and re-emit it. Anyone may
  sweep a Ticker after 144 legacy relative-lock units (about a day).

## Layout

```
contracts/          Oracle.cash, Ticker.cash, PriceGated.cash, compiled artifacts, VM test suite
node/               Rust workspace
  core/             commits, statements, BCH Schnorr, exchange registry, transaction builders, Electrum client
  notary/           ticker-notary: TLSNotary verifier for one row, signs minute statements
  daemon/           ticker-node: prover, builder, sweeper, genesis
deploy/systemd/     user-mode units for an operator host
web/                static dashboard (manifest-driven, reads chain state from Fulcrum)
docs/design/        v25 plan and the first-principles record behind it
```

## Trust model

The chain enforces: ≥ 7 distinct rows signed `(category, row, exchange, minute, price)`; the
written value is their lower median; the minute strictly increases; the head, its category and
minting capability survive; exactly two 708-sat Tickers are minted; the reserve drops by at most
5,000 sats per update.

The thirteen rows read Kraken, Coinbase, Gemini, Binance (USDC), Bitstamp, Crypto.com, Bitfinex,
Gate.io, Bitget, OKX (USDC), KuCoin (USDC), Bybit and HTX; the registry in
`node/core/src/sources.rs` is append-only, so a source byte always means the same exchange.

Forging the price takes seven of thirteen notaries. A notary never chooses a number: it is a
TLSNotary verifier that validates the exchange's certificate chain and signs what the exchange
said. Provers and builders are permissionless and hold no keys. While ticker.cash runs all
thirteen rows the honest description is "one operator who cryptographically verified each
exchange"; the design's value is that a row is light enough to hand to an independent operator.

## Build and test

```
cd node && cargo build --release --workspace && cargo test --workspace --release
cd contracts && npm install && npm test          # cashc 0.14 + VM suite on BCH_2026_05
```

## Run

```
# one notary (row 7 = Gate.io, registry id 14)
ticker-notary --home ~/.ticker-notary-7 init --row 7 --source 14 --category <hex> \
    --listen 0.0.0.0:7007 --api 0.0.0.0:7107 --mode both --operator "name"
ticker-notary --home ~/.ticker-notary-7 run

# operator: genesis once, then run (prover + builder + sweeper)
ticker-node keygen --network chipnet                 # fund the printed address
ticker-node genesis --reserve 40000000 --prepare     # prints the future category for the notaries
ticker-node genesis --reserve 40000000               # writes manifest.json
TICKER_PUBLISH_DIR=/path/to/web/dist ticker-node run
ticker-node status
```

Decisions and measurements are recorded in `docs/design/v25-plan.md`; the earlier evaluation of
TLSNotary and SolidCash is in `docs/design/proof-of-fetch-oracle.md`.

## License

MIT.
