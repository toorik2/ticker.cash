# ticker.cash

A decentralized BCH/USD ticker on Bitcoin Cash chipnet.

A 7-notary federation co-witnesses prices from 13 operator-diverse exchanges; any publisher relays them into a covenant that commits the per-cycle median on chain. No admin keys; the covenant is the only on-chain rule.

Live at [usd.ticker.cash](https://usd.ticker.cash). Reference docs at [usd.ticker.cash/docs](https://usd.ticker.cash/docs).

## Layout

```
contracts/         CashScript covenants + compiled artifacts.
daemon/            Notary, publisher, and deploy scripts (Node + tsx).
web/               Standalone HTML + Express JSON API (Vite-free).
references/        Local copy of CashScript language reference (gitignored).
DEPLOY-V12.md      Runbook for the v12 deploy (chipnet ceremony + cutover).
```

## v12 architecture

- 13 mutable `PublisherSlot` NFTs, one per `(publisher, sourceId)` pair, minted ONCE at genesis. After that, the slot category is closed forever by CashTokens consensus — no further mints possible.
- Each publisher's daemon refreshes their slot via `PublisherSlot.attest()` per cycle (notary sig + publisher sig + cycleSeq monotonicity check). The slot UTXO outpoint changes; its `(sourceId, publisherPkh)` identity does not.
- `Oracle.update()` consumes ≥ 7 slot inputs and re-emits each one unchanged at the matching output index. Mints 2 mutable `Ticker` NFTs per cycle for consumers.
- No more `VerifiedAttestation` NFTs (and therefore no orphan accumulation). No more `TLSNotaryGateway` covenant — its notary-sig verification moved into `PublisherSlot.attest()`.

The v12 design closes the VA-orphan accumulation problem (v11 created ~8.6k orphan VAs/day) and tightens two `consume()` invariants caught by two rounds of red-team competition: full 33-byte category equality (Oracle minting-cap pin) and Oracle covenant `lockingBytecode` pin (rejects operator-genesis duplicate 0x02 NFTs).

See `contracts/PublisherSlot.cash` + `contracts/Oracle.cash` for the load-bearing covenant logic. See `DEPLOY-V12.md` for the deploy runbook.

## Quick start

### Reading the price

Off-chain (JSON):

```
curl https://usd.ticker.cash/api/v1/price
```

On-chain (atomic): spend a `Ticker` NFT in your tx; read `price` + `lastTs` from its 17-byte commit. Full guide at [/docs#consume](https://usd.ticker.cash/docs#consume).

### Running a node

```
git clone https://github.com/toorik2/ticker.cash
cd ticker.cash/daemon
npm install

# Generate a 32-byte seed (kept local, never commit)
mkdir -p .ticker
head -c 32 /dev/urandom | xxd -p -c 64 > .ticker/seed.hex
chmod 600 .ticker/seed.hex

# Point at a Fulcrum you control (chipnet)
export TICKER_ELECTRUM_HOST=127.0.0.1
export TICKER_ELECTRUM_PORT=50001

# Deploy your own instance (mints a fresh Oracle + 13 PublisherSlot NFTs + Ticker category)
npm run deploy             # plan
npm run deploy -- --broadcast

# Run a notary + publisher for slot 0
npm run ticker-node -- --notary --publisher --slot 0 \
  --notary-url http://127.0.0.1:8081 \
  --notary-url http://127.0.0.1:8082 \
  --notary-url http://127.0.0.1:8083 \
  --notary-url http://127.0.0.1:8084 \
  --notary-url http://127.0.0.1:8085 \
  --notary-url http://127.0.0.1:8086 \
  --notary-url http://127.0.0.1:8087
```

Full operator playbook at [/docs#operate](https://usd.ticker.cash/docs#operate).

## Seed management

All federation keys derive from a single 32-byte seed kept at `.ticker/seed.hex` (gitignored; never committed). Each operator generates their own seed; there is no shared key material.

Derivation is `privateKey = sha256(seed || utf8(label))`. Labels:

- `master` — hot wallet (deploy + gas)
- `notary-0..6` — 7 federation Schnorr keys (the OR-list inside `PublisherSlot.attest()`)
- `publisher-0..12` — 13 publisher wallets (one per source)

Anyone with the seed can produce any wallet. Treat it like the master secret it is: `chmod 600`, back it up off-host, never paste it into a log or share.

## Architecture in one paragraph

Publishers fetch a price from one of 13 operator-diverse exchanges, get a notary signature over `(serverName, sourceId, price, ts, cycleSeq)`, then refresh their persistent `PublisherSlot` NFT via `slot.attest()` — same UTXO identity, new commitment, monotonic cycleSeq. The covenant pins each source's CN/SAN hash and verifies the notary sig + publisher sig inside the slot refresh. Any publisher then races to broadcast `Oracle.update` consuming ≥ 7 distinct slot inputs and re-emitting each one unchanged at the matching output index. The Oracle covenant position-checks the median and emits 2 mutable `Ticker` NFTs. Consumer dApps spend a Ticker in their tx for atomic co-finality.

## License

MIT. See [LICENSE](./LICENSE).
