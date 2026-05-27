# ticker.cash

A decentralized BCH/USD ticker on Bitcoin Cash chipnet.

A 7-notary federation co-witnesses prices from 13 operator-diverse exchanges; any publisher relays them into a covenant that commits the per-cycle median on chain. No admin keys; the covenant is the only on-chain rule.

Live at [usd.ticker.cash](https://usd.ticker.cash). Reference docs at [usd.ticker.cash/docs](https://usd.ticker.cash/docs).

## Layout

```
contracts/         CashScript covenants + compiled artifacts.
daemon/            Notary, publisher, and deploy scripts (Node + tsx).
web/               Standalone HTML + Express JSON API (Vite-free).
```

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

# Deploy your own instance (mints a fresh Gateway + Oracle)
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
- `notary-0..6` — 7 federation Schnorr keys (the Gateway's OR-list)
- `publisher-0..12` — 13 publisher wallets (one per source)

Anyone with the seed can produce any wallet. Treat it like the master secret it is: `chmod 600`, back it up off-host, never paste it into a log or share.

## Architecture in one paragraph

Publishers fetch a price from one of 13 operator-diverse exchanges, get a notary signature over `(serverName, sourceId, price, ts, cycleSeq)`, mint a `VerifiedAttestation` NFT through the `TLSNotaryGateway` covenant (which pins each source's CN/SAN hash and verifies the notary sig + publisher sig), then race to broadcast `Oracle.update` consuming ≥ 7 distinct VAs. The Oracle covenant position-checks the median and emits four mutable `Ticker` NFTs. Consumer dApps spend a Ticker in their tx for atomic co-finality.

## License

MIT. See [LICENSE](./LICENSE).
