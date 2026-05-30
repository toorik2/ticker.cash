# ticker.cash

A decentralized BCH/USD ticker on Bitcoin Cash.

A 7-notary federation co-witnesses prices from 13 operator-diverse exchanges;
any publisher relays them into a covenant that commits the per-cycle median
on chain. No admin keys; the covenant is the only on-chain rule.

Live at [usd.ticker.cash](https://usd.ticker.cash). Reference docs at
[usd.ticker.cash/docs](https://usd.ticker.cash/docs).

## Layout

```
contracts/           CashScript covenants + compiled artifacts (.cash + .json)
node/                Rust runtime — operator daemon, coordinator tooling, systemd
web/                 Public dashboard (Express JSON API + static SPA)
references/          External knowledge base mirror (gitignored)
.ticker-coordinator/ Coordinator-only state (gitignored)
```

## v12 architecture

- 13 mutable `PublisherSlot` NFTs, one per `(publisher, sourceId)` pair,
  minted ONCE at genesis. After that, the slot category is closed forever by
  CashTokens consensus — no further mints possible.
- Each publisher's daemon refreshes their slot via `PublisherSlot.attest()`
  per cycle (notary sig + publisher sig + cycleSeq monotonicity check). The
  slot UTXO outpoint changes; its `(sourceId, publisherPkh)` identity does not.
- `Oracle.update()` consumes ≥ 7 slot inputs and re-emits each one unchanged
  at the matching output index. Mints 2 mutable `Ticker` NFTs per cycle for
  consumers.

See `contracts/PublisherSlot.cash` + `contracts/Oracle.cash` for the
load-bearing covenant logic.

## Runtime — `node/`

Three Rust crates, ~4 MB combined release size, 9 direct deps, 57 transitive
in `Cargo.lock`:

- `node/daemon/` → **`ticker-node`** binary — operator daemon. Runs one or
  both of:
  - `--notary`: HTTP server (`POST /sign`, `GET /health`) on `127.0.0.1:8081+slot`
  - `--publisher`: cycle loop (read oracle → attest → wait for quorum →
    race `Oracle.update`)
  - `--stats-bind ADDR:PORT`: opt-in `/stats` endpoint
- `node/ops/` → **`ticker-ops`** binary — coordinator tooling: `setup-all`,
  `dump-state`, `fund`, `send`
- `node/core/` → **`ticker-core`** library — chain layouts, tx encoder,
  CashTokens-aware sighash, cycle state machine, electrum client, identity

systemd unit templates in `node/systemd/`:
- `ticker-node-bundled@.service` (slots 0–6: notary + publisher in one process)
- `ticker-node-pub@.service` (slots 7–12: publisher only)

Operator install layout (under `$TICKER_HOME`, default `~/.ticker`):
```
~/.ticker-slot-N/
├── manifest.json     public bundle: contracts + notary pubkeys + publisher pkhs
├── notary.key        32-byte hex, mode 0600 (slots 0–6 only)
└── publisher.key     32-byte hex, mode 0600 (all slots)
```

## Quick start

### Reading the price

```
curl https://usd.ticker.cash/api/v1/price
```

On-chain (atomic): spend a `Ticker` NFT in your tx; read `price` + `lastTs`
from its 17-byte commit. Full guide at
[/docs#consume](https://usd.ticker.cash/docs#consume).

### Building from source

```
cd node && cargo build --release
ls target/release/{ticker-node,ticker-ops}
```

## Repo conventions

- `.ticker-coordinator/` — coordinator-only secrets (gitignored): `seed.hex`,
  `deploy-state.json`, `treasury-seed.hex`.
- `references/cashscript-language-reference.md` — local working aid
  (gitignored); refresh with the curl one-liner in `CLAUDE.md`.
- Federation deployment uses one box for all 13 slots (the "coordinator"
  layout). Multi-operator install is supported by the same binaries but is
  not currently in production.
