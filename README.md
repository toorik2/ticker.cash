# ticker.cash

A decentralized BCH/USD ticker on Bitcoin Cash.

13 publishers, each pinned to one operator-diverse exchange, attest prices to
a covenant that commits the per-cycle median on chain. No admin keys; the
covenant is the only on-chain rule.

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

## v13 architecture

- 13 mutable `PublisherSlot` NFTs, one per `(publisher, sourceId)` pair,
  minted ONCE at genesis. After that, the slot category is closed forever by
  CashTokens consensus — no further mints possible.
- Each publisher's daemon fetches its pinned source over TLS and refreshes
  its slot via `PublisherSlot.attest()` per cycle (publisher sig +
  cycleSeq monotonicity check + CN-hash binding). The slot UTXO outpoint
  changes; its `(sourceId, publisherPkh)` identity does not.
- `Oracle.update()` consumes ≥ 7 slot inputs and re-emits each one unchanged
  at the matching output index. Mints 2 mutable `Ticker` NFTs per cycle for
  consumers.

See `contracts/PublisherSlot.cash` + `contracts/Oracle.cash` for the
load-bearing covenant logic.

## Trust model

- **Quorum**: 7-of-13 publishers must be honest for the on-chain median to
  be honest. The covenant absorbs ≤ 6 misbehaving publishers per cycle.
- **Source-publisher pinning**: each publisher's slot is pinned to a
  specific `sourceId` at genesis. The covenant verifies
  `hash160(serverName) == sourceCNHashes[sourceId]` at every attest, so a
  publisher cannot relabel a Kraken price as Coinbase's.
- **No notary tier**. v12 carried a 7-key Schnorr "notary" federation
  between exchange and publisher; v13 (PR13a / Phase B) dropped it. In our
  single-operator deployment the notary tier added no real attacker cost
  beyond the publisher quorum — notaries and publishers shared boxes, and
  the covenant only required a 1-of-7 notary signature. The honest framing
  is "7-of-13 publisher quorum, period."
- **Forward compatibility**: if TLSNotary reaches a stable release with
  public notary services (it was still alpha at v13 design time), real
  cryptographic source attestation can be added later as a per-publisher
  off-chain artifact without another covenant migration.

## Runtime — `node/`

Three Rust crates, ~4 MB combined release size, sync I/O, no tokio:

- `node/daemon/` → **`ticker-node`** binary — operator daemon. Single mode:
  - `--publisher`: cycle loop (read oracle → fetch price → attest → wait
    for quorum → race `Oracle.update`)
  - `--stats-bind ADDR:PORT`: opt-in `/stats` endpoint
- `node/ops/` → **`ticker-ops`** binary — coordinator tooling: `setup-all`,
  `dump-state`, `fund`, `send`
- `node/core/` → **`ticker-core`** library — chain layouts, tx encoder,
  CashTokens-aware sighash, cycle state machine, electrum client, identity

systemd unit template in `node/systemd/`:
- `ticker-node@.service` (single template, 13 identical instances)

Operator install layout (under `$TICKER_HOME`, default `~/.ticker`):
```
~/.ticker-slot-N/
├── manifest.json     public bundle: contracts + publisher pkhs
└── publisher.key     32-byte hex, mode 0600
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
  not currently in production. A future multi-operator split would need to
  reintroduce a notary tier (or adopt real TLS attestation) to regain the
  cross-operator separation that v13's single-operator model collapses.
