# ticker.cash

A decentralized BCH price ticker on Bitcoin Cash chipnet.

13 publishers, each pinned to one operator-diverse exchange (9 USD spot
markets, 2 USDC, 2 USDT), attest prices to a covenant that commits the
per-cycle median on chain. No admin keys; the covenant is the only on-chain
rule.

Live at [usd.ticker.cash](https://usd.ticker.cash). Reference docs at
[usd.ticker.cash/docs](https://usd.ticker.cash/docs).

## Layout

```
contracts/           CashScript covenants + compiled artifacts (.cash + .json)
node/                Rust runtime — operator daemon, coordinator tooling, systemd
web/                 Public dashboard (static HTML — on-chain consumption only)
references/          External knowledge base mirror (gitignored)
.ticker-coordinator/ Coordinator-only state (gitignored)
```

## v14 architecture

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
- Cycle stride: covenant-enforced 60 s minimum
  (`Oracle.cash`: `require(newTs - prevTs >= 60)`).

See `contracts/PublisherSlot.cash` + `contracts/Oracle.cash` for the
load-bearing covenant logic.

### Version history

- **v14** (2026-05-30) — stride floor raised 30→60 s. Same `PublisherSlot`
  covenant body as v13 (still slot version byte `0x73`); new Oracle/Slot
  addresses because the Oracle bytecode changed.
- **v13** (2026-05-30) — dropped the 1-of-7 notary OR-list from
  `PublisherSlot.attest`. Slot commit version bumped `0x72` → `0x73`.

## Trust model

- **Quorum**: 7-of-13 publishers must be honest for the on-chain median to
  be honest. The covenant absorbs ≤ 6 misbehaving publishers per cycle.
- **Source-publisher pinning**: each publisher's slot is pinned to a
  specific `sourceId` at genesis. The covenant verifies
  `hash160(serverName) == sourceCNHashes[sourceId]` at every attest, so a
  publisher cannot relabel a Kraken price as Coinbase's.
- **Quote-currency mix**: 9 of 13 sources quote BCH/USD directly; 2 quote
  BCH/USDC (OKX, KuCoin) and 2 quote BCH/USDT (Bybit, HTX). The covenant
  treats all 13 as USD-equivalent for the median; both stablecoin clusters
  could depeg the same direction simultaneously and the median still lands
  in the 9-USD cluster.
- **No notary tier**. v12 carried a 1-of-7 Schnorr "notary" OR-list in
  `PublisherSlot.attest` between exchange and publisher; v13 (PR13a /
  Phase B) dropped it. In our single-operator deployment the notary tier
  added no real attacker cost beyond the publisher quorum — notaries and
  publishers shared boxes, and only one of seven notary signatures was
  required. The honest framing is "7-of-13 publisher quorum, period."
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
- `node/ops/` → **`ticker-ops`** binary — coordinator tooling: `deploy`
  (genesis ceremony), `setup-all`, `dump-state`, `fund`, `send`.
- `node/core/` → **`ticker-core`** library — chain layouts, tx encoder,
  CashTokens-aware sighash, cycle state machine, electrum client, identity.

systemd unit template in `node/systemd/`:
- `ticker-node@.service` (single template, 13 identical instances)

Per-slot install layout. The systemd unit sets
`TICKER_HOME=%h/.ticker-slot-%i`, so each instance reads from its own
directory:

```
~/.ticker-slot-N/
├── manifest.json     public bundle: contracts + publisher pkhs
└── publisher.key     32-byte secp256k1 privkey hex-encoded, mode 0600
```

The daemon binary's bare-default fallback when `$TICKER_HOME` is unset is
`$HOME/.ticker`, but production federation deployments always set the env
to a per-slot path.

## Quick start

### Reading the price

On-chain only. Spend a `Ticker` NFT in your transaction; the covenant's
17-byte NFT commitment is `0x80 | seq(4) | lastTs(4) | medianPrice(8)`
(version byte, big-endian cycle sequence, big-endian last-locktime,
big-endian price in 1e-8 USD/satoshi units). Decode `lastTs` + `price`
straight from the commit.

No off-chain JSON API. The on-chain commit is the source of truth — read
it via any BCH-aware library or explorer. Full integration guide,
including the canonical Ticker NFT category id and worked decode
examples, in [/docs §06 Integrate](https://usd.ticker.cash/docs#integrate).

### Building from source

```
cd node && cargo build --release
ls target/release/{ticker-node,ticker-ops}
```

## Repo conventions

- `.ticker-coordinator/` — coordinator-only secrets (gitignored): `seed.hex`,
  `deploy-state.json`, `treasury-seed.hex`.
- `references/cashscript-language-reference.md` — local working aid
  (gitignored). Refresh with:

  ```
  mkdir -p references
  curl -sSL https://raw.githubusercontent.com/toorik2/BCH_Knowledge_Base/main/language/language-reference.md \
    -o references/cashscript-language-reference.md
  ```

- Federation deployment uses one box for all 13 slots (the "coordinator"
  layout). Multi-operator install is supported by the same binaries but is
  not currently in production. A future multi-operator split would need to
  either reintroduce a notary-style tier or adopt real TLS attestation to
  regain the cross-operator separation that the current single-operator
  model collapses.
