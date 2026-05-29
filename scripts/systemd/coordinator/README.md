# Coordinator systemd layout (ticker.cash-vps)

The coordinator box (`ticker.cash-vps`) holds the master seed and runs all 7
notaries + 13 publishers from one seed. This directory holds the systemd
unit templates that layout uses, plus the migration script that cuts the
fleet over from the original 21-unit hand-crafted setup.

This is **coordinator-side** layout, not operator-side. Fresh operators get
a single `ticker-node.service` instance written by `daemon/scripts/install-payload.sh`
during bake-installer onboarding. The two layouts intentionally differ
because the coordinator runs N slots from one seed while an operator runs
one slot from one keyfile.

## Unit fleet (13 units)

| Unit | Slot range | Roles per unit | Notes |
|---|---|---|---|
| `ticker-node-bundled@0..6.service` | 0-6 | notary + publisher, same process | Notary HTTP server binds `127.0.0.1:8081+slot` |
| `ticker-node-pub@7..12.service` | 7-12 | publisher only | Hits the 7 notaries on `127.0.0.1:8081..8087` via the publisher's default URL list |
| `ticker-web.service` | — | web/API (`/api/v1/{price,health,stats}`) | Untouched by the migration; serves `usd.ticker.cash` + `stats.ticker.cash` |
| `ticker.slice` | — | CPU cap (180%) for all `ticker-*` units | Untouched by the migration |

Each `ticker-node-*` unit invokes `daemon/scripts/ticker-node.ts` with the
appropriate role flags plus `--slot %i`. The script lives in this repo and
is the same entry point baked-installer operators run on their boxes — so
production behavior of the coordinator and an operator differ only in
which slots run on the same host.

## Initial migration

```bash
bash scripts/systemd/coordinator/migrate.sh
```

Stops the legacy fleet in 4 waves of 5 (≥25 s apart per the
electrum-reconnect-storm guideline), disables + removes the old unit
files, installs the new templates, enables the 13 new units, and starts
them in 3 waves. Idempotent + re-runnable.

## Day-to-day ops

```bash
# Watch a slot
journalctl --user -fu 'ticker-node-bundled@2.service'
journalctl --user -fu 'ticker-node-pub@9.service'

# Restart a single slot
systemctl --user restart 'ticker-node-bundled@5.service'

# Restart everything in waves (use the same wave gap as migrate.sh)
for wave in '0 1 2 3 4' '5 6 7 8 9' '10 11 12'; do
  for s in $wave; do
    [ "$s" -lt 7 ] && systemctl --user restart "ticker-node-bundled@${s}.service" \
                   || systemctl --user restart "ticker-node-pub@${s}.service"
  done
  sleep 25
done

# Watch quorum + freshness from chain
curl -sS https://usd.ticker.cash/api/v1/stats | jq '.aggregate'
```

## What's *not* here

- `daemon/scripts/install-payload.sh` ships the operator-side
  `ticker-node.service` (single non-template unit, no slot suffix, since an
  operator's keyfile determines their slot intrinsically). That unit is
  *not* used by the coordinator and shouldn't be confused with these.
- Nothing else — `ticker-web.service` and `ticker.slice` are also captured
  in this directory so a coordinator rebuild only needs the contents of
  `scripts/systemd/coordinator/` (plus `daemon/.ticker/seed.hex` from
  off-host backup, of course).
