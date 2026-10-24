# deploy

User-mode systemd units for one operator host (`~/.config/systemd/user/`):

| Unit | Runs | Home |
|---|---|---|
| `ticker-notary@N.service` | `ticker-notary run` for table row N | `~/.ticker-notary-N/` (notary.json, notary.key, statements.jsonl) |
| `ticker-node.service` | `ticker-node run`: prover, builder, sweeper; publishes `manifest.json` + `status.json` into the web root | `~/.ticker-node/` (operator.key, genesis.json, manifest.json) |
| `ticker-web.service` | the static site (`web/`) on 127.0.0.1:3000 behind nginx | `~/projects/ticker.cash/web` |
| `ticker.slice` | CPU cap shared by all of the above | |

Binaries live in `~/.local/bin/`. Every unit runs with `UMask=0077`, `ProtectHome=read-only` and an
explicit `ReadWritePaths`; the daemon re-opens its two published files as 0644.
