# deploy

systemd units for one operator host. The notaries, the node and their CPU cap are *user* units
(`~/.config/systemd/user/`, kept alive across logouts by `loginctl enable-linger`). The web server
is a *system* unit (`/etc/systemd/system/`) that runs as its own unprivileged user.

| Unit | Scope | Runs | Paths |
|---|---|---|---|
| `ticker-notary@N.service` | user | `ticker-notary run` for table row N | `~/.ticker-notary-N/` (notary.json, notary.key, statements.jsonl) |
| `ticker-node.service` | user | `ticker-node run`: prover, builder, sweeper; publishes `manifest.json` + `status.json` into the web root | `~/.ticker-node/` (operator.key, genesis.json, manifest.json); writes `web/dist/` |
| `ticker.slice` | user | CPU cap shared by the notaries and the node | |
| `ticker-web.service` | system, `User=web` | `server/server.ts` under tsx on 127.0.0.1:3000 behind nginx; serves `web/dist/` | `~/projects/ticker.cash/web`, read-only |

Binaries live in `~/.local/bin/`. The user units run with `UMask=0077`, `ProtectHome=read-only` and an
explicit `ReadWritePaths`; the daemon re-opens its two published files as 0644 so the web user can
read them.

## Web server

The web process is the only one that talks to the internet, so it is the one that holds the least:
a system user `web` with no shell, no home directory and no keys; a read-only view of the
filesystem (`ProtectSystem=strict`, `ProtectHome=read-only`, a private `/tmp`); an empty capability
set; `Restart=always`. nginx terminates TLS and proxies usd.ticker.cash, stats.ticker.cash and
quote.layer1.cash to it; the same process answers all three.

Install on a fresh host (the unit's paths are the ticker.cash host's; a system unit cannot use `%h`):

```
sudo useradd --system --shell /usr/sbin/nologin --no-create-home web
chmod o+x /home/<operator>     # traverse only: web can reach the checkout but not list the home
# The checkout itself is world-readable (directories 755, files 644), and ticker-node publishes
# manifest.json and status.json as 0644 on purpose. No ACLs are involved.
sudo cp deploy/systemd/ticker-web.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ticker-web
```

## Host

Administration reaches the host only over Tailscale: ufw defaults to deny, allows 80 and 443 from
anywhere and 22 only on the `tailscale0` interface (plus the hosting panel's console address).
sshd accepts keys only, no passwords, no root login. fail2ban and unattended-upgrades are on.
nginx redirects HTTP to HTTPS, sends HSTS and a shared security-header snippet, and proxies each of
the three hostnames to 127.0.0.1:3000 with `Host` and `X-Forwarded-*` set; certificates come from
certbot.
