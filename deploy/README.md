# deploy

systemd units for one operator host. The notaries, the node and their CPU cap are *user* units
(`~/.config/systemd/user/`, kept alive across logouts by `loginctl enable-linger`). The web server
is a *system* unit (`/etc/systemd/system/`) that runs as its own unprivileged user.

| Unit | Scope | Runs | Paths |
|---|---|---|---|
| `ticker-notary@N.service` | user | `ticker-notary run` for table row N: fetches its exchange once a minute, signs, serves `/v1/statement` on loopback | `~/.ticker-notary-N/` (notary.json, notary.key, statements.jsonl) |
| `ticker-node.service` | user | `ticker-node run`: builder and recycler; publishes `manifest.json` + `status.json` into the web root | `~/.ticker-node/` (operator.key, genesis.json, manifest.json); writes `web/dist/` |
| `ticker.slice` | user | CPU cap shared by the notaries and the node | |
| `ticker-web.service` | system, `User=web` | `server/server.ts` under tsx on 127.0.0.1:3000 behind nginx; serves `web/dist/` | `~/projects/ticker.cash/web`, read-only |

Binaries live in `~/.local/bin/`. The user units run with `UMask=0077`, `ProtectHome=read-only` and an
explicit `ReadWritePaths`; the daemon re-opens its two published files as 0644 so the web user can
read them. A notary needs outbound 443 to its exchange and one loopback port for its statement
API; nothing connects to it from outside. The node needs outbound access to the Electrum pool.

## Cutting a deployment over (v25 → v26, 2026-10-25)

```
systemctl --user stop ticker-node 'ticker-notary@*'
mkdir -p ~/archive/v25 && mv ~/.ticker-notary-{0..12} ~/archive/v25/ && mv ~/.ticker-node/{manifest,genesis}.json ~/archive/v25/
for i in $(seq 0 12); do ticker-notary --home ~/.ticker-notary-$i init --source <id> --category <future category> --api 127.0.0.1:71$(printf %02d $i) --operator ticker.cash; done
# genesis.json: rows {row, source, pubkey (from init), operator, api}; electrum pool
ticker-node genesis --reserve 40000000 --prepare     # prints the future category first; init the notaries with it
ticker-node genesis --reserve 40000000
systemctl --user start 'ticker-notary@{0..12}' ticker-node
```

The previous head stays on chain with its reserve; v25 had no exit path. v26 does: a majority of
rows can retire a head to a P2PKH with `ticker-node rotate --retire-to ADDRESS`.

## Web server

The web process is the only one that talks to the internet, so it is the one that holds the least:
a system user `web` with no shell, no home directory and no keys; a read-only view of the
filesystem (`ProtectSystem=strict`, `ProtectHome=read-only`, a private `/tmp`); an empty capability
set; `Restart=always`. Cloudflare terminates visitor TLS and hands usd.ticker.cash,
stats.ticker.cash and quote.layer1.cash through a tunnel to nginx, which proxies them to it; the
same process answers all three.

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

The host exposes no public ports. Visitors reach the sites through a Cloudflare Tunnel: the
`cloudflared` service connects out to Cloudflare, which forwards each hostname to nginx on loopback,
and nginx proxies to ticker-web on 127.0.0.1:3000 with `Host` and `X-Forwarded-*` set; the real
visitor address comes from `CF-Connecting-IP`. Visitors see Cloudflare's edge certificate, so the
Let's Encrypt origin certificates are no longer renewed. Adding a hostname is an ingress entry in
`/etc/cloudflared/config.yml`, a restart of `cloudflared` and a proxied CNAME to the tunnel.

Administration reaches the host only over Tailscale: ufw defaults to deny and allows 22 only on
the `tailscale0` interface (plus the hosting panel's console address). sshd accepts keys only, no
passwords, no root login. fail2ban and unattended-upgrades are on. nginx sends HSTS and a shared
security-header snippet, hides its version and allows TLS 1.2 and 1.3 only.
