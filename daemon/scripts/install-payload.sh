# ticker.cash install payload — appended verbatim by bake-installer.ts
# after the per-operator variable definitions.
#
# Expects these vars to already be defined:
#   TICKER_OPERATOR_LABEL          — operator-supplied label, e.g. "alice"
#   TICKER_NETWORK                 — "chipnet" or "mainnet"
#   TICKER_NOTARY_SLOT             — "0".."6" or "" if not running notary
#   TICKER_PUBLISHER_SLOT          — "0".."12" or "" if not running publisher
#   TICKER_NOTARY_KEY_HEX          — 64 hex chars or "" if not running notary
#   TICKER_PUBLISHER_KEY_HEX       — 64 hex chars or "" if not running publisher
#   TICKER_MANIFEST_B64            — base64 of manifest JSON
#   TICKER_REPO_URL                — git URL to clone (e.g. github.com/toorik2/ticker.cash)
#   TICKER_REPO_REV                — git rev the installer was baked against (informational)
#
# `set -euo pipefail` is set above. Any step failing aborts the whole install.

ROLE_LABELS=()
[ -n "$TICKER_NOTARY_KEY_HEX" ]    && ROLE_LABELS+=("notary slot $TICKER_NOTARY_SLOT")
[ -n "$TICKER_PUBLISHER_KEY_HEX" ] && ROLE_LABELS+=("publisher slot $TICKER_PUBLISHER_SLOT")
ROLE_SUMMARY=$(IFS=, ; printf '%s' "${ROLE_LABELS[*]}")

echo "ticker.cash installer · operator: $TICKER_OPERATOR_LABEL"
echo "  network:  $TICKER_NETWORK"
echo "  role(s):  $ROLE_SUMMARY"
echo "  repo:     $TICKER_REPO_URL @ $TICKER_REPO_REV"
echo

# ─── [1/6] platform check ─────────────────────────────────────────────
if [ "$(uname -s)" != "Linux" ]; then
  echo "✗ this installer requires Linux + systemd; got $(uname -s)" >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "✗ systemd (systemctl) not found in PATH" >&2
  exit 1
fi
echo "[1/6] platform check                  ✓"

# ─── [2/6] node check ─────────────────────────────────────────────────
if ! command -v node >/dev/null 2>&1; then
  echo "✗ node not found in PATH. install Node ≥ 20 first (nvm recommended)." >&2
  echo "  nvm: https://github.com/nvm-sh/nvm" >&2
  exit 1
fi
NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]")
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "✗ node $NODE_MAJOR detected; need ≥ 20" >&2
  exit 1
fi
NODE_BIN_DIR=$(dirname "$(command -v node)")
echo "[2/6] node v$(node -p "process.versions.node")           ✓"

# ─── [3/6] clone or update repo ───────────────────────────────────────
TICKER_HOME="$HOME/ticker.cash"
if [ -d "$TICKER_HOME/.git" ]; then
  echo "[3/6] updating $TICKER_HOME..."
  git -C "$TICKER_HOME" fetch --quiet origin main
  git -C "$TICKER_HOME" reset --hard --quiet origin/main
else
  echo "[3/6] cloning into $TICKER_HOME..."
  git clone --quiet "$TICKER_REPO_URL" "$TICKER_HOME"
fi
LOCAL_REV=$(git -C "$TICKER_HOME" rev-parse --short HEAD)
echo "       at $LOCAL_REV (baked against $TICKER_REPO_REV)"

# ─── [4/6] npm install ────────────────────────────────────────────────
echo "[4/6] installing daemon deps (this can take 1-2 min)..."
(cd "$TICKER_HOME/daemon" && npm install --silent --no-audit --no-fund)
echo "       ✓"

# ─── [5/6] write credentials + manifest ───────────────────────────────
DOT_TICKER="$TICKER_HOME/daemon/.ticker"
mkdir -p "$DOT_TICKER"
chmod 700 "$DOT_TICKER"

if [ -n "$TICKER_NOTARY_KEY_HEX" ]; then
  printf '%s' "$TICKER_NOTARY_KEY_HEX" > "$DOT_TICKER/notary.key"
  chmod 600 "$DOT_TICKER/notary.key"
fi
if [ -n "$TICKER_PUBLISHER_KEY_HEX" ]; then
  printf '%s' "$TICKER_PUBLISHER_KEY_HEX" > "$DOT_TICKER/publisher.key"
  chmod 600 "$DOT_TICKER/publisher.key"
fi
printf '%s' "$TICKER_MANIFEST_B64" | base64 -d > "$DOT_TICKER/manifest.json"
chmod 644 "$DOT_TICKER/manifest.json"
echo "[5/6] wrote credentials + manifest to $DOT_TICKER ✓"

# ─── [6/6] systemd unit + start ───────────────────────────────────────
SYSTEMD_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_DIR"

ROLE_FLAGS=""
[ -n "$TICKER_NOTARY_KEY_HEX" ]    && ROLE_FLAGS="$ROLE_FLAGS --notary"
[ -n "$TICKER_PUBLISHER_KEY_HEX" ] && ROLE_FLAGS="$ROLE_FLAGS --publisher"

cat > "$SYSTEMD_DIR/ticker-node.service" <<EOF
[Unit]
Description=ticker.cash node — $TICKER_OPERATOR_LABEL ($ROLE_SUMMARY)
After=network.target

[Service]
Type=simple
WorkingDirectory=$TICKER_HOME/daemon
Environment=PATH=$NODE_BIN_DIR:/usr/bin:/bin
ExecStart=$TICKER_HOME/daemon/node_modules/.bin/tsx scripts/ticker-node.ts$ROLE_FLAGS
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=default.target
EOF

# Symlink the operator CLI into ~/.local/bin so the operator can run `ticker
# status`, `ticker logs -f`, etc. from any shell. Tolerates a pre-existing
# symlink (re-install / re-bake case).
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
ln -sf "$TICKER_HOME/daemon/scripts/ticker" "$LOCAL_BIN/ticker"

systemctl --user daemon-reload
systemctl --user enable --now ticker-node.service >/dev/null 2>&1 || true

# Enable lingering so the unit keeps running across logouts (best-effort;
# requires sudo on most distros, harmless if it fails).
if command -v loginctl >/dev/null 2>&1; then
  loginctl enable-linger "$USER" >/dev/null 2>&1 || true
fi

# Give the daemon a couple seconds to start so we can verify before exit.
sleep 3
if ! systemctl --user is-active --quiet ticker-node.service; then
  echo "[6/6] systemd unit installed but failed to start ✗" >&2
  echo "       inspect with:  systemctl --user status ticker-node" >&2
  echo "                      journalctl --user -u ticker-node -n 50" >&2
  exit 1
fi
echo "[6/6] systemd unit installed and active ✓"

echo
echo "your ticker.cash node is running."
echo "  ticker status        cycle + service state"
echo "  ticker logs -f       follow the daemon log"
echo "  ticker upgrade       pull latest + restart"
echo "  ticker help          all commands"
if ! echo ":$PATH:" | grep -q ":$LOCAL_BIN:"; then
  echo
  echo "note: $LOCAL_BIN is not on your PATH yet. add this to ~/.bashrc or ~/.zshrc:"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo "then 'source ~/.bashrc' (or open a new shell). until then, run the CLI as:"
  echo "  $LOCAL_BIN/ticker status"
fi
echo
echo "back up your operator key(s) NOW:"
[ -n "$TICKER_NOTARY_KEY_HEX" ]    && echo "  $DOT_TICKER/notary.key"
[ -n "$TICKER_PUBLISHER_KEY_HEX" ] && echo "  $DOT_TICKER/publisher.key"
echo "without these files, your slot becomes permanently unusable."
