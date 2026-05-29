#!/usr/bin/env bash
# Coordinator migration script — cuts the VPS over from the legacy 21-unit
# layout (7 ticker-notary-N + 13 ticker-publisher@N + 1 web + 1 slice) to
# the unified-ticker-node 13-unit layout:
#
#   ticker-node-bundled@0..6   notary + publisher in one process per slot
#   ticker-node-pub@7..12      publisher-only (notaries come from slots 0-6)
#
# Idempotent. Re-runnable. Stops and starts in waves of ≤5 with 25 s gaps
# per the electrum-reconnect-storm guideline (mass restart of >5 daemons
# sharing one Fulcrum saturates the host).
#
# Run on ticker.cash-vps:
#   bash scripts/systemd/coordinator/migrate.sh
#
# ticker-web.service and ticker.slice are NOT touched — the new units
# share the same slice as the old.
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/toorik/projects/ticker.cash}"
SYSTEMD_DIR="${SYSTEMD_DIR:-$HOME/.config/systemd/user}"
TEMPLATE_SRC="$REPO_DIR/scripts/systemd/coordinator"
WAVE_GAP=${WAVE_GAP:-25}

# ─── pre-flight ──────────────────────────────────────────────────────────

[ -f "$REPO_DIR/daemon/scripts/ticker-node.ts" ] \
  || { echo "✗ ticker-node.ts not found at $REPO_DIR/daemon/scripts/"; exit 1; }
[ -f "$TEMPLATE_SRC/ticker-node-bundled@.service" ] \
  || { echo "✗ bundled template not found at $TEMPLATE_SRC"; exit 1; }
[ -f "$TEMPLATE_SRC/ticker-node-pub@.service" ] \
  || { echo "✗ pub template not found at $TEMPLATE_SRC"; exit 1; }

echo "=== ticker.cash coordinator migration ==="
echo "repo:         $REPO_DIR"
echo "systemd dir:  $SYSTEMD_DIR"
echo

# ─── [1/6] install new templates ─────────────────────────────────────────
echo "[1/6] installing new template files..."
mkdir -p "$SYSTEMD_DIR"
cp "$TEMPLATE_SRC/ticker-node-bundled@.service" "$SYSTEMD_DIR/"
cp "$TEMPLATE_SRC/ticker-node-pub@.service"     "$SYSTEMD_DIR/"
systemctl --user daemon-reload
echo "       ✓ installed + daemon-reload"

# ─── [2/6] stop legacy units in waves of 5 ───────────────────────────────
echo "[2/6] stopping legacy units in 4 waves (≥${WAVE_GAP}s gap)..."
stop_wave() {
  local label="$1"; shift
  echo "       wave $label: $*"
  for u in "$@"; do systemctl --user stop "$u" 2>/dev/null || true; done
}
stop_wave 1 ticker-notary-0 ticker-notary-1 ticker-notary-2 ticker-notary-3 ticker-notary-4
sleep "$WAVE_GAP"
stop_wave 2 ticker-notary-5 ticker-notary-6 ticker-publisher@0 ticker-publisher@1 ticker-publisher@2
sleep "$WAVE_GAP"
stop_wave 3 ticker-publisher@3 ticker-publisher@4 ticker-publisher@5 ticker-publisher@6 ticker-publisher@7
sleep "$WAVE_GAP"
stop_wave 4 ticker-publisher@8 ticker-publisher@9 ticker-publisher@10 ticker-publisher@11 ticker-publisher@12
echo "       ✓ all legacy units stopped"

# ─── [3/6] disable legacy units (clears default.target.wants symlinks) ───
echo "[3/6] disabling legacy units..."
for i in 0 1 2 3 4 5 6; do
  systemctl --user disable "ticker-notary-${i}.service" 2>/dev/null || true
done
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12; do
  systemctl --user disable "ticker-publisher@${i}.service" 2>/dev/null || true
done
echo "       ✓ disabled"

# ─── [4/6] remove legacy unit files ──────────────────────────────────────
echo "[4/6] removing legacy unit files..."
for i in 0 1 2 3 4 5 6; do rm -f "$SYSTEMD_DIR/ticker-notary-${i}.service"; done
rm -f "$SYSTEMD_DIR/ticker-publisher@.service"
systemctl --user daemon-reload
echo "       ✓ legacy unit files removed"

# ─── [5/6] enable new units ──────────────────────────────────────────────
echo "[5/6] enabling 13 new ticker-node units..."
for s in 0 1 2 3 4 5 6;   do systemctl --user enable "ticker-node-bundled@${s}.service" 2>/dev/null; done
for s in 7 8 9 10 11 12;  do systemctl --user enable "ticker-node-pub@${s}.service"     2>/dev/null; done
echo "       ✓ 13 units enabled"

# ─── [6/6] start new units in waves ──────────────────────────────────────
echo "[6/6] starting new units in 3 waves..."
start_wave() {
  local label="$1"; shift
  echo "       wave $label: $*"
  for u in "$@"; do systemctl --user start "$u"; done
}
start_wave 1 ticker-node-bundled@0 ticker-node-bundled@1 ticker-node-bundled@2 ticker-node-bundled@3 ticker-node-bundled@4
sleep "$WAVE_GAP"
start_wave 2 ticker-node-bundled@5 ticker-node-bundled@6 ticker-node-pub@7 ticker-node-pub@8 ticker-node-pub@9
sleep "$WAVE_GAP"
start_wave 3 ticker-node-pub@10 ticker-node-pub@11 ticker-node-pub@12

# ─── verification ────────────────────────────────────────────────────────
echo
echo "=== verification (after 5 s settle) ==="
sleep 5
running_new=$(systemctl --user list-units 'ticker-node-*' --no-legend --state=running 2>/dev/null | wc -l)
legacy_remaining=$(systemctl --user list-units 'ticker-notary-*' 'ticker-publisher@*' --no-legend 2>/dev/null | wc -l)
echo "  new ticker-node-* running:      $running_new  (expect 13)"
echo "  legacy ticker-notary/publisher: $legacy_remaining  (expect 0)"
echo
echo "any failed units?"
systemctl --user list-units 'ticker-*' --no-legend --state=failed 2>/dev/null || true
echo
echo "next: watch a cycle land —"
echo "  journalctl --user -fu 'ticker-node-bundled@0' -n 20"
