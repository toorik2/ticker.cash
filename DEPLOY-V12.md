# v12 deploy runbook

v12 fundamentally changes the attestation architecture: no Gateway, no VAs,
no per-cycle minting. Each publisher owns ONE persistent slot NFT minted at
genesis and rewrites its commitment in place per cycle.

## On the VPS

```bash
cd /path/to/ticker.cash/daemon

# 0. Make sure seed is present
ls .ticker/seed.hex      # 32 hex bytes, mode 0600

# 1. Plan-mode deploy (verifies wallet balances, prints planned txs)
npx tsx scripts/deploy.ts

# 2. Run real deploy (irreversible — mints Oracle 0x02 + 13 mutable slots)
npx tsx scripts/deploy.ts --broadcast

# Output: .ticker/deploy-state.json (oracle/slot/ticker addresses + categories)

# 3. Stop v11 publishers
#    (per stagger memory: ≤5 per wave, ≥20s apart, to avoid Electrum reconnect storm)
systemctl --user stop ticker-publisher@0 ticker-publisher@1 ticker-publisher@2 ticker-publisher@3 ticker-publisher@4
sleep 25
systemctl --user stop ticker-publisher@5 ticker-publisher@6 ticker-publisher@7 ticker-publisher@8 ticker-publisher@9
sleep 25
systemctl --user stop ticker-publisher@10 ticker-publisher@11 ticker-publisher@12

# 4. Update systemd units to point at the new script (was scripts/publisher.ts already
#    in the public repo — same path, new contents). Reload + start.
systemctl --user daemon-reload
for i in 0 1 2 3 4; do systemctl --user start ticker-publisher@$i; done
sleep 25
for i in 5 6 7 8 9; do systemctl --user start ticker-publisher@$i; done
sleep 25
for i in 10 11 12; do systemctl --user start ticker-publisher@$i; done

# 5. Tail logs — first cycle should attest 13 slots then close Oracle.update
journalctl --user -fu 'ticker-publisher@*'
```

## Verification

- All 13 slot UTXOs visible at `state.slotAddress` (Fulcrum)
- Oracle UTXO visible at `state.oracleAddress` with seq incrementing per minute
- `/api/v1/price` returns the new median
- No VA UTXOs accumulating anywhere (the category doesn't exist post-cutover)

## Website update (after deploy confirms)

After `.ticker/deploy-state.json` is populated, update the website addresses:

```bash
# On the VPS where the web server lives
jq '{oracle: {address, category}, ticker: {address}, slot: {address, category}}' \
   < .ticker/deploy-state.json \
   > web/server/contracts.json   # or wherever the live config is

# Restart the web server
systemctl --user restart ticker-web
```

Then update the website architecture story to drop "verified-attestation NFT"
language and describe the persistent slot model. (The CashScript source viewer
will pick up the new files from contracts/ automatically.)

## Trouble

- **`master` wallet has insufficient sats**: needs ≥ `40_000` sats (genesis
  outpoint min × 2 = 40k for both ceremonies). Top up before deploy.
- **`mempool-conflict` mid-deploy**: the script saves state between the two
  genesis txs. Re-run after a few seconds to resume.
- **Slot address mismatch in publisher**: the publisher reconstructs the
  PublisherSlot Contract from the same constructor args used at deploy. If
  the seed differs (different machine), addresses will not match. Use the
  same seed everywhere.
