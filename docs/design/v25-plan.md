# ticker.cash v25 — Proof-of-Fetch: every minute, one transaction

Status: **superseded by v26** (`v26-plan.md`, 2026-10-25) after the red team of the same day. Was deployed on chipnet 2026-10-24 (record in §12). Supersedes v24. Covenants and
the test suite live in `contracts/`; the exchange registry in `node/core/src/sources.rs`.
Background and the evaluation of SolidCash / TLSNotary are in `proof-of-fetch-oracle.md`.

---

## 0. The design in one screen

* **Thirteen notaries, zero publishers, zero slots.** Each notary runs the TLSNotary *Verifier* against
  one pinned exchange endpoint, validates the exchange's certificate chain itself, reads the revealed
  price bytes, and signs a 39-byte statement with secp256k1 Schnorr. It never chooses a number.
  Anyone may be the **prover** that opens the session, and anyone may be the **builder** that posts the
  update. There is no privileged writer anywhere in the protocol.
* **Cadence = the Unix minute.** `seq = floor(unix_time / 60)`. A notary signs at most one statement per
  `(row, seq)`. Builders post whenever a block comes. On 1-minute BCH this is one update per block; on
  10-minute BCH it is a short unconfirmed chain. The covenant enforces only `seq > previous`.
  No timestamps, no block heights, no CLTV, no CSV anywhere in the Oracle, which also makes it immune to
  Faster Blocks' redefinition of legacy locktime units.
* **One transaction per update.** Input 0 is the Oracle head; outputs are exactly the head plus `K = 2`
  Tickers. The head carries a BCH reserve and pays its own fees (`out.value >= in.value - 5000`), so an
  update needs no funder input and no change output.
* **Two covenants, 404 bytes of logic.** `Oracle.cash` 373 B (P2SH-32; the 442-byte notary table and the
  Ticker lock are constructor constants), `Ticker.cash` 31 B (P2S). The head's state is a 12-byte
  commitment, `seq(4) ‖ price(8)`, identical to a Ticker's. The notary set is fixed at genesis (D1: no
  rotation path); each table row names its exchange (D11), and the notary signs that exchange id.
* **Tickers are immutable, 12-byte snapshots that clean themselves up.** `seq ‖ price`, 708 sats (the
  exact dust floor of an 88-byte P2S token output), P2S. Anyone may sweep one after 144 legacy
  relative-lock units (one day before and after Faster Blocks); the sweep is an 86-byte transaction that
  nets ~620 sats, so the dust recycles itself.
* **Nothing is overpaid.** Fee is exactly `size + 1` sat (the size is known before building: the Oracle
  input carries no transaction signature and Schnorr signatures are fixed-width); Ticker value is the
  dust floor to the sat; `seq` is 4 bytes; every optional byte was measured and kept only if it paid.
* **The Oracle reads no foreign inputs.** Its only introspection targets are its own input and its own
  outputs. The entire V22-OC-22 class (unpinned foreign input) is structurally absent.

| Measured (cashscript 0.14 MockNetworkProvider, `BCH_2026_05`, libauth token validation) | v24 on chipnet (until 2026-10-24) | v25 |
|---|---|---|
| Transactions per update | 14 (13 attests + update) | **1** |
| Bytes per update | 13 × 589 + 3,620–4,458 ≈ **12.0 KB** | **1,701 B** (k = 7) … **2,140 B** (k = 13) |
| Updates per day | 1,057 measured (60-s stride, misses) | 1,440 (one per minute) |
| Fee per day (fee = size + 1) | ≈ 12.7 M sats ≈ 0.127 BCH | ≈ 2.45–3.08 M sats ≈ 0.025–0.031 BCH |
| Dust parked per day | 2 × 1,500 × 1,057 ≈ 3.2 M sats, unrecoverable | 2 × 708 × 1,440 ≈ 2.0 M sats, **recycled by sweeps** (≈ 0.12 M sats of sweep fees) |
| Op-cost used | — | 32 % (k = 7) … 46 % (k = 13) of the input budget, no padding |
| Covenant bytes | 497 + 167 + ~60 | **373 + 31** |
| NFT categories / closed-category invariants | 2 / 1 | 1 / 0 |
| Deploy-time literal substitution sites | 3 | 0 (two constructor arguments: table, Ticker lock) |

At BCH ≈ $290 that is roughly **$7.5–9.3 per day, sweeps included,** for 1,440 notarized updates, against ≈ $37 per day
for v24's 1,057 un-notarized ones.

---

## 1. Facts this plan is built on (verified 2026-10-24)

**Faster Blocks (CHIP-2025-03).** Target 600 s → 60 s. Activation: chipnet at MTP 1794744000
(2026-11-15 12:00 UTC); mainnet, testnet4, scalenet at MTP 1810382400 (2027-05-15 12:00 UTC). The
endorsement / lock-in window is open now; bitjson supports it but had not formally endorsed as of the
forum threads. A tempnet (`tempnet.chaingraph.cash`, bitjson plus volunteers) runs until 15 Nov, then
chipnet itself switches. Consensus mechanics that matter to us:

* Ticks: 600 per block before activation, 60 after. **Legacy height-mode `nLockTime` and block-mode
  `nSequence` are evaluated in 600-tick chunks** ("N units = 600N ticks"), so `CSV 1` means ~10
  one-minute blocks and `OP_CHECKLOCKTIMEVERIFY` keeps 10-minute granularity. **No new opcodes or
  fields.** Time-mode locks are unchanged. MTP window shrinks to ~10 minutes; tempnet measured block
  timestamps a median 335 s ahead of MTP. Coinbase maturity 60,000 ticks; finalization ≈ 121 blocks.
* Consequence: a per-block cadence **cannot** be enforced with a 1-block relative lock after May 2027.
  v25 therefore enforces cadence socially (one statement per row per minute) and consensus enforces
  only monotonicity. The design works identically before and after activation, and even if the CHIP
  fails to lock in.

**TLSNotary** (`tlsn` v0.1.0-alpha.15, 2026-05-21): live Verifier model; the notary server was removed
in alpha.13; MPC-TLS default, proxy mode new; TLS 1.2 only; the Verifier validates the server
certificate chain against a root store and returns `server_name` (`crates/tlsn/src/verifier.rs`,
`verifier/verify.rs`). All 13 pinned exchange hosts negotiate TLS 1.2 ECDHE + AES-128-GCM today.

**CashVM 2026** (active on mainnet since 2026-05-15): loops, functions, bitwise, P2S standard (201-B
locking bytecode), 10,000-B unlocking bytecode standard, 128-B token commitments, op-cost budget
`(41 + unlockingBytes) × 800`, `OP_CHECKDATASIG` = 26,100 op-cost. Note: libauth 3.0.0's
`verifyTransactionTokens` still enforces the 2023 40-byte commitment limit; v25's 12-byte commit is
valid under both.

**v24 on chipnet.** Attest tx 589 B / ~638 sats; `Oracle.update` 3,620–4,458 B / 3,669–4,508 sats with
9–12 slots; ~1,057 updates per day. The live deployment's last confirmed update is block 316,028
(2026-07-25); chipnet tip at measurement was 329,273.

---

## 2. Question everything: v24 component by component

| v24 piece | v25 verdict | Why |
|---|---|---|
| 13 `PublisherSlot` UTXOs, 13 attest txs, 26 slot emissions per cycle | **Deleted** | Statements travel inside the update's unlocking script (73 B each). The slot existed to give attestations a place to land and to carry `cycleSeq`; a signed `(row, seq)` does both for free. |
| Publisher keys, pkh literals, HD seed, manifests | **Deleted** | Provers hold no key. The only keys in the system are the 13 notary keys in the table. |
| `cnHash` / `serverName` binding in the slot | **Moved to the notary** | The tlsn Verifier validates the certificate chain; our notary additionally pins host, path, status line and the JSON key before it signs. |
| Slot category, closed-category invariant, F01 per-iteration category pin | **Gone** | The Oracle introspects no foreign inputs. |
| Timestamp votes (`±120 s`, lower/upper counts), `newTs - prevTs >= 60` | **Gone** | `seq` is the Unix minute agreed by the signing notaries; consensus checks only `seq > old`. |
| `claimedMedian` + second counting loop | **One loop** | Signature check and median counting share the per-row loop; the lower median is unique for even k. |
| `budgetPad` | **Gone** | 30–43 % of op-cost used at k = 7…13. |
| Funder input + change output on `Oracle.update` | **Gone** | The head carries a reserve; `out[0].value >= in.value - 5000`. Top-ups ride on any update by adding an input. |
| `Oracle` P2SH-32 redeem 497 B revealed per cycle | **453 B** | Does more (13 sigchecks, rotation) with fewer bytes. |
| Mutable Tickers, 17/19-B commit with version byte, 1,500 sats, perpetual dust, P2SH-32 | **Immutable, 12-B commit, 708 sats (dust floor), sweepable, P2S 31 B** | Sweep is an 86-B tx; dust recycles; P2S saves 35-B hashes on creation and the redeem reveal on every spend. |
| Output-count caps and token-leak guards on Ticker | **Dropped** | An immutable NFT cannot be forged or multiplied; the Oracle pins exactly 1 + K outputs with full token fields. |
| Version bytes (`0x80`) | **Gone** | Capability and locking bytecode already distinguish head from Ticker. |
| Re-genesis to change the signer set | **Kept** (D1: no rotation) | A 9-of-13 rotation branch was drafted and measured at 75 B; deferred to keep the covenant to a single path. The notary table is a constructor constant. |
| Rust cycle state machine, identity, slot specialization pipeline (`specialize_slot_body`), 201-B wall tests | **Replaced** | Three small roles (notary, prover, builder) and a stateless codec crate. |
| `web/` dashboards reading slots | **Rewritten** | Decode the 33-B head commit; P2S Ticker scripthash subscriptions; notary registry view. |

---

## 3. Protocol

### 3.1 Roles

| Role | Count | Holds | Trusted for | Who can run it |
|---|---|---|---|---|
| Notary | 13 (one per table row) | a secp256k1 key listed in the table; a tlsn Verifier | signing only what it verified; one statement per minute per row; its clock | independent BCH infrastructure operators |
| Prover | any number | nothing | nothing (liveness only) | anyone; ticker.cash runs several |
| Builder | any number | a few sats optional (top-ups) | nothing (first-seen race) | anyone |
| Sweeper | any number | nothing | nothing | anyone (profitable) |

### 3.2 Statement

```
message   = 0x4e ‖ category(32, VM byte order) ‖ row(1) ‖ source(1) ‖ seq(4, u32 LE) ‖ price(8, u64 LE)   (47 B)
signature = BCH Schnorr(secp256k1) over sha256(message), 64 B, CHECKDATASIG-compatible
table     = 13 × (pubkey(33) ‖ source(1)) = 442 B, a constructor constant of the Oracle (D11)
```

Nothing of the statement is stored on chain except the 8-byte price it carries; the Oracle rebuilds
the message from its own category, the row byte, the source byte it reads from the table entry, `seq`
and the supplied price. A notary therefore signs which exchange it watched, and the chain records it.

### 3.3 One minute in the life of the oracle

1. At second ~2 of minute `m`, every prover opens an MPC-TLS (or proxy-mode) session for each row it
   serves: `GET <pinned path>` to `<pinned host>` through that row's notary.
2. The notary's tlsn Verifier validates the certificate chain and the handshake, learns `server_name`,
   and receives the prover's selective disclosure: the full request line and `Host:` header, the
   status line, and the byte range holding the pinned JSON key and its value.
3. The notary checks `server_name`, request, `200`, parses the decimal into 1e-8 USD, checks
   `|now - 60·m| < 90 s`, refuses if it already signed `(row, m)`, signs, stores, and returns
   `(row, m, price, sig)` over HTTP (`GET /v1/statement?seq=m`).
4. A builder with ≥ 7 statements for the same `m` posts the update: input 0 = head, output 0 = head
   with commit `m ‖ lowerMedian`, outputs 1–2 = Tickers with the same commit.
5. When a block arrives slower than a minute, the next minute's update simply spends the unconfirmed
   head (BCHN has no chained-transaction limit). A builder may also skip minutes and post only the
   latest; `seq > old` is the only rule. On 1-minute blocks this converges to one update per block.
6. Sweepers reclaim Tickers older than 144 units in 86-byte transactions.

### 3.4 Builder algorithm

```
on new statement set S_m (≥ 7 rows, equal m, m > head.seq):
  sort by row; choose k = |S_m| (cap 13); median = k-th-lowest with (k-1)/2 below
  tx: in[0] = head (sequence 0xffffffff, no locktime)
      out[0] = head', value = in.value - (size + 1) - K·708    (≥ in.value - 5000)
      size is exact before building: no transaction signature on the Oracle input, Schnorr is fixed-width
      out[1..K] = Ticker(m, median), 708 sats each (the dust floor, pinned exactly)
  broadcast; on conflict (another builder won) discard and wait for m+1
  optional: add a P2PKH input to top up the reserve (out[0].value may exceed in.value)
```

Reorgs: statements are keyed by minute, not block hash, so an update orphaned by a reorg is simply
rebroadcast unchanged.

### 3.5 Changing the notary set

There is no rotation path (D1). The table is a constructor constant of the Oracle, so a new notary set
is a new genesis, as in v24. The 9-of-13 rotation branch that was drafted measured 75 bytes and stays
in the draft's history if it is ever wanted.

---

## 4. Covenants (`contracts/`)

### 4.1 `Oracle.cash` (373 B body; 850 B redeem with the 442-B table and the 31-B Ticker lock pushed)

Constructor `(table, tickerLock)`. State: `seq(4) ‖ price(8)` = 12 B. Function `update(seq, rows, prices, sigs, median)`:

1. `seq.length == 4` and `int(seq) > int(commit[0..4))`.
2. `k >= 7`, `prices.length == 8k`, `sigs.length == 64k`, `median.length == 8`.
3. Loop over `k` rows: rows strictly ascending (distinctness; a row ≥ 13 fails the table slice);
   `entry = table[row]` (pubkey ‖ source); `checkDataSig(sig_i, 0x4e ‖ cat ‖ row_i ‖ source_i ‖ seq ‖ price_i, pubkey_i)`;
   count `below / above / equal` against the claimed median in the same pass.
4. `found`, `below <= (k-1)/2`, `above <= k/2` (unique lower median).
5. `outputs.length == 3`. Head re-emitted at output 0 with the same locking bytecode and full token
   category (minting capability kept), commit `seq ‖ median`, `tokenAmount == 0`.
6. Outputs 1–2 are Tickers at the pinned lock, same category (32 B, no capability = immutable), the same
   12-byte commit, `tokenAmount == 0`, value `== 708` (pinned exactly: a `>=` would let a builder siphon
   the reserve into Tickers it later sweeps).
7. `out[0].value >= in.value - 5000`.

### 4.2 `Ticker.cash` (31 B, P2S)

`consume()`: output at the same index has the same locking bytecode, same category, same value.
`sweep()`: `this.age >= 144` (legacy units: 600 ticks each, so one day before and after Faster
Blocks); the NFT is burned implicitly and the dust is reclaimed.

### 4.3 `PriceGated.cash` (41 B) — reference consumer

Input 1 must be a Ticker at the pinned lock and category; requires `minSeq <= seq <= maxSeq` and
`price >= strike`. The `maxSeq` ceiling is the v23 F02 lesson carried forward.

### 4.4 VM results (`npm test` in `contracts/`)

| Scenario | Result |
|---|---|
| update k = 7 / 8 / 13 | accepted; 1,701 / 1,774 / 2,140 B (analytic byte count matches); op-cost 369 k / 419 k / 679 k of 1.14 M / 1.20 M / 1.49 M; tokens valid |
| ticker sweep after 144 units, NFT burned | accepted; 86 B; tokens valid |
| ticker consume with P2PKH funder | accepted; tokens valid |
| quorum 6; duplicate row; stale seq; statement for another exchange (source byte); statement for another deployment (category); forged signature; wrong median; commit ≠ median; ticker commit mismatch; reserve drain > 5000; extra output; ticker at 709 sats (overpaid dust); sweep at 143; consume with value changed | all rejected by the covenant at the expected `require` |

What the suite does not cover yet: a node-level relay test (standardness, dust, chained updates) on
chipnet; `MockNetworkProvider` applies script and token rules only.

---

## 5. Trust model

**What consensus enforces.** ≥ 7 distinct table rows signed the same `(category, seq, price_i)`;
the posted value is the lower median of those prices; `seq` strictly increases; the head, its
category, its minting capability and its reserve survive; exactly `K` Tickers with the posted value
are minted; the notary set cannot change at all (a new set is a new genesis).

**What notaries are trusted for.** Not colluding beyond 6 of 13 (price integrity), not signing twice
per minute (selection resistance), honest clocks (`seq` semantics), and availability (liveness
needs 7 of 13 up). Each notary verifies the exchange's TLS session itself; a notary cannot be fed a
fake exchange because the certificate chain and handshake are validated against public roots, and in
MPC mode the prover never holds the session keys.

**What nobody is trusted for.** Choosing which observations exist (one per row per minute), building
the transaction (anyone), funding it (the head pays), or operating the chain's cadence.

| Threat | Outcome |
|---|---|
| ≤ 6 notaries lie or go rogue | absorbed by the lower median |
| 7+ notaries collude | price corrupted (same bound as v24's 7-of-13 publishers), undetectable on chain; the residual of every Family-B oracle; mitigations: heterogeneous attestation (MPC vs proxy vs TEE rows), bonds + equivocation slashing (phase 2), more rows |
| Notary signs two prices for one minute | builder can pick; cheap to prove on chain → `NotaryBond` slash (phase 2). Honest notaries never do it; the window is one minute |
| Builder posts an older minute that is still `> head.seq` | legal; bounded by other builders racing to post the latest (first-seen); visible to consumers via `seq` |
| Reserve griefing | impossible without 7 valid statements; a colluding 7 can at most spend 5,000 sats per update it is entitled to make anyway |
| Exchange outage or TLS 1.3-only migration | that row stops; 12 remain; rotate the row if permanent (watch: tlsn is TLS 1.2 only) |
| Reorg | statements survive; rebroadcast |
| Faster Blocks fails to lock in | nothing changes: minute cadence, unconfirmed chains inside 10-minute blocks |
| Deep clock skew at a notary | its statements fall outside builders' current minute; liveness only |

Honest caveat, unchanged from v24: if ticker.cash runs all 13 notaries, the trust model is "one
operator who at least cryptographically verified each exchange". The step change happens when rows are
handed to independent operators, and v25 makes that hand-off a 30-minute job: a notary has no slot key,
no funds, no exchange account, no on-chain footprint.

---

## 6. Cost model

**Fee policy: exactly `size + 1` sat, never a rate estimate.** The update's serialized size is known
before it is built (the Oracle input has no transaction signature; Schnorr data signatures are 64 B;
every push width is fixed), so the builder sets `out[0].value = in.value − (size + 1) − 2 × 708`.
The covenant's 5,000-sat cap is a ceiling, not a payment: it leaves headroom for ≈ 2.1 sat/B at k = 7
and ≈ 1.7 sat/B at k = 13 before a re-genesis would be needed.

| Where the bytes go (k = 7 / 13) | Bytes | Note |
|---|---|---|
| redeem script (373 B covenant + 442 B table + 31 B lock + pushes) | 850 | revealed every update; the floor for 13 full pubkeys |
| 13 / 13 Schnorr signatures | 448 / 832 | 64 B each |
| prices | 56 / 104 | u64 1e-8 USD; u48 in 1e-6 USD would save 14–26 B here and 6 B in commits (D12) |
| rows + seq + claimed median + pushes | 26 / 32 | a 1-byte median index was measured: +16 B redeem for −8 B unlocking, rejected |
| input overhead (outpoint, sequence, varint) | 43 | |
| head output (P2SH-32 + 12-B token prefix) | 91 | |
| 2 Ticker outputs (P2S 31 B + token prefix) | 174 | 87 B each; K = 1 saves 87 B and 708 sats of float per update (D13) |
| tx overhead | 10 | |
| **total** | **1,701 / 2,140** | measured and analytic counts agree |

| Per day at 1,440 updates | k = 7 | k = 13 |
|---|---|---|
| Update fees (`size + 1`) | 2.45 M sats | 3.08 M sats |
| Ticker float (2 × 708), returned to sweepers | 2.04 M sats | 2.04 M sats |
| Sweep fees (batched, ≈ 43 sats per Ticker) | 0.12 M sats | 0.12 M sats |
| **Net cost if ticker.cash sweeps** | **≈ 0.026 BCH** | **≈ 0.032 BCH** |
| Gross reserve outflow (fees + float) | 0.045 BCH | 0.051 BCH |

Reserve sizing: the head loses fee **and** Ticker float on every update, about 3,120–3,560 sats; the
float comes back only to whoever sweeps. Fund the reserve for a week (≈ 0.35 BCH), run the sweeper, and
route swept dust back into the reserve through top-up inputs on ordinary updates. Alert when the
reserve falls under a day.

Operational: 13 MPC-TLS sessions per minute network-wide, one per notary. tlsn publishes no bandwidth
numbers; benchmark both modes in M0 before committing rows to MPC mode.

---

## 7. Off-chain architecture (fresh workspace, no carry-over by default)

As built (the plan had four crates; prover and builder share one daemon because both only need the
manifest, and the sweeper and the status publisher live with them):

```
node/                      Rust workspace (tokio; tlsn is async)
  core/                    codecs (commit, statement), BCH-Schnorr signer, exchange registry, tx builders, electrum pool
  notary/                  ticker-notary: tlsn Verifier + row pin + parser + signer + HTTP API + per-minute store
  daemon/                  ticker-node: prover (second ~2 of each minute), builder, sweeper, genesis, status publisher
contracts/                 Oracle.cash, Ticker.cash, PriceGated.cash, artifacts, VM test suite
deploy/systemd/            systemd units for one operator host (web as a system unit under its own user)
web/                       head decoder, scripthash subscriptions, notary table, cost meter
```

* **BCH Schnorr in Rust.** No crate exposes BCH's variant (Jacobi-symbol nonce, 33-byte key in the
  challenge). It is ~60 lines over `k256` field arithmetic; cross-test against libauth's
  `signMessageHashSchnorr` with vectors generated by `contracts/test`. Fallback: ECDSA-DER data
  signatures cost ≈ +8 B per statement and need no new code.
* **Notary config per row:** host, path, HTTP method, JSON key path, decimals, quote currency, mode
  (MPC | proxy), root store, key file. The notary refuses anything outside its pin.
* **Reuse candidates from v24 after review:** `electrum/` client, `tx/cashaddr.rs`, CashTokens
  output encoding. Delete: `cycle/`, `identity/`, `covenant/redeem.rs` specialization, slot and
  attest codecs, `prover/` (replaced by the tlsn prover), `ops/deploy.rs` (genesis becomes one
  transaction: mint the head with `hash160(table) ‖ seq0 ‖ 0` and fund the reserve).
* **Manifest** shrinks to `{ category, tickerLock, table: [{row, pubkey, operator, source, mode}] }`
  and is public.

---

## 8. Decisions requested

| # | Decision | Recommendation |
|---|---|---|
| D1 | Rotation path (9-of-13) | **Decided: no** (2026-10-24). Re-genesis to change the set; the branch measured 75 B and stays in history. |
| D2 | Cadence counter | **Unix minute** (not block height): chain-agnostic, no notary chain-tracking, robust to Faster Blocks' outcome. |
| D3 | Reserve-funded head vs funder input | **Decided: reserve** (2026-10-24). Builders pay exactly `size + 1` sat; the 5,000 cap is a ceiling with ≈ 1.7 sat/B of headroom at k = 13. |
| D4 | N rows / quorum | **13 / 7** at genesis; the covenant takes N as a literal, so 26 / 14 (two notaries per exchange) is a re-genesis or a rotation-plus-recompile later. |
| D5 | MPC-TLS vs proxy per row | Decide per row after M0; default MPC where bandwidth allows, proxy for notaries on constrained links. |
| D6 | K Tickers, value, sweep age | **2, 708 sats (exact dust floor), 144 units.** |
| D7 | Signature encoding | **BCH Schnorr (64 B)**; DER fallback if the signer slips. |
| D8 | Publisher countersignature | **No.** Open provers; two-party security comes from more independent rows, not from a key the operator holds. |
| D9 | Bonds / equivocation slashing | **Phase 2**, after independent notaries exist. |
| D10 | Builder tip | Optional bounded fourth output (≈ 500 sats, once per minute, ≈ 0.007 BCH/day). Not in the draft; add only if volunteer builders prove scarce. |
| D11 | Exchange identity on chain | **Decided: go** (2026-10-24). Table rows are `pubkey ‖ source`; the source byte is in every signed statement. |
| D12 | Price width | u64 in 1e-8 USD (current) vs u48 in 1e-6 USD. u48 saves 14–26 B per update and 6 B of commits (≈ 1 %) and caps at $281 M per BCH. **Recommend keeping u64**: satoshi-scale convention, 8-byte alignment for every consumer. |
| D13 | Ticker count | K = 2 (current) vs K = 1. K = 1 saves 87 B and 708 sats of float per update (≈ 0.0013 BCH/day net) at the cost of a second independent consumer chain per minute. **Recommend K = 2 for mainnet**; K = 1 is defensible for chipnet. |

---

## 9. Milestones and gates

*Outcome (2026-10-24):* M0–M3 were completed in one day and are recorded in §12; the chipnet genesis
happened before Faster Blocks activates there, since nothing in the covenant depends on it. M4 is next.


| When | Milestone | Gate to pass |
|---|---|---|
| now → 7 Nov | **M0 benchmark**: tlsn alpha.15 prover+verifier against all 13 endpoints, MPC and proxy; session time, bytes, failures | per-row mode chosen; worst-case session < 20 s |
| now → 14 Nov | **M1 covenants frozen**: finalize `contracts`, add relay-level tests on chipnet (dust, chained updates, sweep), fingerprint tests, external review scoped (453 + 31 B) | suite green on the frozen artifacts; reviewer engaged |
| 1 → 28 Nov | **M2 daemons**: `ticker-notary`, `ticker-prover`, `ticker-builder`, BCH-Schnorr with libauth cross-vectors | 13 self-run notaries produce statements every minute on chipnet |
| 15 Nov | chipnet activates Faster Blocks | observe one update per block, variance, MTP lag |
| late Nov | **M3 chipnet genesis v25** + web | 7 days of continuous operation; cost meter matches §6 |
| Dec → Feb | **M4 independent notaries**: hand rows to independent BCH infrastructure operators; publish the registry; run the mixed set on chipnet | ≥ 7 rows outside ticker.cash |
| Jan → Mar | **M5 review + bonds**: external audit of covenants and notary; `NotaryBond` equivocation covenant | findings closed |
| Mar → Apr 2027 | **M6 mainnet genesis** (works at 10-minute blocks via chained minute updates, or builder policy "once per block") | reserve funded; monitoring; consumer guide published |
| 15 May 2027 | Faster Blocks on mainnet | nothing to do: cadence converges to one per block by itself |

---

## 10. Risks and open questions

* **tlsn API churn.** Alpha software, breaking changes expected; pin a release, vendor if needed.
* **MPC bandwidth** is the only unmeasured operating cost (M0).
* **TLS 1.3-only exchanges** would break TLSNotary rows until tlsn ships 1.3; today all 13 offer 1.2.
* **cashc 0.14 trust.** Audit the compiled 453 bytes, not the source; pin the artifact fingerprint.
* **Builder stale-minute selection** (§5) is bounded by builder diversity; run builders in at least
  two independent places from day one.
* **Notary clocks.** NTP required; the ±90 s acceptance window hides ordinary skew.
* **Exchange IP policies** in proxy mode (datacenter IP of the notary is visible); v24's VPS fetches
  worked for months, so expect no change, but keep MPC mode available per row.
* **What "trustless" still does not mean.** The price originates off chain; the strongest statement
  the chain can make is "≥ 7 independent verifiers, each of whom validated a TLS session with a named
  exchange, signed this number within this minute". v25 makes exactly that statement, with no one
  else in the loop.

---

## Appendix A — byte layouts

```
Head commit (12 B):     seq u32 LE[4] ‖ price u64 LE[8]          (identical to the Ticker commit)
Ticker commit (12 B):   seq u32 LE[4] ‖ price u64 LE[8]
Table (442 B):          13 × (compressed pubkey[33] ‖ source[1]), row order, constructor constant
Statement message:      0x4e ‖ category_vm[32] ‖ row[1] ‖ source[1] ‖ seq[4] ‖ price[8]      (47 B)
Unlocking (update, k):  seq[4] ‖ rows[k] ‖ prices[8k] ‖ sigs[64k] ‖ median[8] ‖ redeem[850]
Update tx:              1 in (head) → out0 head, out1..2 Ticker (P2S 31 B, 708 sats); fee = size + 1
```

## Appendix B — measurement sources

chipnet Fulcrum (`chipnet.imaginary.cash:50002`), Oracle `bchtest:pvgts6s4…`, slot scripthashes from
`web/public/ticker-client.js`; tx sizes from `blockchain.transaction.get` verbose; v25 numbers from
`contracts/test/v25.suite.mjs` (cashscript 0.14.0, libauth 3.0.0, cashc 0.14.0).

## 12. Deployment record (chipnet, 2026-10-24)

| | |
|---|---|
| network | chipnet |
| category | `16bc04ed68a236c217c5f96346206de4442663f41aa5736395e8f943fd92fccb` |
| genesis | `ac602422cb513184bb745568ae19854c76fd04580b95e23687f538f9cab0230e` (276 B, fee 277 sats) |
| head address | `bchtest:p0z2vuz0cegv56z4lc4x5n78sspmm3qu9a7hf6q0yld8f9zvtpq76twyczghu` |
| oracle lock | `aa20c4a6704fc650ca6855fe2a6a4fc78403bdc41c2f7d74e80f27da74944c5841ed87` |
| Ticker lock | `76009c63c076cd78c78876d178ce8876cc7cc69c7767519d029000b2755168` |
| reserve | 40,000,000 sats (≈ 11,200 updates at k = 13 before a top-up) |
| table | rows 0–12 → registry ids 1, 2, 3, 16, 5, 6, 7, 14, 15, 10, 11, 12, 13 (Kraken, Coinbase, Gemini, Binance·USDC, Bitstamp, Crypto.com, Bitfinex, Gate.io·USDT, Bitget·USDT, OKX·USDC, KuCoin·USDC, Bybit·USDT, HTX·USDT) |
| first update | `c7a7ad0a57e23121950b56f72bacf8fd14a1d9e728f4de50186fb15b1ed37642`: k = 13, 2,140 B, fee 2,141 sats, median 272.865 |
| operator | ticker.cash runs all 13 rows on one host (`deploy/systemd/`); provers and builder are the same daemon |
| web | https://usd.ticker.cash serves `manifest.json` and `status.json`; pages read the head from Fulcrum over WSS |

### 12.1 Registry change before go-live

The first v25 genesis of the day (category `b401b67e…`, table = registry ids 1–13) ran for twenty minutes
and exposed three rows that could not honestly sign a market price:

| id | exchange | finding |
|---|---|---|
| 8 | EXMO | `BCH_USD` delisted; only `BCH_USDC` remains, last trade 6 h old, 0.13 BCH/day |
| 9 | Independent Reserve | `LastPrice` 279.91 against a 273 market; last BCH/USD trade 2026-09-23 at 355 |
| 4 | Binance.US | 0.03 BCH traded in 24 h (one trade) |

A source byte must keep its meaning for as long as a statement carrying it exists, so the registry is
append-only: ids 4, 8 and 9 stay defined but retired, Gate.io (14, USDT), Bitget (15, USDT) and
Binance BCH/USDC (16) were appended, and the deployment was re-run with a new table. The abandoned head
keeps its 0.3998 BCH test reserve; it is unspendable except through `update`, which nobody signs for.
Quote mix after the change: 6 USD, 3 USDC, 4 USDT, so one stablecoin losing its peg leaves at least
seven unaffected rows for the lower median. All three replacements were proven end to end in MPC and
proxy mode before the re-genesis (bodies 36–389 B; sessions 0.75–1.8 s).

### 12.2 Operations notes

* Electrum pool order is operator configuration (`genesis.json` → `manifest.json`), not consensus. The
  daemon remembers the endpoint that last answered and caps TCP connect at 5 s, so a dead endpoint
  costs one timeout per process. `chipnet.layer1.cash` (159.195.80.214) was unreachable on go-live day
  and sits last in the pool.
* `ticker-node run` re-publishes `manifest.json` and `status.json` as 0644 every 10 s; the web build
  deletes everything else in `dist/` and leaves those two alone.
* v24's thirteen `ticker-node@N` publisher units were stopped and disabled on the same host; the v24
  binaries are archived under `~/archive/v24-bin/`, the v24 treasury seed stays in `~/.ticker-coordinator/`.
* Statement logs of the abandoned deployment were rotated to `statements.b401b67e.jsonl` in each notary home.
