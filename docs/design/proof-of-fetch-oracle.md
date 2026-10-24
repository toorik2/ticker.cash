# Proof-of-Fetch: a consensus-verified, notarized price oracle for Bitcoin Cash

Status: **proposal / first-principles design note** (2026-10-24). Not implemented. Written
as the answer to "does SolidCash (mainnet_pat, 2026-10-23) get us to a trustless BCH-native
price oracle, and what would a novel design look like?"

Companion notes: `minimal-slot-principle.md` (fee discipline), `../incidents/v22-oc-22-quorum-bypass.md`
(why every input read must be category/identity-pinned).

---

## 0. TL;DR

1. **SolidCash is a compiler, not a new capability.** It lowers Solidity syntax to the same
   CashVM the ticker already runs on (BCH-2025 BigInt + VM limits, BCH-2026 loops / functions /
   bitwise / P2S). Nothing it does is unreachable from CashScript. Its own `block.*` oracle is a
   **single-key, keeper-trusted** NFT, i.e. *less* trustless than ticker.cash v24. It is not on the
   critical path of a trustless price oracle.
2. What SolidCash *does* prove is useful: heavy cryptography (keccak256, full secp256k1 scalar
   multiplication) runs inside consensus when split across co-spent inputs ("compute-and-commit
   side-cars"). That is the template for any future on-chain X.509 / TEE-quote verifier.
3. **The actual unlock for trustlessness is elsewhere:** TLSNotary (v0.1.0-alpha.15, May 2026) now
   runs a *live Verifier* that validates the exchange's certificate chain itself and learns the
   revealed plaintext. A thin wrapper turns that Verifier into a BCH **notary** that signs a
   39-byte statement with secp256k1-over-sha256, which `Oracle.update` verifies with **one
   `OP_CHECKDATASIG` per slot**. No Merkle openings, no RSA, no P-256, no ZK on chain.
4. **The concept — Proof-of-Fetch:** every slot attestation that enters the median must carry a
   co-signature from an *independent* notary that co-operated the TLS session with the exchange
   (MPC-TLS) or sat in its network path (proxy mode). Forging one slot requires the publisher **and**
   its paired notary; forging the median requires 7 publishers **and** 7 specific notary operators.
   The slot covenant is untouched (167 B, P2S). The Oracle grows by ~0.6 KB of body and ~0.1 KB of
   unlocking per included slot. Estimated hot-path cost ≈ 2–2.5× today's (≈ $6–8/day vs ≈ $5/day
   at 1 sat/B, BCH ≈ $290).
5. Objective misbehaviour (two statements for one `(slot, seq)`) becomes slashable with a
   150-byte equivocation covenant. Subjective collusion still needs either more notaries per slot
   or an escalation court — both are layered on, not required for v1.
6. Everything else evaluated — on-chain DEX TWAP, miner coinbase voting, Groth16-compressed TLS,
   importing Pyth/Wormhole, a permissionless header-chain clock — is recorded in §8 with why it is
   parked, not chosen.

---

## 1. What the tweet actually announces

Tweet (2026-10-23 14:11 UTC): "SolidCash is out: write Solidity, run it on Bitcoin Cash. Near-complete
Solidity parity. Stateful contracts. A real EVM project, @eaccmarket, running on BCH*. One year of
active development… None of this was possible before the BCH [May 2026 upgrade]." Site:
solidcash.org; repo: github.com/solidcash/solidcash (MIT). Figures below are from the repo at HEAD
on 2026-10-24.

| Claim | What the repo says |
|---|---|
| Solidity → BCH, no sidechain | True. `solidc` compiles `.scash` to CashVM bytecode; state lives in CashTokens NFT commitments (master minting NFT + mutable data NFTs + "verified mapping" entry NFTs as an authenticated sorted list). |
| Stateful contracts | True, with real constraints: 128-B commitments, one master UTXO serialises calls, 10,000-B per-input script limit. |
| Cross-contract calls, events, ecrecover, keccak | Modelled as co-spent inputs; `keccak256` and `ecrecover` are *side-car* covenants that do the arithmetic on their own input budget (recovery needs two inputs even with GLV). |
| "A real EVM project running on BCH*" | The asterisk: the eacc marketplace fixture has **7 of 19 artifacts over the 10,000-byte per-input limit** (largest composed unlocking 24,937 B); it runs on a mock node with relaxed limits. README calls it a "mocknet beta". Two small apps are proven on regtest. |
| Security | `msg.sender` is **not authenticated** under the default `direct` convention (audit F1). The 2026-10-16 audit lists CRITICAL findings (DYN-1, ECR-1, C3 class) fixed 2026-10-22/23; several fixes are compile-level only ("the displaced-delegate transaction was not built, so the refusal itself is unrun"). |
| Block oracle | `block.number/timestamp` come from **one owner-keyed NFT**; docs: "The owner is trusted not to under-report or lie about any field." `blockhash(n)` pairs are minted by a keeper baton. |

**Verdict for us:** excellent evidence that CashVM-2026 is a real compute target, a plausible
on-ramp for EVM developers (demand for a BCH price feed), and a reference implementation for
input-split heavy crypto. Not a source of trustlessness, and not something to hold bonds in yet.

---

## 2. First principles: how a number can enter a covenant

A covenant can only check things about the spending transaction: signatures, hashes, arithmetic
over supplied bytes, and introspection of co-spent inputs/outputs. A price is never an on-chain
fact. Every oracle is therefore a choice of **whose signature the covenant accepts** and **what that
signature attests**. There are exactly four families:

| Family | What the covenant verifies | Who must lie to forge | Examples |
|---|---|---|---|
| A. Reporter quorum | k-of-n reporter signatures | k reporters | ticker.cash v24 (7-of-13), Chainlink DON, GP's AnyHedge oracle (1-of-1) |
| B. Source-bound receipt | a signature from a party that *co-operated the TLS session* with the source | reporter **and** that co-operator (per slot) | TLSNotary/DECO lineage; this note |
| C. Hardware attestation | an enclave key whose quote chains to a vendor root (P-256) | vendor root, enclave code, or a TEE break | Town Crier, Chainlink DECO/TEE work |
| D. Native market | state of an on-chain market (reserves, auction clearing) | whoever can move the market for the sampling window | Uniswap TWAPs |

Two observations drive the design:

* **Family D is not available on BCH today.** The only USD-denominated CashToken with a market is
  MUSD (Moria/Riften Labs), whose peg itself rests on an oracle, traded on Cauldron with thin
  depth. A thin market is a cheap market to move. Revisit when BCH/stablecoin depth is real (§8).
* **The chain verifies secp256k1-over-sha256 signatures for free** (`OP_CHECKDATASIG`, op-cost
  26,100). Anything else costs real inputs (table below). So the design goal is: *make every
  trust-bearing statement a secp256k1-over-sha256 signature*, and push every other kind of proof
  off the hot path or into one-time registrations.

### 2.1 On-chain verification price list (CashVM 2026)

Budget: `(41 + unlockingBytes) × 800` op-cost per input, so a maximal 10,000-B input has 8.03 M.
`OP_MUL/DIV/MOD` cost `100 + 2·len(c) + len(a)·len(b)`; one hash iteration costs 192 (standard).

| Primitive | Op-cost (est.) | Inputs | Notes |
|---|---|---|---|
| `OP_CHECKDATASIG` (secp256k1 ECDSA/Schnorr over sha256) | 26 k | 0.003 | **the cheap path** |
| sha256 of a 2 KB transcript | ~7 k | — | 32 iterations |
| RSA-2048 PKCS#1 v1.5 verify (e = 65537) | 3.4 M | 0.4 | 17 modmuls of 256-B numbers |
| RSA-4096 verify | 13.4 M | 2 | Bitstamp's intermediate CA |
| ECDSA P-256 verify (Jacobian, Shamir, windowed) | ~13 M | 2 | same order as SolidCash's secp256k1 recovery pair |
| ECDSA P-384 verify | ~40 M | 5 | GTS Root R4 → WE1 signature |
| Groth16 verify (verifier.cash) | — | 5 inputs, 35 KB | per-circuit trusted setup |
| Full TLSNotary presentation (notary sig + Merkle + plaintext hash + X.509 chain) | 1 + 0 + 0 + 2–7 inputs | 3–8 | only needed if the notary does **not** check server identity |
| Intel DCAP quote (3 × P-256) | ~40 M | 5–6 | once per enclave registration |

Measured on 2026-10-24: **all 13 pinned exchange API hosts negotiate TLS 1.2 ECDHE with
AES-128-GCM** (TLSNotary's requirement). Certificate chains: Google Trust Services WE1 (P-256 leaf,
P-256 intermediate, P-384 root) for Kraken, Coinbase, Crypto.com, Bitfinex, OKX, KuCoin; Amazon
RSA-2048 chains for Gemini, Binance.US, Independent Reserve, Bybit, HTX; GoGetSSL/USERTrust RSA-2048
for EXMO; DigiCert RSA-4096 intermediate for Bitstamp.

### 2.2 The decisive fact about TLSNotary in 2026

* `tlsn` v0.1.0-alpha.13 (2025-10) **removed the notary server**; `tlsn-attestation` is frozen.
  The project moved to a **live Verifier** model (MPC-TLS, and since alpha.15 a cheaper
  **proxy mode** where the verifier forwards the encrypted traffic and the prover proves the
  session in ZK). TLS 1.2 only; 1.3 is roadmap.
* The Verifier **validates the server certificate chain itself** against a root store
  (`crates/tlsn/src/verifier.rs`: `ServerCertVerifier::new(self.config.root_store())`;
  `verify.rs`: "certificate verification failed") and outputs `server_name`. It also learns every
  plaintext byte range the prover chooses to reveal.
* Therefore a notary built as *tlsn Verifier + secp256k1 signer* can attest, in its own words,
  "I co-operated a TLS 1.2 session with `api.kraken.com` (chain valid), the prover revealed request
  `GET /0/public/Ticker?pair=BCHUSD` and a response range reading `"c":["512.34…"`, at time T".
  **The chain never needs to see the transcript, the certificate, or TLSNotary's own formats.**

That collapses Family B's on-chain cost from "3–8 heavy inputs" to **one `OP_CHECKDATASIG`**.

---

## 3. The concept: Proof-of-Fetch slots

### 3.1 Roles

| Role | Runs | Trusted for |
|---|---|---|
| Publisher (13, as today) | `ticker-node --publisher` + a tlsn **prover** | liveness; slot key custody; nothing about the price value any more |
| Notary (13 pinned, one per slot) | tlsn **Verifier** + statement signer (`ticker-notary`) | not colluding with *its* publisher; its clock |
| Exchange (13, as today) | its API | its own market price (absorbed by the median) |
| Oracle.update builder | any publisher | nothing (consensus checks everything) |

The notary is deliberately **generic**: it has no exchange-specific extraction logic beyond a
per-slot pin (host, path, JSON key, decimals), no slot key, no BCH funds, and cannot initiate an
attestation on its own (it needs a publisher to open the session and hold the slot key). That is
what makes it recruitable from parties who would never run a publisher.

### 3.2 The notary statement (39 bytes signed, 0 bytes stored)

```
stmt = TAG(1) ‖ domain(20) ‖ publisherPkh(20) ‖ price(8, u64 LE) ‖ ts(5, u40 LE) ‖ cycleSeq(5, u40 LE)
TAG    = 0x4e ('N')
domain = hash160(oracleCategory)         // replay separation between deployments
sig    = Schnorr(secp256k1) over sha256(stmt)   (64 B; CHECKDATASIG-compatible)
```

The last 18 bytes are **byte-identical to the v24 slot commit** (`price ‖ timestamp ‖ cycleSeq`),
so the Oracle rebuilds `stmt` from data it already reads. Nothing is added to the slot commit.

Notary duty when a publisher connects for `(slot, seq)`:

1. Run the tlsn Verifier session (MPC-TLS by default; proxy mode acceptable, see §6).
2. Require `server_name == pinned host`; require the prover to reveal the full request line and
   `Host:` header and check them against the pin; require the response status line `200`.
3. Require the revealed response range to parse as `pinnedJsonKey ‖ decimal`; parse the decimal to
   `price` in 1e-8 USD. The notary's parse is authoritative; the publisher copies it.
4. `ts` = notary wall clock at session end. `cycleSeq` = the value the publisher asked for.
5. **Issue at most one statement per `(publisherPkh, cycleSeq)`.** Refuse otherwise.
6. Sign; return statement + signature. Keep a log (needed only for disputes/audits).

### 3.3 Cycle flow (changes in bold)

1. Publisher reads Oracle `(seq, lastTs)` as today.
2. **Publisher opens an MPC-TLS/proxy session to its pinned exchange *through its paired
   notary*, reveals the request and the price range, receives `(stmt, notarySig)`.**
3. Publisher signs the v24 attest message using the notary's `price` and `ts`, broadcasts
   `PublisherSlot.attest` (unchanged covenant, unchanged bytes).
4. Race winner builds `Oracle.update` and **supplies `(notaryPubkey_i, notarySig_i)` for every
   included slot** (published by each publisher alongside its attest, e.g. in the stats endpoint
   or an OP_RETURN-free side channel; any peer can fetch them).
5. **Oracle.update verifies each statement (below).** Median, Ticker mints, re-emits as today.

### 3.4 Covenant changes

`PublisherSlot.cash`: **none.** (167 B stays 167 B; the minimal-slot principle holds.)

`Oracle.cash` (P2SH-32, paid once per cycle), inside the existing per-slot loop:

```cashscript
// deploy-time literal table, 13 × (publisherPkh 20 ‖ notaryPkh 20) = 520 B
bytes pairing = 0x...;

bytes slotLb   = tx.inputs[slotIdx].lockingBytecode;
bytes20 pubPkh = bytes20(slotLb.slice(PKH_OFFSET, PKH_OFFSET + 20)); // slot body literal offset
int j = int(pairIdx.slice(i, i + 1));                                  // unlocking-supplied index
require(pairing.slice(j * 40, j * 40 + 20) == pubPkh);
bytes20 notaryPkh = bytes20(pairing.slice(j * 40 + 20, j * 40 + 40));

pubkey  npk = pubkey(notaryKeys.slice(i * 33, i * 33 + 33));
datasig nsg = datasig(notarySigs.slice(i * 64, i * 64 + 64));
require(hash160(npk) == notaryPkh);
bytes stmt = 0x4e + hash160(tx.inputs[idx].tokenCategory.slice(0, 32)) + pubPkh + slotCommit;
require(checkDataSig(nsg, stmt, npk));
```

(`tokenCategory.slice(0, 32)` is the category in VM byte order, i.e. reversed relative to the
display id; the notary must derive `domain` from the same bytes. `pairIdx`, `notaryKeys`,
`notarySigs` are new unlocking arguments of `update()`, omitted from the sketch's signature.)

Why this is sound given the existing invariants: the slot category pin (F01) plus the closed
category guarantee `slotIdx` is one of the 13 genesis slots; the slot's own re-emit pins its
locking bytecode, so `pubPkh` sliced from the LB is the slot's immutable identity; the slot's
attest already bound `slotCommit` under the publisher key; the statement binds the same bytes under
the notary key. The pairing table is as immutable as the Oracle body (new notary set ⇒ re-genesis,
consistent with "no admin keys").

Budget: 13 extra `OP_CHECKDATASIG` ≈ 0.34 M op-cost; the loop body adds ≈ 60 B of script. The Oracle
redeem grows from 497 B to ≈ 1.1 KB, still far under the 10,000-B input cap.

### 3.5 Accountability covenants (optional, zero hot-path cost)

* `NotaryBond(notaryPkh)`: P2SH-32 holding the notary's bond. Spend path **`equivocation`**: two
  statements with equal `(domain, publisherPkh, cycleSeq)` and different `(price ‖ ts)`, both
  passing `checkDataSig` under the notary key ⇒ pays a share to the prover of the equivocation and
  the rest to a burn/treasury output. ≈ 150 B of script.
* `PublisherBond(publisherPkh)`: same shape over the v24 attest message (two signed tuples with
  equal `cycleSeq`, different payload).
* This turns the "issue at most one statement per cycle" rule and the selection-bias attack
  (fetch 20 times, keep the best print) from a courtesy into a consensus-enforced loss.

### 3.6 Timestamps

`ts` now comes from the notary clock, so the Oracle's median-of-timestamps vote is a median over
*notary* clocks. Publishers lose the ability to skew `newTs`; the ±120 s jitter window can be
tightened once notary clock quality is measured.

---

## 4. Trust accounting

| Property | v24 today | Proof-of-Fetch v1 | + bonds | + 2 notaries per slot |
|---|---|---|---|---|
| Parties needed to forge the median | 7 publishers (in practice: 1 operator) | 7 publishers **and** their 7 paired notaries | same, plus they lose bonds if they ever equivocate | 7 publishers and 14 notaries |
| Who can lie about *when* | publishers (vote-absorbed) | notaries (vote-absorbed) | same | same |
| Selection bias within the window | free | needs a notary willing to issue twice | **slashable** | needs both notaries |
| Detectable on chain | nothing beyond the median | nothing beyond the median | equivocation | equivocation |
| Liveness | 7 of 13 publishers up | 7 of 13 (publisher ∧ notary) pairs up | same | same (if "either"), weaker (if "both") |
| Exchange lies about its own price | absorbed (≤ 6) | absorbed (≤ 6) | absorbed | absorbed |
| What the chain itself enforces | quorum, freshness, median | **+ every number is co-signed by a party that validated the exchange's certificate and saw the bytes** | + one statement per cycle | + two independent co-signers |

What is *not* achieved: an on-chain proof that a (publisher, notary) pair did not collude. That is
the residual of Family B everywhere (DECO, TLSNotary, Reclaim). Shrinking it means more notaries
per slot (§7.2), heterogeneous attestation (TEE, §7.4), or an economic court (§7.7). There is no
cryptographic way to remove it while exchanges do not sign their own data.

The single-operator caveat from the README applies with full force: **if the same operator runs
the notaries, nothing is gained.** The design's value is that the notary role is light and generic
enough to be handed to independent BCH infrastructure operators without giving them a slot key.

---

## 5. Cost

Assumptions: 1 sat/B, BCH ≈ $290, 1,440 cycles/day, current measured ≈ 1.2 k sats/cycle.

| Component | Bytes / cycle | Notes |
|---|---|---|
| Oracle body: pairing table + loop logic | ≈ 580 (1×) | P2SH-32 redeem, revealed once per cycle |
| Oracle unlocking: `npk(33) + nsg(64) + pushes(2)` per included slot | 693 (7 slots) – 1,287 (13 slots) | |
| Slot bytes | **0** | commit and body unchanged |
| **Total added** | **≈ 1.3 – 1.9 KB** | ≈ +1.9 – 2.7 M sats/day ≈ **+$5.5 – $7.9/day** |
| Dual notary (§7.2) | + 0.7 – 1.3 KB | ≈ +$3 – 5/day |
| Optimistic variant (§7.1) | + 0.4 KB | 32-B receipt hash per attest; needs bonds + watchers |

Operational: MPC-TLS bandwidth per session is the main unknown (tlsn publishes no numbers; the
protocol is described as "high bandwidth", proxy mode as "low"). 13 sessions per minute across the
federation is trivially fine in proxy mode; benchmark MPC mode before committing to a 60-s cadence
(§9, M0). Notary CPU/RAM is modest; the notary holds no funds.

---

## 6. MPC-TLS vs proxy mode (per slot, notary-side setting)

| | MPC-TLS | Proxy mode |
|---|---|---|
| Added assumption | none beyond cryptography | nobody MITMs the notary→exchange path (DNS/BGP); the notary still validates the certificate chain, so a hijacker also needs a CA-issued cert |
| Exchange sees | normal TLS from the publisher | the notary's IP (datacenter IP blocks are a risk) |
| Cost | high bandwidth, slower | "significantly faster", low bandwidth |
| Recommendation | default for slots whose notary has bandwidth; required if a notary is in a jurisdiction where path attacks are plausible | pragmatic default for a 60-s cadence |

Both modes keep the collusion residual identical ("a colluding verifier could attest to fabricated
sessions" — tlsn's own wording applies to both).

---

## 7. Variants and extensions (each independent of v1)

### 7.1 Optimistic mode (cheaper hot path, more machinery)
Store only `sha256(stmt ‖ sig)` in the publisher's signed attest message (+32 B unlocking per
attest, slot body unchanged); verify statements only on challenge. Needs: publisher bonds,
challenge/response covenants, a 30-day receipt retention duty, and a 1-of-N honest watcher
assumption. Saves ≈ $4–6/day. Not recommended first: the validity path is cheap enough and has no
liveness assumption on watchers.

### 7.2 r-of-n notaries per slot
Pairing table rows carry n notary pkhs; the Oracle requires r signatures. `r = n = 2` doubles the
collusion requirement; `r = 1, n = 2` is a liveness fallback. Linear byte cost per extra signature.

### 7.3 Open slots (no publisher keys)
If a slot's statement is bound to the slot by `(domain, sourceId)` instead of `publisherPkh`,
*anyone* with a notary statement can attest, and publishers become permissionless keepers. Then
forging a slot needs only the notary (it can play prover itself), so this only makes sense with
`r ≥ 2`. Interesting as a later decentralisation step: the protocol would have **no privileged
writers at all**, only co-signers who cannot write alone.

### 7.4 TEE notaries (heterogeneous attestation)
A TDX/SGX fetcher that validates the exchange chain inside the enclave and signs the same 39-byte
statement with an enclave-held secp256k1 key plugs into the *same* Oracle check. Its one-time
registration (DCAP quote: ≈ 3 × P-256 ≈ 5–6 inputs ≈ 50 KB) goes through a registry covenant built
exactly like SolidCash's ecrecover side-car pair. Pairing a TLSNotary notary with a TEE notary on
one slot forces an attacker to break a hardware root of trust **and** bribe an operator.

### 7.5 On-chain X.509 cache (only for "dumb" notaries)
Needed only if we ever accept receipts from notaries that do *not* validate server identity. Cost
amortises well: register an intermediate CA once (P-384 or RSA-2048), register a leaf per rotation
(P-256/RSA-2048), then per receipt verify just the handshake signature (≈ 2 inputs). Parked: tlsn's
verifier already does this off chain and no generic public notaries exist any more.

### 7.6 CashSPV clock (permissionless block oracle)
A covenant that anyone extends with BCH headers: checks `prevHash` linkage, PoW against the ASERT
target (aserti3-2d is integer-only: `factor = ((195766423245049·e + 971821376·e² + 5127·e³ + 2⁴⁷) >> 48) + 65536`,
half-life 172,800 s, 16 fractional bits — all expressible with BCH bigints and shifts), MTP over the
last 11 timestamps, and cumulative work; state fits one 128-B commitment (tip hash, height, nBits,
11 timestamps, work). It yields a **trustless** `block.timestamp`/`block.number` upper bound, a
miner-grindable-only randomness beacon (for rotating notary assignments), and SPV inclusion for a
future miner-coinbase price channel. Replaces SolidCash's keeper-owned block oracle for the whole
ecosystem. Separate project; reorg handling (store a short ring of recent tip hashes) is the main
design wrinkle.

### 7.7 Escalation court
Bonded jurors (BCH stake, commit-reveal vote via verified mappings) decide subjective disputes
("the exchange API was down", "the notary statement was for a different symbol"). This is the
UMA/Kleros shape and the only tool against undetectable collusion. SolidCash's stateful model is
the natural prototyping ground; production use waits for its audit to settle.

---

## 8. Considered and parked

| Option | Why not (now) |
|---|---|
| On-chain BCH/stablecoin TWAP as the source | only MUSD exists, thin Cauldron depth, peg depends on an oracle; cheap to move. Keep as a future *sanity bound*, never as the source. |
| Miner coinbase price voting (hashrate-weighted median) | needs miner adoption and a header-chain clock first; trust = hashpower majority of ~5 pools. Possible tertiary channel via §7.6. |
| Groth16 proof of a whole TLS transcript | the client always knows the TLS keys, so ZK alone cannot remove the notary; 35 KB/5 inputs per proof buys nothing over one CHECKDATASIG. |
| Import Pyth/Wormhole or Chainlink Data Streams | 13 × full ECDSA (keccak-hashed, not CHECKDATASIG-compatible) ≈ 26 inputs per update; not BCH-native; trust moves to 19 guardians. |
| Verify tlsn's signed attestation format on chain | tlsn dropped notary issuance; the live-verifier model makes our own 39-byte statement strictly simpler. |
| FROST/Schnorr aggregation of the 13 publisher sigs | BIP-340 ≠ BCH-Schnorr; already parked in `minimal-slot-principle.md`. |
| Putting the notary pin in the slot body | +22 B × 26 emissions/cycle ≈ same bytes as the Oracle table, but spends slot headroom (167 → 189 of 201 B). Table wins. |

---

## 9. Staged plan

* **M0 — Benchmark (1 week).** `tlsn` alpha.15 prover+verifier against all 13 endpoints in MPC
  and proxy mode: session time, bandwidth, failure rate, HTTP quirks (chunked encoding, HTTP/1.1
  requirement). Decide mode per slot. Measure notary clock skew.
* **M1 — `ticker-notary` (Rust, separate binary).** tlsn Verifier + per-slot pin + parse + sign +
  one-statement-per-`(pkh, seq)` store. Note: `tlsn` is tokio-based; the prover side of
  `ticker-node` (sync, no tokio) gets it as a sidecar process or a small async shim behind the
  existing `PriceProver` trait (`node/core/src/prover/trait_.rs` is already the seam).
* **M2 — Oracle v25 on chipnet.** Pairing table + loop check (§3.4). All 13 notaries self-run:
  no security gain yet, but the protocol, fees, and the stats/web decode are proven. Regression
  tests mirror the F01 pattern (table placeholder appears exactly once; fingerprint pinned).
* **M3 — Independent notaries.** Hand notary keys to independent BCH infrastructure operators;
  re-genesis with the real pairing table. This is the step that changes the trust model.
* **M4 — Bonds.** `NotaryBond` / `PublisherBond` equivocation covenants and a watcher that scans
  attests and statements.
* **M5 — Options.** Dual notaries on the highest-weight slots; TEE notary pilot; CashSPV clock.

---

## 10. Where SolidCash fits, concretely

* **Not** in the hot path (`Oracle.cash`, `PublisherSlot.cash`, `Ticker.cash` stay hand-written
  CashScript under the minimal-slot discipline).
* **Consumer adapter:** a SolidCash reader can already consume a Ticker by pinning
  `tickerLockingBytecode` + category and slicing the 19-B commitment, exactly the way its
  `block.*` readers slice the block-oracle NFT. Publishing that adapter is a cheap distribution
  win and offers SolidCash developers a *trustless* alternative to their keeper-owned oracle.
* **Prototyping ground** for §7.5–7.7 (registries, bonds with vmaps, courts). Promote to
  production only after the 2026-10 audit fixes have aged and the relevant transactions have
  actually been built against real limits.
* **Reference code:** `packages/utils/src/ecrecover-compute-library.ts` (A/B split GLV ladder,
  compute-and-commit) and `keccak-compute-library.ts` are the closest existing implementations of
  the input-split pattern any P-256 / RSA / DCAP verifier on BCH would reuse.

---

## Appendix A — facts verified on 2026-10-24

* Tweet id 2113634351116145003 → 2026-10-23 14:11:13 UTC (snowflake); text via syndication API.
* SolidCash repo: README (composition conventions, limits, "mocknet beta"),
  `docs/security/security-audit-2026-10-16.md` (fix pass 2026-10-22), `website/docs/guides/block-oracles.md`,
  `website/docs/language/cryptography.md`, `computation-sidecars.md`, `storage-model.md`,
  `verified-mappings.md`, `cross-contract-calls.md`, `basics/platform-differences.md`.
* TLSNotary: releases alpha.6 … alpha.15 (2026-05-21); notary server removed in alpha.13;
  `tlsn-attestation` frozen; proxy mode blog 2026-04-22; verifier validates certificates
  (`crates/tlsn/src/verifier.rs`, `verifier/verify.rs`); docs: TLS 1.2 only.
* CashVM limits: `bitjson/bch-vm-limits` readme + operation-costs (800/B budget, 0.5 hash
  iterations/B standard, MUL/DIV/MOD formula). May-2026 upgrade: loops, functions, bitwise, P2S
  standard (201-B locking bytecode, 128-B commitments, 10,000-B unlocking standard).
* ASERT: `bitcoincash-upgrade-specifications/spec/2020-11-15-asert.md`.
* verifier.cash: smallest fitting Groth16 verifier 35 KB over 5 inputs.
* Exchange TLS probe: `openssl s_client -tls1_2` against all 13 source hosts in
  `node/core/src/chain/sources.rs` (AES-128-GCM accepted everywhere; chain key types as listed in §2.1).
