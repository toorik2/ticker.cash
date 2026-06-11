# The minimal-slot principle (and the closed-category invariant)

Status: adopted v24-minimal (2026-06). Standing design rule for the covenant
family.

## TL;DR

Put as little logic as possible in the `PublisherSlot` covenant; put everything
the `Oracle` covenant can soundly carry into the Oracle. This is simultaneously
the **fee optimum** and the **size-safety discipline**. Two hard facts drive it:

1. **Slot bytes cost ~26× Oracle bytes per cycle.** The slot is P2S — its full
   script body is emitted into an output `scriptPubKey` every time a slot output
   is created: 13 publisher attests + 13 Oracle.update re-emits = **26
   emissions per cycle**. The Oracle is P2SH-32 — its redeem script is revealed
   **once per cycle** (the single Oracle.update input unlock). A byte added to
   the slot is paid 26×; a byte added to the Oracle is paid 1×.

2. **The slot body has a hard 201-byte wall.** P2S `locking_bytecode` is capped
   at 201 B by BCH relay policy (`references/cashscript-language-reference.md`
   §326). Over the cap → `REJECT_NONSTANDARD` at the node. The Oracle (P2SH-32)
   has no such wall (its locking_bytecode is a 35-byte hash; the redeem is
   bounded only by the 10,000 B unlocking cap).

So: keep the slot minimal, let the Oracle aggregate. New gates default to the
Oracle unless they are provably un-delegable to it.

## What this cost us (the v24-first-cut failure)

v22 moved the slot to P2S to save fees, landing at 196 B — only 5 B under the
wall, untracked. v24's first cut added u40 caps + length + tokenAmount pins to
the slot, reaching 233 B, and the slot genesis tx was rejected
`REJECT_NONSTANDARD`. cargo + mem-cash had passed: neither sees relay policy
(both model script-VM semantics only). The fix was to recognize the added gates
were redundant given the invariant below and drop them — landing at **167 B**,
*smaller* than the live v23 (the redundant pkh-monotone sort, ~29 B, also went).

Two permanent guards now prevent a repeat:
- `slot_template_fits_standardness_cap` cargo test — hard build-time assert that
  the compiled slot body ≤ 201 B (with a 16 B headroom warning).
- `deploy.rs` pre-flight — refuses to build genesis if any slot body > 201 B.

## The closed-category invariant (why the dropped gates were redundant)

The slot genesis (`node/ops/src/deploy.rs`) mints exactly **13 mutable slot
NFTs** and **no minting NFT** of the slot category; the genesis outpoint is
consumed once. Therefore the slot category is **permanently closed at 13
tokens** — no more slot-category tokens (NFT or fungible) can ever be created.

This single fact, combined with Oracle's F01 per-iter category pin, is what the
quorum's integrity rests on:

- Every slot input to `Oracle.update` is one of the 13 legit slots (F01 pins
  the category; only 13 tokens of it exist).
- Each slot has a distinct, immutable pkh (genesis assigns one per publisher;
  the re-emit pins `outputs[idx].lockingBytecode == inputs[idx].lockingBytecode`,
  so a slot's pkh never changes).
- A UTXO cannot be double-spent within a tx.
- ⇒ N distinct slot inputs = N distinct publishers, automatically.

Given that, the v24-first-cut slot gates were redundant:

| Dropped slot gate | Why redundant |
|---|---|
| pkh-monotone sort | Only mattered against duplicate-pkh tokens of the legit category, which can't exist. Gave **zero** independent security: V22-OC-22 proved that without the category pin an attacker forges distinct ascending pkhs and passes the sort anyway. With F01 it's pure redundancy. |
| cycleSeq cap | The monotonic check `cycleSeq > old` already rejects a sign-mag-negative value; Oracle increments + caps `newSeq` and pins each slot `cycleSeq == newSeq`. Bounded with no slot-side cap. |
| timestamp cap | A sign-mag timestamp only skews the Oracle's vote count, which is threshold-absorbed (one bad vote can't flip a majority); the Oracle's *output* `newTs` stays capped. |
| tokenAmount pins | No category fungible tokens can ever exist (closed category) → tokenAmount is always 0. |
| oldCommit.length pin | Oracle pins `slotCommit.length == 18`; out-of-bounds slices fail closed; legit slots self-pin their re-emit to exactly 18 B. |

Note this also tightens F01's own foundation: F01 (the V22-OC-22 fix) *depends*
on the closed category — if slot-category tokens could be minted, F01's pin
would not stop a forged-slot quorum. The closure is the bedrock; verify it
holds on every re-genesis (the deploy mints 13 mutable + 0 minting, and asserts
13 distinct slot addresses).

## The escape hatch (when minimal isn't enough)

If a future feature is genuinely un-delegable to the Oracle and pushes the slot
over 201 B, migrate the slot from P2S to **P2SH-32**. Cost: the slot output
becomes a 35-byte hash, but each spend reveals the body in the input. Slot UTXOs
are spent once per output, so P2S vs P2SH-32 is ~break-even on the body, with
P2SH-32 paying an extra ~35 B/output hash wrapper (~35 × 26 ≈ 910 B/cycle).
That is the price of unlimited script headroom. Keep P2S while minimal-slot
fits; treat P2SH-32 as the pressure-release valve, not the default.

Parked: Schnorr/FROST signature aggregation (collapse 13 sigs → 1) is the large
fee lever but a known dead-end for now — BIP-340 ≠ BCH-Schnorr and no Rust crate
exposes the BCH variant. Re-open only if such a crate appears.
