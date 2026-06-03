# V22-OC-22 — Oracle quorum bypass via unpinned slot tokenCategory

| Field              | Value                                                |
| ------------------ | ---------------------------------------------------- |
| Finding ID         | V22-OC-22 (Latent Labs F01)                          |
| Severity           | Critical                                             |
| Class              | Class-1 (any-party adversarial)                      |
| Affected           | v22 deployment (chipnet, all cycles 1..N)            |
| Discovered         | 2026-05 Latent Labs red-team engagement              |
| Closed             | v23 (chipnet re-genesis, 2026-06-03)                 |
| Disclosure         | Public after fix landed; no mainnet exposure         |

## Summary

`Oracle.update()` iterates `tx.inputs[1..=numAttestations]` and reads each
input's NFT commitment as a "slot attestation". The covenant verified the
commit shape, freshness, and quorum size — but never verified that the inputs
were actually slot UTXOs.

Any party can mint an arbitrary CashTokens NFT in any category, give it the
17-byte commitment shape a slot uses, and feed seven of them into a fake
Oracle.update. The covenant accepts the input set as a 7-of-13 quorum and
mints valid Tickers reflecting the attacker's chosen median.

The 7-of-13 publisher trust root collapses entirely: an attacker with zero
slot-key custody can publish arbitrary prices over the legitimate Oracle UTXO.

## Reproduction

The PoC built via mem-cash + cashscript-sdk:
1. Mint a category-X mutable NFT with the slot commit layout (pkh, cycleSeq,
   timestamp, sourceId, price).
2. Repeat for seven distinct synthetic pkhs (or seven distinct categories).
3. Build `Oracle.update` with `input[0] = real Oracle UTXO`, `inputs[1..=7] =
   fake NFTs`, `input[8] = funder UTXO`. Re-emit "slots" at matching outputs.
4. Tx is consensus-accepted; Tickers minted reflect attacker median.

Validated against v22 chipnet artifacts: **PoC accepted**, vuln confirmed.
Validated against v23 artifacts: **PoC rejected** at the per-iter slot
category check, fix confirmed.

## Root cause

The covenant's iteration logic dereferences `tx.inputs[slotIdx].nftCommitment`
without first checking `tx.inputs[slotIdx].tokenCategory`. CashScript does not
implicitly type-pin inputs; the commitment field is just opaque bytes that
happen to be 17 B long on a slot. The vuln is the missing pin, not a logic
error in the surrounding median / quorum code.

## v23 fix (F01)

Inline the slot category as a 33-byte literal (`slot_category_reversed ||
0x01` for the mutable capability suffix) in the Oracle body, then assert
inside the per-iter loop:

```cashscript
bytes slotCatWithCap = 0xBABEFACE...01;   // 33-byte placeholder
do {
    int slotIdx = i + 1;
    require(tx.inputs[slotIdx].tokenCategory == slotCatWithCap);
    bytes slotCommit = tx.inputs[slotIdx].nftCommitment;
    // ... existing logic unchanged
}
```

The placeholder bytes are substituted at deploy time from the slot genesis
outpoint — same pattern used by the v22 PublisherSlot template, audited
to appear at exactly one byte offset in the compiled body.

Body size impact: 421 B → 460 B (+39 B). Per-cycle cost: ≈ $58/yr at chipnet
prices (2.3% of v22 fee-economics wins).

## Why this slipped past v22 review

The v22 design discussion centred on slot template specialization (pkh,
cnHash, oracleCatHash baked into the per-source slot bodies) and the slot
commit's source identifier. The slot covenant's category was treated as
"obviously" the binding by virtue of the slot's own redeem script — but the
Oracle covenant never looks at slot redeem scripts, only at the NFT
commitment bytes. The category pin was structurally absent, not gated and
forgotten.

The audit caught it because Latent Labs treated the slot category as an
attack-surface input rather than a deployment constant.

## Permanent regression coverage (v23)

Three Rust tests in `node/core/src/covenant/redeem.rs` enforce the v23
invariant:

1. `oracle_template_placeholder_appears_exactly_once` — placeholder is at
   exactly one offset in the compiled body. A future cashc release that
   inlined the literal twice would silently substitute only one site and
   leave the second as live BABEFACE bytes — trips this test.
2. `oracle_specialized_body_contains_no_babeface_marker` — after
   substitution no BABEFACE quad survives. Catches partial substitution.
3. `oracle_v23_template_fingerprint` — pinned sha256d of the compiled body.
   Any cashc upgrade or source edit forces a human to re-verify the F01
   pin site before re-pinning the fingerprint.

The mem-cash PoC scripts remain in the Latent Labs engagement archive as
the adversarial proof; the Rust tests are the structural guardrails.

## Trust-model implication

V22-OC-22 was Class-1 (any-party adversarial). The threshold-absorbed trust
model adopted in v23 holds that Class-1 gates MUST be closed in the covenant,
while Class-2 gates (in-federation misbehavior) can be absorbed by the 7-of-13
threshold. v23 closes F01 because it would have allowed bypass by an entirely
out-of-federation attacker; the curated scope explicitly accepted Class-2
findings (F03..F07, F09) as absorbed.

## Lessons learned

* For every `tx.inputs[i].X` read in a CashScript loop, the category of input
  `i` is an implicit precondition that MUST be either statically known
  (single-input position, redeem-script binding) or asserted in-loop. v23
  Oracle is the latter; v22 PublisherSlot is the former.
* Per-input position assumptions ("input[k] is always a slot") cannot be
  inherited from comment or convention. The covenant has to assert them.
* Template-literal substitution (the v22 slot pattern, now v23 Oracle) is a
  clean way to bake deploy-time constants into a body while keeping the
  source independent of any one deployment.
