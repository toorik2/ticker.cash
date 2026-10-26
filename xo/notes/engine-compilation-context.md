# Proposal to XO: resolve libauth built-ins in output token fields

**Status (2026-10-26).** Raised in the XO chat on 2026-10-25 as a feature ask (let a template name input 0's
txid as a token category). Jonathan (XO team) answered on 2026-10-26: token genesis handling is on
the todo list, "a gap / not well handled today"; with BLAZE this close it may not land before it, so work
around it for now; Kiok has been notified. The workaround is in place: `ticker-genesis` takes `category` as a
typed `token_category` variable, `create` is offered on the funding coin so the input is pinned and its value
prefilled, and a mistyped category is an invalid transaction by consensus, so nothing can be lost. When the
engine gains the context, the template change is the one line under "Result" and the variable goes away.

Kiok (XO team) confirmed the same day: partial introspection evaluations are not yet supported,
since a transaction context has to be passed even for the smallest evaluation; it is in the pipeline, highly
likely after BLAZE. His workaround is the one this template already uses: pass the chosen genesis input's
`outpointTransactionHash` as a variable in the action's requirements and fill the token category of any
output from it by CashAssembly evaluation, as `wrapped_cash.ts` does from a constant (line 142) and
`experimental/multisig.ts` does with generated public keys that each signer also passes as a variable, kept
as locking-script `state` so the script can be rebuilt from stored variables alone. Once the support lands,
the engine will work the value out on its own and the variable goes away.

**Problem.** CashTokens fixes a new category as the txid of the coin spent at input 0. A template cannot
express that today: output token fields (`token.category`, `token.nft.commitment`) are evaluated by
`compileCashAssemblyString` without a transaction context, so libauth's `signing_serialization.*` built-ins
are unavailable there, and `collectVariablesUsingParseScript` reports them as missing variables. The app has
to read the funding coin's txid and pass it in as a variable.

**Observation.** libauth already knows how to say "input 0's txid": with a `compilationContext` whose
`inputIndex` is 0, `<signing_serialization.outpoint_transaction_hash>` evaluates to exactly those 32 bytes,
in display order, in any script, not only unlocking scripts. No new template keyword is needed.

**Change (nine lines, prototyped against `@xo-cash/utils` 0.0.10 and `@xo-cash/engine` 0.1.0-next.17446870453).**

In `@xo-cash/utils`, `compileCashAssemblySourceToBytes` and `generateCashAssemblyBytecode`:

* let `compileCashAssemblyString` accept an optional `compilationContext` and pass it through to
  `compiler.generateBytecode({ data: { bytecode, compilationContext }, scriptId })`;
* do not treat identifiers starting with `signing_serialization.` or `current_block_` as template variables
  (skip them in the missing-variable check and in the bytes conversion).

In `@xo-cash/engine`, `mergeInvitationCommits`: before `resolveMergedOutputs`, build a context from the
merged input at transaction index 0 when its outpoint is known

```js
{ inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: new Uint8Array(), valueSatoshis: 0n }],
  transaction: { version, locktime,
    inputs: [{ outpointTransactionHash, outpointIndex, sequenceNumber: 0, unlockingBytecode: new Uint8Array() }],
    outputs: [] } }
```

and hand it to `resolveTemplateTokenCategory` / `resolveTemplateTokenNft` (and, for the same price, to
`resolveTemplateOutputLockingBytecode`).

**Result.** With the patch applied locally, `ticker-genesis` with

```
token: { category: '$(<signing_serialization.outpoint_transaction_hash> HEX_ENCODE)', … }
```

and no `category` variable built, on chipnet, a genesis whose output category equals the funding coin's
txid (`e7f222bbe4f8f7ea317c9a8c3cbe1efc258a0dee097a725d4414becda1f429ff`, 267 B). `HEX_ENCODE` is the
template-side loop that turns bytes into the hex text the token decoder expects; if the decoder accepted
raw bytes as well, even that would go away. The transaction was built as a dry run and not broadcast; the
packages were restored afterwards.

**Why it matters.** Instantiating a price oracle then becomes a pure template: fund a coin, spend it,
nothing typed by anyone. Rotation (7 of 13 approvals) and consumption already are.

Related, smaller: a `bytes` primitive with `toBytes`; a dust-aware change policy for token outputs; the
post-broadcast bookkeeping that can lose a race with the spend notice; one Electrum pool per process.
