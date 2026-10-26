---
name: xo
description: Agent-facing, condensed knowledge base on XO by General Protocols (xo.cash) - the wallet-template format (@xo-cash/types), the headless engine (@xo-cash/engine), the Dev Wallet UI, how CashAssembly is evaluated in each part of a template, and every empirical gotcha found while building and running ticker.cash's templates on chipnet. Load it whenever XO, xo.cash, any @xo-cash package, XO templates, invitations, commits, the Dev Wallet, wrapped-cash/AnyHedge/multisig template patterns or "can a wallet do X with our covenant" come up, even indirectly, and before touching xo/ in this repo. Append new findings (dated) whenever a test teaches something; prune what turns out wrong.
---

# XO (General Protocols) - working knowledge

Dense notes for the agent. Facts, not prose. Dates mark when something was observed; re-verify old ones
against package versions. Keep under ~300 lines; move long catalogues to `references/`.

## 1. What it is, where it lives

- XO = a wallet-template standard + engine from General Protocols (GP). A template declares roles, actions,
  transactions, inputs/outputs, locking scripts, CashAssembly scripts, variables, constants. Wallets
  (the engine) build transactions from *invitations*: a chain of *commits* by entities holding roles.
- Repos (GitLab, `gitlab.com/GeneralProtocols/xo/`): `templates` (format + reference templates;
  `development` branch has `source/wrapped_cash.ts`, `source/p2pkh.ts`, `source/experimental/multisig.ts`),
  `engine`, `xo-web-devtool` (the Dev Wallet, React/Vite, `source/logic/...`).
- npm (versions used 2026-10-25): `@xo-cash/engine@next` = 0.1.0-next.17446870453, `@xo-cash/state` 0.0.5,
  `@xo-cash/types` 0.0.8, `@xo-cash/utils` 0.0.10, `@xo-cash/primitives` 0.0.3, `@xo-cash/templates` 0.0.11.
  Also `@bitauth/libauth` (the compiler underneath).
- Ours: `xo/templates/{common,ticker-read,ticker-stamp,ticker-genesis,ticker-rotate}.mjs`, built JSON in
  `xo/dist/*.json` (what a wallet imports), `xo/build.mjs`, `xo/test.mjs` (27 checks), live tools in
  `xo/tools/{stamp,genesis,rotate}-live.mjs`, notes in `xo/notes/`, user-facing summary in `xo/README.md`.
  Throwaway wallets: `~/.ticker-xo/` (mnemonic 0600, IndexedDB under `db/`), row wallets `~/.ticker-xo/rows/`.
- People: Jonathan and Kiok (GP) answer in the XO group chat; both responsive within a day (2026-10-26).

## 2. Template format - the parts that bite

- Top level: `$schema` (libauth wallet-template-v0), `name`, `description`, `icon`, `version`, `supported`
  (`BchVmVersion[]`, e.g. `['BCH_2026_05']`), `resources[]`, `defaults{change,address,receive}`, `roles`,
  `start[]`, `actions`, `transactions`, `inputs`, `outputs`, `lockingScripts`, `scripts`, `constants`,
  `variables`. A read-only template still needs `inputs: {}` and `outputs: {}` or the parser rejects it.
- `start[]` entries `{action, role, generate:[keyVars]}`: pass one of these as `intent` to
  `createInvitation`; it is what makes the engine generate keys. Do not also pass `roleIdentifier` with an
  intent (`InvitationRoleDuplicatedError`). Without intent: `LockingScriptSecretsNotFoundError`.
- `actions.<a>.roles.<r>.requirements: {secrets:[...], variables:[...]}`: a variable listed under a role must
  be committed by an entity holding that role or any role listing it (`assertRoleVariablesProvidedByRoleEntities`).
  Later commits overwrite earlier values of the same variable. Operator can list all per-row variables so
  absent participants can be recorded as empty values.
- `actions.<a>.requirements.participants: [{role, slots:{min,max}}]`: roles with min 0 max 1 are optional
  single-slot participants. That is how k-of-n is expressed: n single-slot roles + a fold in CashAssembly.
- `transactions.<t>`: `inputs:[{input, inputIndex}]`, `outputs:[{output, outputIndex}]` (index may be
  `undefined` = anywhere), `version`, `locktime`; descriptions evaluated (see §3).
- `inputs.<i>`: `valueSatoshis`, `token` (null or `{category, amount, nft}`), `unlockingScript` (the name
  says "script" but it is the raw unlocking *bytecode* script; GP TODO to rename).
- `outputs.<o>`: `lockingScript`, `valueSatoshis`, `token: {category, amount: bigint|string|null, nft:
  {capability, commitment}}`, `roles.<r>.relevant: false` so the wallet does not track a foreign output as
  its own (recipient coins, covenant heads not held by that role).
- `lockingScripts.<l>`: `lockingType` p2pkh|p2sh|p2s, `lockingBytecode` (script id), `unlockingBytecode`
  (script id), `actions:[{action, role}]` (follow-up actions a wallet offers on a coin held here),
  `selectable` (false keeps a covenant out of coin selection), `state.variables` (variables stored with the
  coin and prefilled for follow-ups; also lets the script be rebuilt from stored variables, cf. GP multisig),
  `roles.<r>.{relevant, state:{variables,secrets}}`, `balance{satoshis,fungibleTokens,nonfungibleTokens}`.
- `constants.<c> {name, description, type, value}` merge into variables for `$()` evaluation
  (`mergeTemplateConstantsWithInvitationVariables`) but are unknown to the libauth path (§3).
- `variables.<v> {name, description, type}`; primitive types with `.toBytes` include nft_commitment,
  token_category, public_key, schnorr_signature, transaction_hash, satoshis, timestamp, locking_script,
  private_key, integer, bytes. No primitive for arbitrary-length bytes beyond `bytes` (text in `$()`).
- `conditions`, `importDefaultValue`, `data` actions: accepted by the schema, ignored by the engine (2026-10).

## 3. Two evaluation paths - the single most important fact

1. **Locking/unlocking scripts** compile through libauth (`createCompilerBch`, `generateBytecode`,
   `convertInvitationVariableValueForCompiler`): a hex-string variable (type bytes or isHex) is raw bytes;
   template *variables* are known, *constants* are not -> covenant bytecode goes in as a raw `0x…` literal
   inside the script, never via a constant (`LockingBytecodeGenerationFailedError: Unknown identifier`).
   `<var.public_key>`, `<var.schnorr_signature.all_outputs>` resolve here.
2. **Token fields, valueSatoshis, descriptions** evaluate through `compileCashAssemblyString` (utils):
   string variables are UTF-8 *text*; a token category/commitment expression's result is decoded as utf8 and
   parsed as hex text; valueSatoshis as bigint. Typed variables arrive as text too, so decode with
   `<var.toBytes>` (e.g. `tickerCommitment` typed `nft_commitment`). No transaction context here:
   `signing_serialization.*` and `current_block_*` are reported as missing variables.
- A description holds one kind of evaluation only (all numbers or all text); mixing fails.
- Loops (`OP_BEGIN`/`OP_UNTIL`) work in XO's evaluator on BCH_2026_05. Helpers in `xo/templates/common.mjs`:
  `HEX_ENCODE` (bytes -> hex text, what token fields want), `HEX_DECODE` (hex text -> bytes, for `bytes`
  variables such as a 442-B table), `REVERSE_BYTES` (display-order txid -> VM order). Loop idioms that
  work: `<0x00> OP_CAT OP_BIN2NUM` to read a byte unsigned; keep the remainder on the stack and test
  `OP_SIZE OP_0 OP_NUMEQUAL` as the until-condition.
- `compileCashAssemblyString` is wrong for push-containing unlocking scripts; for byte-exact checks use
  libauth `createCompilerBch({scripts, variables, lockingScriptTypes, unlockingScripts})` +
  `generateBytecode({data:{bytecode, compilationContext}, scriptId})`. With a `compilationContext`,
  `<signing_serialization.outpoint_transaction_hash>` evaluates in any script (display-order txid of the
  input at `inputIndex`); OP_EVAL is not available in evaluation.

## 4. Engine - API and the flow that works (headless, Node)

- `Engine.create(mnemonic, {network:'chipnet', storageType: StorageType.INDEXEDDB, databasePath})`.
  sqlite storage stores templates only; use INDEXEDDB (indexeddbshim) for coins. One Electrum pool per
  process: a second `Engine.create` in one process fails ("Cannot configure storage for cache") -> one
  wallet per child process. Always `engine.stop()`.
- Setup: `importTemplate(json) -> {templateIdentifier}`; `setDefaultPolicies({address, change, receive})`
  from `p2pkhTemplate` when `getDefaultPolicies().address` is unset.
- Flow: `createInvitation({templateIdentifier, actionIdentifier, intent, variables:[{variableIdentifier,
  value}], inputs:[{inputIdentifier, transactionIndex, roleIdentifier, outpointTransactionHash:Uint8Array,
  outpointIndex, valueSatoshis:bigint, unlockingBytecode?}]})` -> `appendInvitation(id, {templateIdentifier,
  actionIdentifier, outputs:[{outputIdentifier, transactionIndex, roleIdentifier?}] | inputs:[...]})` ->
  `appendOwnOutputResolutions(id, outputId, role)` (own key outputs) -> `addChangeToInvitation(id)` ->
  `for i of listOwnInputIndexes(id): signInvitation(id, i)` -> `listMissingRequirements(id)` ->
  `buildInvitationTransactionFromMergedCommit(id) -> {serializedTransaction}` ->
  `executeAction(id, {broadcastTransaction:true}) -> {builtTransaction:{transactionHash}}`.
  Values: bigint for satoshis/integer, hex string for bytes/categories/commitments.
- Multi-party: `serializeInvitation` -> share -> other wallet `acceptInvitation(deserializeInvitation(json),
  {roleIdentifier, variables})` (wants the object, not the JSON string) / `joinInvitationRole`; originator
  `updateInvitation` with the returned serialized form; `listInvitations()` -> StoredInvitation
  `{invitation:{invitationIdentifier, templateIdentifier, actionIdentifier, commits}, entityIdentifier, isArchived}`.
- "Own" input = outpoint present in this wallet's UTXO store. `signInvitation` on a covenant input compiles
  the template unlocking script with no key. Covenant heads appear in `listSpendableUnspentOutputs()` only
  when an imported template tracks that lock for a role the wallet holds (e.g. ticker-rotate's operator);
  otherwise supply foreign coins explicitly (`fetchUnspentOutputsForLockingBytecode(lockHex, templateId)`,
  `fetchDecodedTransactionOutput`). `listSpendableUnspentOutputs` returns selectable, unreserved coins with
  `templateIdentifier, tokenCategory, outpointTransactionHash, outpointIndex, valueSatoshis, minedAtHeight`.
- Reservations: coins committed to an invitation stay reserved until it executes or is archived
  (`archiveInvitation`). `UnspentOutputReservationExternalConflictError` -> archive stale invitations first.
- Fee estimate undershoots token outputs -> can emit dust change (40-420 sats). Skip change when the
  remainder is under ~1,000 sats and let it be fee.
- After broadcast, `UnspentOutputNotFoundInStoreError` can fire when the spend notice wins the race against
  the bookkeeping; the tx is out. Save the hex before executing and tolerate it.
- Wrong coin picked (`TemplateUnlockingScriptNotFoundError`) = the engine fell back to a coin the template
  cannot unlock; filter candidates strictly (`templateIdentifier`, `tokenCategory === undefined`, vout).
- `generateLockingBytecodeFromDefaultPolicy` for the wallet's own address.

## 5. Dev Wallet (xo-web-devtool) facts

- Import a template = paste the built JSON (`xo/dist/*.json`). Invitations travel as pasted JSON too.
- On a coin held under a `lockingScripts` entry with `actions`, the wallet offers those actions; it pins the
  coin as the input and prefills variables from the coin's token fields and the script's `state.variables`.
  It never suggests outpoints/txids (2026-10-25 reading of `source/logic/invitation/*`).
- Missing requirements UI has **"Paste JSON"** (`import-missing-variables-json.ts`): flat `{varId: value}`,
  nested `{roleId:{varId:value}}`, or `[{variableIdentifier, value}]`; strings and numbers accepted.
  `genesis-live.mjs variables <reserve> --funding <txid>:0` prints such an object.
- Field placeholders: category "32 byte category hex", txid "64 character txid hex"; `locking_script`
  variables accept a CashAddress and convert it. Integer-like types reach the compiler as numbers
  (`default-policy-variables.ts`).
- Follow-up value suggestions from a UTXO exist only for p2pkh token send/burn.

## 6. Known gaps and their status (dated)

- **Token category = input-0 txid** cannot be expressed: token fields evaluate without tx context.
  GP (Jonathan, Kiok, 2026-10-26): known, on the todo list, likely after BLAZE; interim = pass the chosen
  input's txid as an action variable and fill `category: '$(<var>)'` (wrapped_cash.ts L142 uses a constant;
  experimental/multisig.ts passes generated public keys as variables + `state.variables`). Our proposal
  (nine-line engine change using libauth's `signing_serialization.outpoint_transaction_hash`):
  `xo/notes/engine-compilation-context.md`. When it lands: category expression
  `$(<signing_serialization.outpoint_transaction_hash> HEX_ENCODE)` and drop the variable.
- `data` actions not executed (ticker-read is a decoder shown in action text only).
- No `bytes` primitive with `.toBytes`; no raw-bytes acceptance in token decoders (hence HEX_* loops).
- Engine tracks outputs of the wallet's own roles only (apps supply foreign coins, as GP's wrapped-cash dapp does).
- Quality-of-life to raise with GP: bytes primitive, dust-aware change for token outputs, post-broadcast
  race, one Electrum pool per process.

## 7. Patterns proven live on chipnet (2026-10-25)

- **Consume a covenant NFT and re-emit it** (ticker-stamp): covenant input at index 0 with
  `unlockingBytecode: [0x00]`, re-emitted output index 0 with `valueSatoshis: '$(<v> <toll> OP_ADD)'`,
  payment at index 1, change via defaults; foreign lock/outputs `relevant:false`. tx `cb2195f4…`.
- **Genesis of a minting NFT** (ticker-genesis): two actions `fund` (coin at own key, pinned to vout 0) and
  `create` (that coin at input 0; `category` variable; commitment computed on-template with
  `OP_NUM2BIN/OP_CAT/OP_HASH160` + HEX_ENCODE). `founderLockingScript.actions:[{action:'create'}]`,
  `state.variables:['fundingSatoshis']`. tx `03796b8f…`, first covenant update `26bfb3e8…`.
- **k-of-n governance** (ticker-rotate): operator + 13 single-slot roles (min 0); per-row `bytes` variables
  (empty = absent); CashAssembly fold builds `rows`/`sigs`; unlocking script byte-identical to the Rust
  builder; 8 wallets in child processes; 7-of-13 rotation tx `310fa7aa…`. Approval message hashed by the
  covenant: `0x52 ‖ category(VM order) ‖ oldTableHash ‖ nextLock ‖ tail`.
- **Test harness** (`xo/test.mjs`): run decoders with hex-string variables exactly as the engine passes
  them; compare unlocking bytes with vectors via libauth; round-trip templates through
  `serializeTemplate/parseTemplate/generateTemplateIdentifier` in `xo/build.mjs`.

## 8. Error -> cause -> fix (quick table)

| error / symptom | cause | fix |
|---|---|---|
| parser: token.amount type | must be bigint, string or null | `amount: null` |
| TS literal widening on `supported` | plain array | JSDoc `/** @type {BchVmVersion[]} */` |
| `LockingBytecodeGenerationFailedError: Unknown identifier …` | constant used in lock/unlock script | raw `'0x'+hex` literal |
| wallet shows recipient's coins | foreign output tracked | `roles.<r>.relevant:false` |
| `TemplateUnlockingScriptNotFoundError` | engine fell back to unsignable coin | strict coin filter; reset db; `release` |
| `LockingScriptSecretsNotFoundError` | no key generated | pass `intent` = start entry |
| `InvitationRoleDuplicatedError` | roleIdentifier + intent | drop roleIdentifier |
| `NFTCommitmentInvalidError` | token expr result read as utf8 text | emit hex text (HEX_ENCODE) |
| dust change 40-420 sats | fee estimate undershoots tokens | no change under 1,000 sats |
| acceptInvitation fails on JSON | wants object | `deserializeInvitation` first |
| "Cannot configure storage for cache" | second Engine in process | child process per wallet |
| `UnspentOutputReservationExternalConflictError` | stale invitations | archive them at start |
| `UnspentOutputNotFoundInStoreError` after broadcast | bookkeeping race | tolerate; tx was sent |
| mixed description fails | numbers + text in one `$()` set | one kind per description |
| `CashAssemblyRequiredVariableMissingError: signing_serialization…` | no tx context in token fields | engine gap (§6) |

## 9. Maintaining this file

Append dated bullets to the section they belong to; rewrite a bullet when a newer observation contradicts
it; delete what a package release makes false (note the version). Prefer a measured fact (tx id, byte
count, error string) over a belief. Keep user-facing explanation in `xo/README.md`; this file is for us.
