# ticker.cash × XO

[XO](https://xo.cash) (General Protocols) is a wallet engine driven by **templates**: JSON documents that
describe roles, actions, inputs, outputs and CashAssembly scripts, so that any XO wallet can take part in
a contract it has never seen before. These templates put the ticker.cash BCH/USD oracle into that world.

| template | what it does | status |
|---|---|---|
| `ticker-read` | decodes a Ticker commitment: timestamp, update counter, price in cents, rows that signed | parses, compiles, imports; **`data` actions are still work in progress in the XO engine**, so the wallet shows the decoded fields in the action text but cannot "run" the read |
| `ticker-stamp` | **pay at the oracle price**: a payment that co-spends the newest Ticker and re-emits it with the 1,000-sat toll, so the transaction carries the consensus-verified rate it was priced at | **paid on chipnet** from a headless XO engine (`cb2195f4…`, see below); needs an app that supplies the Ticker input |
| `ticker-genesis` | **instantiate an oracle**: mint a v27 head over a notary table of your choice with your own reserve, in two actions (`fund`, `create`); the template computes the genesis commitment itself | **a second oracle was instantiated on chipnet** from a headless XO engine (`03796b8f…`) and received its first update from the public notaries' statements (`26bfb3e8…`, see below) |
| `ticker-rotate` | **change the notary table by majority**: one role per row (13), each row pastes its approval, the template assembles the covenant's `rotate()` spend and the chain enforces 7 of 13 | **a 7-of-13 rotation was posted on chipnet** by eight XO wallets (`310fa7aa…`, see below); the unlocking script is byte-identical to the Rust builder's |

All three share `templates/common.mjs`: the two protocol constants (the 55-byte Ticker lock and the 35-byte
Oracle lock, identical for every v27 deployment), the ticker.cash category, and the CashAssembly that
decodes a 17-byte commitment.

## Build and verify

```
npm install
npm run build      # round-trips each template through @xo-cash/utils parseTemplate/serializeTemplate → dist/*.json
npm test           # compiles every CashAssembly fragment with XO's compiler against a real Ticker commitment
npm run check      # type-checks the templates against @xo-cash/types
```

`dist/*.json` is what the [XO Web Dev Wallet](https://gitlab.com/GeneralProtocols/xo/xo-web-devtool) import
modal accepts (Templates → Import, paste the JSON). The identifiers printed by the build are the template
identifiers XO derives from the content. All three also import into a headless `@xo-cash/engine` on chipnet,
and the engine creates invitations for every action and reports exactly the requirements the templates declare.

## Live test: an XO engine paid at the oracle price (chipnet, 2026-10-25)

```
npm run stamp -- address                               # prints the tool's throwaway wallet address; fund it
npm run stamp -- pay bchtest:… 5000                    # dry run: finds the newest Ticker, builds, shows the transaction
npm run stamp -- pay bchtest:… 5000 -- --broadcast     # sends it
```

`tools/stamp-live.mjs` drives `@xo-cash/engine` the way the Dev Wallet does: it finds the newest Ticker
through the engine's Electrum helper, creates the `pay` invitation with the Ticker as input 0 and the
variables, appends the two template outputs (the engine derives value, lock and token from the variables),
appends a wallet coin as the funding input, adds change, signs its own input and executes.

| | |
|---|---|
| transaction | `cb2195f4ab719844c603124fd481466f2b3294d5b575071579e673f7aeba3c46` (377 B, fee 560 sats) |
| Ticker consumed | counter 37, minute 1792945680 (16:28 UTC), 275.31 USD/BCH, 13 rows; re-emitted at output 0 with 1,792 sats |
| payment | 5,000 sats at output 1; change at output 2 to the template's payer key |

## Live test 2: an XO engine instantiated an oracle (chipnet, 2026-10-25)

```
npm run genesis -- fund 18000 --broadcast     # a coin at the founder key, pinned to output 0 of its transaction
npm run genesis -- create 17680 --broadcast   # spend it at input 0 into a new head over ticker.cash's table
npm run genesis -- release                    # archive open invitations so the coins they reserved are spendable again
```

| | |
|---|---|
| funding | `ba3dfff849ec7adf2bcbbc0f87911ed55907a96a45a2a41b3f4d58cc06fd5448` (219 B): 18,000 sats at the founder key, output 0 → the new category |
| genesis | `03796b8feb6fa200dfdf5aee5e998eba92c1fd9d7f9c517428b64e3960c1dc47` (267 B, fee 320 sats): one input, one output: 17,680 sats at the shared v27 Oracle lock, minting NFT, commitment `1792946580 ‖ 0 ‖ 0 ‖ 0 ‖ 0 ‖ f6118ff8…` |
| first update | `26bfb3e8075cfdb496eb15a101e3771f3cc9a2c09970724dee25417f1b90a330`: built by `ticker-node build --once` from a second home whose manifest names the new category; counter 1, k = 13, 275.30 USD at minute 1792946640, the same minute and price as ticker.cash's own counter-53 update, from the same 13 statements |

Nobody told the notaries. Their statements name no deployment, so a head that lists their keys consumes them
from its first minute; the two heads sit at the same address and differ only by category. The new instance
is a demonstration and is not kept running: its reserve (13,759 sats after the update) pays for a few more
updates if anyone points a builder at it.

## Live test 3: eight XO wallets rotated an oracle's table, 7 of 13 (chipnet, 2026-10-25)

```
npm run genesis -- create 25600 --manifest vector-table.json --funding <txid>:0 --broadcast   # a throwaway oracle over the 13 test keys
npm run rotate -- <category> <newTableHex> --signers 0,1,2,3,4,5,6 --keys keys.json --old-table-file table.hex --broadcast
```

The operator's wallet creates the `rotate` invitation naming the head, the current table and the new table.
Seven row wallets, each its own process (the engine keeps one Electrum pool per process), accept it in turn,
join `row0` … `row6` and commit their approval; for the test the tool signs with the repository's test keys in
place of `ticker-notary sign-rotate`. Back at the operator, the six absent rows are recorded as empty
approvals, the engine compiles the covenant's unlocking script from the merged variables, and posts.

| | |
|---|---|
| oracle | genesis `ff9d3010304fcc94ba427fd86a050cb70b09c603f29d1c9ea2cba70f55306405`, category `5bfd04fd…`, over the 13-row table of `contracts/test/v27-vectors.json` |
| rotation | `310fa7aacd86…` (1,651 B, unlocking data 1,482 B, fee 1,700 sats): table hash `955b819f…` → `e848f6d4…` (the same table minus row 12), counter and reserve carried over |
| byte check | the template's `rotateUnlock`, compiled through libauth as the engine does, is identical to the Rust-built unlocking script of the rotation vector; the next commitment and the approval message match the vector too (`npm test`) |

Nothing new was asked of XO for this. The format already had what a majority vote needs: a role per row with
zero or one participant, variables bound to roles, an unlocking script the engine compiles from everyone's
commits, and CashAssembly loops (`OP_BEGIN`/`OP_UNTIL`) to fold thirteen optional approvals into the
covenant's `rows` and `sigs` arguments.

## What the engine taught us

All of it is reflected in the templates and the tools:

* **Covenant bytecode goes into a script as a raw `0x…` literal.** Output locks compile through libauth,
  which knows template variables but not constants, so `$(<someConstant>)` fails there.
* **Two value conventions.** Inside locking and unlocking scripts (compiled by libauth) a hex variable is raw
  bytes. In token fields, values and descriptions (evaluated by `@xo-cash/utils`) a variable is UTF-8 text,
  and token fields are read back as hex text. So a decoder asks the primitive for bytes
  (`<tickerCommitment.toBytes>`, type `nft_commitment`), a table with no primitive type is decoded from hex
  text by a CashAssembly loop, and a computed commitment is hex-encoded by another loop before the engine
  reads it (`HEX_DECODE`, `HEX_ENCODE` in `templates/common.mjs`). Loops run fine in the evaluator: decoding
  442 bytes of table, hashing it and encoding the commitment takes about 150 ms.
* **Foreign locks and outputs carry `roles.<role>.relevant: false`** (the recipient, the oracle head), or the
  wallet starts tracking the recipient's coins as its own.
* **Inputs the wallet does not own come with their unlocking script.** The Ticker's is a single `OP_0`; the
  engine only compiles unlocking scripts for coins it owns.
* **Generated keys need the start intent.** `createInvitation` takes the template's `start` entry as
  `intent` (it carries `generate: ['founderKey']`); giving `roleIdentifier` as well is an error.
* **Coins committed to an invitation stay reserved** until it executes or is archived; the tools archive
  their dry runs and offer `release`.
* **Fee and dust.** The engine's fee estimate undershoots token outputs and will emit a change output below
  the dust limit; the genesis tool leaves a small remainder as the fee instead.

## How each template works

### `ticker-read`

A Ticker's commitment is `timestamp(4) ‖ messageSequence(4) ‖ dataSequence(4) ‖ price(4) ‖ k(1)`, little
endian, price in US cents. The template's `data` section decodes each field with `OP_SPLIT`/`OP_BIN2NUM`, and
its action text renders as, for example:

> BCH/USD 275.80, minute 1792944840, update 23, signed by 13 rows.

The engine does not yet execute `data` actions (they are accepted by the schema and ignored by the engine),
and it only tracks outputs that belong to the wallet's own roles, so it does not discover Tickers on its own.
Today the reader pastes the commitment (34 hex characters, straight from `usd.ticker.cash/stats` or any
chipnet explorer). When XO gains data actions and foreign-output tracking, the same template shows the live
price without a server in between.

### `ticker-stamp`

The transaction is `[Ticker, payer coins…] → [Ticker + 1,000 sats, payment, change]`. The Ticker covenant
requires the re-emitted Ticker at the same output index as its input, so both are pinned to index 0; the
payer's wallet funds the rest through XO's automatic coin selection and signs only its own inputs. The
Ticker is spent with an empty unlocking script (`consumeTicker: 'OP_0'`), which is the `consume()` branch.

An XO engine does not scan the Ticker lock for the newest Ticker. The app that creates the invitation does,
exactly as the wrapped-cash dapp supplies the pool coin: it looks up the latest Ticker of the category
(`contracts/tools/live-consume.mjs` shows the Electrum queries), fills `tickerCommitment` and
`tickerSatoshis`, and attaches the input with `outpointTransactionHash`/`outpointIndex` and `inputIdentifier:
'tickerInput'`. Two payers who pick the same Ticker race for it; the loser's transaction is rejected and the
app retries with the Ticker the winner just re-emitted, which is identical in content.

### `ticker-genesis`

v27 statements name no deployment, so a head whose table lists public notaries can consume their statements
from its first minute: instantiating an oracle is a single transaction, and the only per-instance inputs are
the **table** (`n × (compressed pubkey ‖ exchange id)`) and the **reserve**.

CashTokens fixes a category at genesis as the txid of the coin spent at input 0, and that coin must be output
0 of its transaction. The XO engine has no genesis primitive, so the template splits the job in two:

1. `fund` receives the reserve-to-be at the founder's own key. The app checks the coin landed at output 0.
2. `create` spends exactly that coin at input 0 and mints the head: output 0 is the Oracle lock with a
   minting NFT whose commitment is built in CashAssembly as
   `timestamp ‖ 0 ‖ 0 ‖ 0 ‖ 0 ‖ hash160(table)`, holding the reserve.

The app supplies `category` (the funding coin's txid) and pins the coin as the input; if either is wrong the
transaction is invalid by consensus and nothing is lost. In a wallet, `create` is offered on the funding coin
itself, which pins the input and prefills its value; the category is the one value still typed in. The result is a live oracle whose head address is
the same as ticker.cash's (every v27 oracle shares the lock), told apart by category, and whose first update
can be built by anyone running `ticker-node` against that table.

## What the format can do, and the one thing it cannot

We first believed two things were missing from XO and would have to be requested: a way to gather one value
from each of several participants (for 7-of-13 approvals) and a way for a template to compute a token
commitment. Both turned out to be expressible: the rotation template gathers approvals through thirteen
single-slot roles and folds them with a loop, and the genesis template computes its commitment with
`hash160` and a hex-encoding loop. Three live transactions back this up.

What remains:

* **The category of a new token.** CashTokens fixes it as the txid of the coin spent at input 0. We looked
  for a template-side way and found none: output token fields are evaluated without a transaction context,
  and the Dev Wallet's follow-up suggestions cover token fields and declared state, not outpoints. So
  `ticker-genesis` takes `category` as a variable the app, or the user from the coin picker, fills in. The
  fix is on the engine side and small: pass libauth a compilation context while output token fields are
  evaluated, and `<signing_serialization.outpoint_transaction_hash>`, a built-in libauth already has, yields
  input 0's txid. We prototyped it in nine lines and built a genesis whose category the template derived
  itself; see `notes/engine-compilation-context.md`. This is the single request worth making, and it was
  made on 2026-10-25: General Protocols call it a known gap on their todo list, probably landing after
  BLAZE, so the typed category stays for now. A mistyped one is rejected by consensus.
* **Follow-up from the coin.** The Dev Wallet offers a template's actions on coins it holds when the locking
  script lists them, and prefills variables the script declares as `state`. `ticker-genesis` now offers
  `create` on the funding coin with `fundingSatoshis` carried along, so the user types the reserve, the
  timestamp and the category, and nothing else.
* **Data actions.** Schema accepts them, the engine ignores them; hence `ticker-read` is a decoder, not a
  live view.
* **Foreign outputs.** The engine tracks outputs of the wallet's own roles only. Apps supply the Ticker (as
  they already supply pool coins in XO's own wrapped-cash template); the rotation template has the operator
  track the Oracle lock, which is how the engine comes to know the head it spends.
* **Quality of life**, worth mentioning to General Protocols: a `bytes` primitive with `toBytes` would remove
  the decode loops; a dust-aware change policy for token outputs; the post-broadcast bookkeeping that can
  lose a race with the spend notice; one Electrum pool per process, which rules out several wallets in one
  process.

## Chipnet constants

| | |
|---|---|
| category | `8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b` |
| Ticker lock (P2S, 55 B) | `76009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f75810380510193b1755168` |
| Oracle lock (P2SH-32, 35 B) | `aa20a9f9c3bcf15f1fe97aa1ccbe13ea77cbf77fb5cdd0f20dde98798b9aaac0e87487` |
| Ticker value / toll | 792 sats / 1,000 sats |
| VM | `BCH_2026_05` |
