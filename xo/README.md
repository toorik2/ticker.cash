# ticker.cash × XO

[XO](https://xo.cash) (General Protocols) is a wallet engine driven by **templates**: JSON documents that
describe roles, actions, inputs, outputs and CashAssembly scripts, so that any XO wallet can take part in
a contract it has never seen before. These templates put the ticker.cash BCH/USD oracle into that world.

| template | what it does | status |
|---|---|---|
| `ticker-read` | decodes a Ticker commitment: timestamp, update counter, price in cents, rows that signed | parses, compiles, imports; **`data` actions are still work in progress in the XO engine**, so the wallet shows the decoded fields in the action text but cannot "run" the read |
| `ticker-stamp` | **pay at the oracle price**: a payment that co-spends the newest Ticker and re-emits it with the 1,000-sat toll, so the transaction carries the consensus-verified rate it was priced at | **paid on chipnet** from a headless XO engine (`cb2195f4…`, see below); needs an app that supplies the Ticker input |
| `ticker-genesis` | **instantiate an oracle**: mint a v27 head over a notary table of your choice with your own reserve, in two actions (`fund`, `create`) | parses, compiles, imports; needs an app that pins the funding coin (see below) |

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

Things the engine taught us, all now reflected in the templates: covenant bytecode goes into a script as a
raw `0x…` literal, because output locks compile through libauth, which knows template variables but not
constants; locks and outputs that belong to someone else (the recipient, the oracle head) carry
`roles.<role>.relevant: false`, or the wallet starts tracking the recipient's coins as its own; and the
Ticker's unlocking script is a single `OP_0`, supplied with the input since the engine only compiles
unlocking scripts for coins it owns.

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
transaction is invalid by consensus and nothing is lost. The result is a live oracle whose head address is
the same as ticker.cash's (every v27 oracle shares the lock), told apart by category, and whose first update
can be built by anyone running `ticker-node` against that table.

## What XO cannot express yet

* **k-of-n participants.** Rotation (`rotate()`) needs approvals from a strict majority of the table's rows.
  XO templates have fixed roles with slot counts, and every participant in a role fills the same variable
  set, so "7 of 13 rows each sign one approval" has no representation: there is no aggregation of one
  variable across slots. A governance template waits for per-slot variables or an aggregation primitive in
  the template format; we have raised it with General Protocols.
* **Token genesis.** No primitive yet; hence the two-step `ticker-genesis`.
* **Data actions.** Schema accepts them, the engine ignores them; hence `ticker-read` is a decoder, not a
  live view.
* **Foreign outputs.** The engine tracks outputs of the wallet's own roles only. Apps must supply the Ticker
  (as they already supply pool coins in XO's own wrapped-cash template).

## Chipnet constants

| | |
|---|---|
| category | `8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b` |
| Ticker lock (P2S, 55 B) | `76009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f75810380510193b1755168` |
| Oracle lock (P2SH-32, 35 B) | `aa20a9f9c3bcf15f1fe97aa1ccbe13ea77cbf77fb5cdd0f20dde98798b9aaac0e87487` |
| Ticker value / toll | 792 sats / 1,000 sats |
| VM | `BCH_2026_05` |
