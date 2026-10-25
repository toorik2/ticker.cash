// Pay at the oracle price: a payment that co-spends a ticker.cash Ticker and re-emits it with
// the toll, so the transaction carries the BCH/USD rate it was priced at, verified by consensus.
// The Ticker input is supplied by the app that creates the invitation (the newest Ticker of the
// category); the payer's wallet funds the rest and signs its own inputs.
import { COMMITMENT_DATA, COMMITMENT_SCRIPTS, COMMITMENT_VARIABLE, ORACLE_CATEGORY, SUPPORTED, TICKER_LOCKING_BYTECODE, TOLL_SATS } from './common.mjs';

/** @type {import('@xo-cash/types').XOTemplate} */
export const tickerStampTemplate = {
    $schema: 'https://libauth.org/schemas/wallet-template-v0.schema.json',
    name: 'Pay at the oracle price (ticker.cash)',
    description: 'Pays BCH while co-spending a ticker.cash BCH/USD Ticker, so the payment carries the on-chain rate it was priced at. The Ticker is recreated with a 1,000-satoshi toll that funds the oracle.',
    icon: 'send',
    version: '1',
    supported: SUPPORTED,
    resources: [
        { name: 'ticker.cash', description: 'The oracle: how the price is produced and how to read it.', url: 'https://usd.ticker.cash/docs' },
    ],

    defaults: {
        change: { output: 'changeOutput', role: 'payer', generate: [ 'payerKey' ] },
        address: { lockingScript: 'payerLockingScript', role: 'payer', generate: [ 'payerKey' ] },
        receive: { output: 'changeOutput', role: 'payer', generate: [ 'payerKey' ] },
    },

    roles: {
        payer: { name: 'Payer', description: 'The party paying BCH at the oracle price.', icon: 'sender' },
    },

    start: [
        { action: 'pay', role: 'payer', generate: [ 'payerKey' ] },
    ],

    actions: {
        pay: {
            name: 'Pay at the oracle price',
            description: 'Pay $(<paymentSatoshis>) satoshis at $(tickerDollars).$(tickerCentsTens)$(tickerCentsOnes) USD per BCH (minute $(tickerTimestamp), $(tickerRows) rows signed).',
            icon: 'send',
            roles: {
                payer: {
                    name: 'Pay',
                    description: 'Pay $(<paymentSatoshis>) satoshis to the recipient and stamp the payment with the oracle price.',
                    icon: 'send',
                    requirements: {
                        secrets: [ 'payerKey' ],
                        variables: [ 'recipientLockingScript', 'paymentSatoshis', 'tickerCommitment', 'tickerSatoshis' ],
                    },
                },
            },
            requirements: {
                participants: [ { role: 'payer', slots: { min: 1, max: 1 } } ],
            },
            transaction: 'payTransaction',
        },
    },

    data: COMMITMENT_DATA,

    transactions: {
        payTransaction: {
            name: 'Payment at the oracle price',
            description: 'Paid $(<paymentSatoshis>) satoshis at $(tickerDollars).$(tickerCentsTens)$(tickerCentsOnes) USD per BCH, backed by $(tickerRows) rows at minute $(tickerTimestamp).',
            icon: 'send',
            // The Ticker covenant requires the re-emitted Ticker at the same index as its input.
            inputs: [ { input: 'tickerInput', inputIndex: 0 } ],
            outputs: [
                { output: 'tickerOutput', outputIndex: 0 },
                { output: 'paymentOutput', outputIndex: 1 },
            ],
            version: 2,
            locktime: 0,
        },
    },

    inputs: {
        tickerInput: {
            name: 'Ticker',
            description: 'The newest ticker.cash Ticker: an immutable NFT whose commitment is the price message.',
            icon: 'contract',
            valueSatoshis: '$(<tickerSatoshis>)',
            token: {
                category: '$(<oracleCategory>)',
                amount: null,
                nft: { capability: 'none', commitment: '$(<tickerCommitment>)' },
            },
            unlockingScript: 'consumeTicker',
        },
    },

    outputs: {
        tickerOutput: {
            name: 'Ticker (re-emitted)',
            description: 'The same Ticker, recreated with the 1,000-satoshi toll that funds the oracle.',
            icon: 'contract',
            lockingScript: 'tickerLockingScript',
            valueSatoshis: '$(<tickerSatoshis> <toll> OP_ADD)',
            token: {
                category: '$(<oracleCategory>)',
                amount: null,
                nft: { capability: 'none', commitment: '$(<tickerCommitment>)' },
            },
            roles: { payer: { relevant: false } },
        },
        paymentOutput: {
            name: 'Payment',
            description: 'Paid $(<paymentSatoshis>) satoshis to the recipient.',
            icon: 'send',
            lockingScript: 'recipientLockingScript',
            valueSatoshis: '$(<paymentSatoshis>)',
            token: null,
        },
        changeOutput: {
            name: 'Change',
            description: 'Funds returned to the payer.',
            icon: 'receive',
            lockingScript: 'payerLockingScript',
        },
    },

    lockingScripts: {
        tickerLockingScript: {
            name: 'Ticker',
            description: 'The ticker.cash Ticker covenant (P2S): anyone may consume it by re-emitting it with the toll; only the oracle may recycle it.',
            icon: 'contract',
            lockingType: 'p2s',
            lockingBytecode: 'tickerLockingBytecode',
            actions: [],
            selectable: false,
            roles: { payer: { relevant: false } },
        },
        recipientLockingScript: {
            name: 'Recipient',
            description: 'The recipient of the payment.',
            icon: 'address',
            lockingType: 'p2s',
            lockingBytecode: 'lockToRecipient',
            actions: [],
            selectable: false,
        },
        payerLockingScript: {
            name: 'Payer wallet',
            description: 'The payer\'s own funds in this template.',
            icon: 'address',
            lockingType: 'p2pkh',
            lockingBytecode: 'lockP2PKH',
            unlockingBytecode: 'unlockP2PKH',
            actions: [],
            roles: { payer: { state: { variables: [], secrets: [ 'payerKey' ] } } },
            balance: { satoshis: true, fungibleTokens: true, nonfungibleTokens: true },
            selectable: true,
        },
    },

    scripts: {
        consumeTicker: 'OP_0',
        tickerLockingBytecode: '$(<tickerLockingBytecodeConstant>)',
        lockToRecipient: '$(<recipientLockingScript>)',
        lockP2PKH: 'OP_DUP OP_HASH160 <$(<payerKey.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG',
        unlockP2PKH: '<payerKey.schnorr_signature.all_outputs> <payerKey.public_key>',
        ...COMMITMENT_SCRIPTS,
    },

    constants: {
        oracleCategory: { name: 'Oracle category', description: 'The ticker.cash BCH/USD oracle on chipnet.', type: 'bytes', value: ORACLE_CATEGORY },
        tickerLockingBytecodeConstant: { name: 'Ticker locking bytecode', description: 'The v27 Ticker covenant, 55 bytes.', type: 'bytes', value: TICKER_LOCKING_BYTECODE },
        toll: { name: 'Toll', description: 'Satoshis a consumer adds to the Ticker it re-emits.', type: 'integer', value: TOLL_SATS },
    },

    variables: {
        payerKey: { name: 'Payer key', description: 'The key that spends the payer\'s funds and receives change.', type: 'private_key' },
        recipientLockingScript: { name: 'Recipient', description: 'Where the payment goes.', type: 'locking_script' },
        paymentSatoshis: { name: 'Amount', description: 'The payment, in satoshis.', type: 'satoshis' },
        tickerSatoshis: { name: 'Ticker value', description: 'The satoshis currently held by the Ticker being consumed (792 plus any tolls).', type: 'satoshis' },
        ...COMMITMENT_VARIABLE,
    },
};
