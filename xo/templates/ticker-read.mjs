// Read a Ticker: decode the 17-byte commitment into timestamp, sequence, price and rows. A
// data-only template for the XO Web Dev Wallet: paste a Ticker's commitment and see the price
// the chain carries. No transaction, no funds.
import { COMMITMENT_DATA, COMMITMENT_SCRIPTS, COMMITMENT_VARIABLE, ORACLE_CATEGORY, SUPPORTED, TICKER_LOCKING_BYTECODE } from './common.mjs';

/** @type {import('@xo-cash/types').XOTemplate} */
export const tickerReadTemplate = {
    $schema: 'https://libauth.org/schemas/wallet-template-v0.schema.json',
    name: 'BCH/USD on chain (ticker.cash)',
    description: 'Decodes a ticker.cash Ticker commitment: a General Protocols price message (timestamp, sequence, price in US cents) followed by the number of notary rows that signed it.',
    icon: 'chart',
    version: '1',
    supported: SUPPORTED,
    resources: [
        { name: 'ticker.cash', description: 'The oracle and its live state.', url: 'https://usd.ticker.cash' },
    ],

    roles: {
        reader: { name: 'Reader', description: 'Anyone reading the oracle.', icon: 'owner' },
    },

    start: [
        { action: 'read', role: 'reader' },
    ],

    actions: {
        read: {
            name: 'Read a Ticker',
            description: 'BCH/USD $(tickerDollars).$(tickerCentsTens)$(tickerCentsOnes), minute $(tickerTimestamp), update $(tickerSequence), signed by $(tickerRows) rows.',
            icon: 'chart',
            roles: {
                reader: {
                    name: 'Read',
                    description: 'Decode the commitment of a Ticker.',
                    icon: 'chart',
                    requirements: { variables: [ 'tickerCommitment' ] },
                },
            },
            requirements: { participants: [ { role: 'reader', slots: { min: 1, max: 1 } } ] },
            data: 'priceCents',
        },
    },

    data: COMMITMENT_DATA,

    inputs: {},
    outputs: {},

    lockingScripts: {
        tickerLockingScript: {
            name: 'Ticker',
            description: 'Where every ticker.cash Ticker sits: the v27 Ticker covenant (P2S). Outputs here with the oracle\'s category are price snapshots.',
            icon: 'contract',
            lockingType: 'p2s',
            lockingBytecode: 'tickerLockingBytecode',
            actions: [],
            selectable: false,
        },
    },

    scripts: {
        tickerLockingBytecode: '0x' + TICKER_LOCKING_BYTECODE,
        ...COMMITMENT_SCRIPTS,
    },

    constants: {
        oracleCategory: { name: 'Oracle category', description: 'The ticker.cash BCH/USD oracle on chipnet.', type: 'bytes', value: ORACLE_CATEGORY },
    },

    variables: COMMITMENT_VARIABLE,
};
