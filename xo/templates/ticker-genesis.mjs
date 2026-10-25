// Instantiate an oracle: mint a head of the v27 Oracle covenant over a notary table of your
// choice, funded with your own reserve. The covenant bytecode is a protocol constant; the only
// per-instance inputs are the table and the reserve. Statements name no deployment, so a head
// listing public notaries' keys can consume their statements from its first minute.
//
// CashTokens genesis rule: the category is the txid of the outpoint spent at input 0, and that
// outpoint must be output 0 of its transaction. The engine has no primitive for this yet, so the
// flow is two actions: `fund` receives a coin at this template's own key (the app checks it is
// output 0), then `create` spends exactly that coin at input 0 while the app supplies its txid as
// `category`. A mismatch is simply an invalid transaction; nothing can be lost to it.
import { ORACLE_LOCKING_BYTECODE, SUPPORTED } from './common.mjs';

/** @type {import('@xo-cash/types').XOTemplate} */
export const tickerGenesisTemplate = {
    $schema: 'https://libauth.org/schemas/wallet-template-v0.schema.json',
    name: 'Instantiate an oracle (ticker.cash v27)',
    description: 'Mints a new price-oracle head under the ticker.cash v27 covenant, over a notary table you choose, funded with your reserve. Any notary\'s public statements are usable by it from the first minute.',
    icon: 'contract',
    version: '1',
    supported: SUPPORTED,
    resources: [
        { name: 'ticker.cash', description: 'The covenant, the notary table format and the registry of exchange ids.', url: 'https://usd.ticker.cash/docs' },
    ],

    defaults: {
        change: { output: 'changeOutput', role: 'founder', generate: [ 'founderKey' ] },
        address: { lockingScript: 'founderLockingScript', role: 'founder', generate: [ 'founderKey' ] },
        receive: { output: 'fundingOutput', role: 'founder', generate: [ 'founderKey' ] },
    },

    roles: {
        founder: { name: 'Founder', description: 'Whoever funds the reserve and chooses the table.', icon: 'owner' },
    },

    start: [
        { action: 'fund', role: 'founder', generate: [ 'founderKey' ] },
        { action: 'create', role: 'founder', generate: [ 'founderKey' ] },
    ],

    actions: {
        fund: {
            name: 'Receive the reserve',
            description: 'Receive the coin that will fund the oracle. It must be output 0 of its transaction; its txid becomes the oracle\'s category.',
            icon: 'receive',
            roles: {
                founder: {
                    name: 'Receive',
                    description: 'Receive the funding coin.',
                    icon: 'receive',
                    requirements: { secrets: [ 'founderKey' ], variables: [ 'fundingSatoshis' ] },
                },
            },
            requirements: { participants: [ { role: 'founder', slots: { min: 1, max: 1 } } ] },
            transaction: 'fundTransaction',
        },
        create: {
            name: 'Create the oracle',
            description: 'Mint the head with a reserve of $(<reserveSatoshis>) satoshis over the chosen notary table. The category is the funding coin\'s txid.',
            icon: 'contract',
            roles: {
                founder: {
                    name: 'Create',
                    description: 'Spend the funding coin at input 0 into the oracle head.',
                    icon: 'contract',
                    requirements: {
                        secrets: [ 'founderKey' ],
                        variables: [ 'category', 'tableBytes', 'headCommitment', 'reserveSatoshis', 'startTimestamp', 'fundingSatoshis' ],
                    },
                },
            },
            requirements: { participants: [ { role: 'founder', slots: { min: 1, max: 1 } } ] },
            transaction: 'createTransaction',
        },
    },

    transactions: {
        fundTransaction: {
            name: 'Reserve received',
            description: 'Received $(<fundingSatoshis>) satoshis as the future reserve.',
            icon: 'receive',
            inputs: [],
            outputs: [ { output: 'fundingOutput', outputIndex: 0 } ],
            version: 2,
            locktime: 0,
        },
        createTransaction: {
            name: 'Oracle created',
            description: 'Minted an oracle head with a reserve of $(<reserveSatoshis>) satoshis.',
            icon: 'contract',
            inputs: [ { input: 'fundingInput', inputIndex: 0 } ],
            outputs: [ { output: 'headOutput', outputIndex: 0 } ],
            version: 2,
            locktime: 0,
        },
    },

    inputs: {
        fundingInput: {
            name: 'Funding coin',
            description: 'The coin received by `fund`, spent at input 0 so its txid becomes the category.',
            icon: 'receive',
            valueSatoshis: '$(<fundingSatoshis>)',
            token: null,
            unlockingScript: 'unlockP2PKH',
        },
    },

    outputs: {
        fundingOutput: {
            name: 'Funding coin',
            description: 'The coin that will become the reserve; it must be output 0.',
            icon: 'receive',
            lockingScript: 'founderLockingScript',
            valueSatoshis: '$(<fundingSatoshis>)',
            token: null,
        },
        headOutput: {
            name: 'Oracle head',
            description: 'The minting NFT of the new oracle: commitment = timestamp ‖ 0 ‖ 0 ‖ 0 ‖ 0 ‖ hash160(table), holding the reserve.',
            icon: 'contract',
            lockingScript: 'oracleLockingScript',
            valueSatoshis: '$(<reserveSatoshis>)',
            token: {
                category: '$(<category>)',
                amount: null,
                // Token expressions are decoded as hex text by the engine, and there is no primitive for arbitrary
                // bytes (the table), so the app supplies the commitment; its derivation is in the variable's description.
                nft: { capability: 'minting', commitment: '$(<headCommitment>)' },
            },
            roles: { founder: { relevant: false } },
        },
        changeOutput: {
            name: 'Change',
            description: 'Funds returned to the founder.',
            icon: 'receive',
            lockingScript: 'founderLockingScript',
        },
    },

    lockingScripts: {
        oracleLockingScript: {
            name: 'Oracle head',
            description: 'The ticker.cash v27 Oracle covenant (P2SH-32). Every v27 oracle shares it; the category tells them apart.',
            icon: 'contract',
            lockingType: 'p2s',
            lockingBytecode: 'oracleLockingBytecode',
            actions: [],
            selectable: false,
            roles: { founder: { relevant: false } },
        },
        founderLockingScript: {
            name: 'Founder wallet',
            description: 'The founder\'s own funds in this template.',
            icon: 'address',
            lockingType: 'p2pkh',
            lockingBytecode: 'lockP2PKH',
            unlockingBytecode: 'unlockP2PKH',
            actions: [],
            roles: { founder: { state: { variables: [], secrets: [ 'founderKey' ] } } },
            balance: { satoshis: true, fungibleTokens: true, nonfungibleTokens: true },
            selectable: true,
        },
    },

    scripts: {
        oracleLockingBytecode: '0x' + ORACLE_LOCKING_BYTECODE,
        lockP2PKH: 'OP_DUP OP_HASH160 <$(<founderKey.public_key> OP_HASH160)> OP_EQUALVERIFY OP_CHECKSIG',
        unlockP2PKH: '<founderKey.schnorr_signature.all_outputs> <founderKey.public_key>',
    },


    variables: {
        founderKey: { name: 'Founder key', description: 'The key that holds the funding coin and receives change.', type: 'private_key' },
        fundingSatoshis: { name: 'Funding coin value', description: 'Satoshis in the funding coin.', type: 'satoshis' },
        category: { name: 'Category', description: 'The new oracle\'s category: the txid of the funding coin, which must be output 0 of its transaction.', type: 'token_category' },
        tableBytes: { name: 'Notary table', description: 'n × (compressed pubkey 33 ‖ exchange id 1). Row order is permanent for this instance until its rows rotate it.', type: 'bytes' },
        reserveSatoshis: { name: 'Reserve', description: 'Satoshis locked in the head to pay the oracle\'s fees.', type: 'satoshis' },
        startTimestamp: { name: 'Start timestamp', description: 'A minute start before the first update (Unix seconds, multiple of 60).', type: 'integer' },
        headCommitment: { name: 'Head commitment', description: 'The 37-byte genesis commitment: startTimestamp (4, LE) ‖ 13 zero bytes ‖ hash160(table).', type: 'nft_commitment' },
    },
};
