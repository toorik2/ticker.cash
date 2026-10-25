// Constants shared by the ticker.cash XO templates (chipnet deployment, v27 covenants).
// The two locking bytecodes are constants of the protocol: every v27 oracle shares them, and
// deployments differ only by category. The category below is ticker.cash's BCH/USD oracle.

/** ticker.cash BCH/USD on chipnet, display-order hex. */
export const ORACLE_CATEGORY = '8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b';
/** The v27 Ticker locking bytecode (P2S, 55 bytes). */
export const TICKER_LOCKING_BYTECODE = '76009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f75810380510193b1755168';
/** The v27 Oracle head locking bytecode (P2SH-32 wrapper, 35 bytes); the same for every deployment. */
export const ORACLE_LOCKING_BYTECODE = 'aa20a9f9c3bcf15f1fe97aa1ccbe13ea77cbf77fb5cdd0f20dde98798b9aaac0e87487';
/** What a consumer adds to a Ticker it re-emits. */
export const TOLL_SATS = 1000;

/** @type {import('@xo-cash/types').BchVmVersion[]} */
export const SUPPORTED = [ 'BCH_2026_05' ];

/** CashASM that decodes fields of a 17-byte Ticker commitment held in `tickerCommitment` (type nft_commitment;
 *  `.toBytes` yields the raw bytes, since the engine passes variable values around as text). */
export const COMMITMENT_SCRIPTS = {
    // timestamp: bytes 0..4
    tickerTimestamp: '<tickerCommitment.toBytes> OP_4 OP_SPLIT OP_DROP OP_BIN2NUM',
    // dataSequence: bytes 8..12
    tickerSequence: '<tickerCommitment.toBytes> OP_8 OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP OP_BIN2NUM',
    // price in US cents: bytes 12..16
    tickerPriceCents: '<tickerCommitment.toBytes> OP_12 OP_SPLIT OP_NIP OP_4 OP_SPLIT OP_DROP OP_BIN2NUM',
    // rows that signed: byte 16
    tickerRows: '<tickerCommitment.toBytes> OP_16 OP_SPLIT OP_NIP OP_BIN2NUM',
    // dollars and cents for descriptions
    tickerDollars: 'tickerPriceCents <100> OP_DIV',
    tickerCentsTens: 'tickerPriceCents <100> OP_MOD <10> OP_DIV',
    tickerCentsOnes: 'tickerPriceCents <10> OP_MOD',
};

/** @type {Record<string, import('@xo-cash/types').XOTemplateData>} */
export const COMMITMENT_DATA = {
    timestamp: { value: '$(tickerTimestamp)', type: 'integer' },
    sequence: { value: '$(tickerSequence)', type: 'integer' },
    priceCents: { value: '$(tickerPriceCents)', type: 'integer' },
    rowsSigned: { value: '$(tickerRows)', type: 'integer' },
};

/** @type {Record<string, import('@xo-cash/types').XOTemplateVariable>} */
export const COMMITMENT_VARIABLE = {
    tickerCommitment: {
        name: 'Ticker commitment',
        description: 'The 17-byte NFT commitment of the Ticker: timestamp ‖ messageSequence ‖ dataSequence ‖ price in US cents ‖ rows that signed. The first 16 bytes are a General Protocols price message.',
        type: 'nft_commitment',
    },
};
