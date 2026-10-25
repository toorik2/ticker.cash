// Constants shared by the ticker.cash XO templates (chipnet deployment, v27 covenants).
// The two locking bytecodes are constants of the protocol: every v27 oracle shares them, and
// deployments differ only by category. The category below is ticker.cash's BCH/USD oracle.

/** ticker.cash BCH/USD on chipnet, display-order hex. */
export const ORACLE_CATEGORY = '8f4cf72bf4108a280a2fff0183d92c1162a93f00face71c37f23387bb3d4a46b';
/** The v27 Ticker locking bytecode (P2S, 55 bytes). */
export const TICKER_LOCKING_BYTECODE = '76009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f75810380510193b1755168';
/** The v27 Oracle head locking bytecode (P2SH-32 wrapper, 35 bytes); the same for every deployment. */
export const ORACLE_LOCKING_BYTECODE = 'aa20a9f9c3bcf15f1fe97aa1ccbe13ea77cbf77fb5cdd0f20dde98798b9aaac0e87487';
/** The v27 Oracle redeem script (574 bytes): what the head's P2SH-32 lock hashes to. */
export const ORACLE_REDEEM = '3776009c63c076cd78c78876d178ce8876d278cf8876cc7cc602e80393a27767519dc000ce78ce527e88cf547f75810380510193b175516878009c63c0009d53798277549d57798277549d547982777657a269587981000000655a795379549554937f75537954957f77816e56799f937b757c5279785679a09372777b537a8b7c727b7552795579a2667655798c5296a1697855795296a1699353799f6900cf01117f5779a97888587981765379547f7581a06902605494b1757c5c7f75587f77818b548000ce01207f754f00655c79788b7f75787f77817c8b7c765379a0697672777b5b79780122957f7701227f75607953790140957f7553790140950140947f77014e527901217f777e5f797e011179557954957f755579549554947f777e527901217f75bb6d765879a2665b7a54797e547a7e5e7a7e577a51807ec4539d00cd00c78800d100ce8800d278567a7e88516576cd58798876d155798876d252798876cc0218039d8b7653a2660000656ec6937b757c8b76c3a26600cc7b02180a945200ca82779594a2696d6d6d6d6d6d6d51677c519dc0009d00cf01117f5379a978885479827776529555798277012296a069c4519d00d100ce8800d201117f7c547a88015200ce01207f757e537a7e00cd7e7c7e4f00655679788b7f75787f77817c8b7c765379a0697672777b587952790140957f7552790140950140947f775479587953790122957f7701217f75bb75765479a2660000656ec6937b757c8b76c3a26600cc7b02e803945200ca82779594a2696d6d6d6d755168';
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

// --- CashAssembly loops (BCH_2026_05 has OP_BEGIN/OP_UNTIL). The engine hands a template two kinds of
// values: inside locking and unlocking scripts a hex variable is raw bytes, while in token fields, values and
// descriptions it is UTF-8 text, and token fields are read back as hex text. These helpers bridge the two.

/** nibble (0..15) → one ASCII hex character, lowercase. */
const NIBBLE_CHAR = 'OP_DUP <10> OP_LESSTHAN OP_IF <48> OP_ELSE <87> OP_ENDIF OP_ADD <1> OP_NUM2BIN';
/** ASCII hex character → its value; accepts both cases. */
const CHAR_VALUE = '<0x00> OP_CAT OP_BIN2NUM OP_DUP <58> OP_LESSTHAN OP_IF <48> OP_ELSE OP_DUP <97> OP_LESSTHAN OP_IF <55> OP_ELSE <87> OP_ENDIF OP_ENDIF OP_SUB';

/** bytes → hex text (the form the engine expects from a token commitment or category expression). */
export const HEX_ENCODE = `<""> OP_SWAP OP_BEGIN OP_1 OP_SPLIT OP_ROT OP_ROT <0x00> OP_CAT OP_BIN2NUM OP_DUP <16> OP_DIV ${NIBBLE_CHAR} OP_SWAP <16> OP_MOD ${NIBBLE_CHAR} OP_CAT OP_CAT OP_SWAP OP_SIZE OP_0 OP_NUMEQUAL OP_UNTIL OP_DROP`;
/** hex text → bytes (for a text variable that has no primitive type, such as a notary table). */
export const HEX_DECODE = `<""> OP_SWAP OP_BEGIN OP_2 OP_SPLIT OP_ROT OP_ROT OP_1 OP_SPLIT ${CHAR_VALUE} OP_SWAP ${CHAR_VALUE} <16> OP_MUL OP_ADD <2> OP_NUM2BIN OP_1 OP_SPLIT OP_DROP OP_CAT OP_SWAP OP_SIZE OP_0 OP_NUMEQUAL OP_UNTIL OP_DROP`;
/** reverse a byte string (display-order category → VM order). */
export const REVERSE_BYTES = `<""> OP_SWAP OP_BEGIN OP_1 OP_SPLIT OP_ROT OP_ROT OP_SWAP OP_CAT OP_SWAP OP_SIZE OP_0 OP_NUMEQUAL OP_UNTIL OP_DROP`;
