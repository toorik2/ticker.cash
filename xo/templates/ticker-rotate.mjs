// Change the notary table of a v27 oracle by majority approval: 7 of 13 rows each sign one approval, the
// transaction carries them, the covenant checks them. One role per table row (row0 … row12, each 0 or 1
// participant) plus an operator who proposes the new table and assembles the spend. A row that does not take
// part is simply absent; the operator records the absence as an empty approval and the scripts skip it. The
// covenant, not the template, enforces the majority: fewer than 7 approvals and the transaction is invalid.
//
// What the rows sign: 0x52 ‖ category (VM order) ‖ hash160(old table) ‖ next lock ‖ hash160(new table).
// The template computes that message and shows it to each row (approvalMessageHex), so a notary operator
// can hand it to `ticker-notary sign-rotate` and paste the 64-byte signature back as the row's approval.
import { HEX_DECODE, HEX_ENCODE, ORACLE_LOCKING_BYTECODE, ORACLE_REDEEM, REVERSE_BYTES, SUPPORTED } from './common.mjs';

const ROWS = 13;
const rowIds = Array.from({ length: ROWS }, (_, n) => `row${n}`);
const approvalIds = Array.from({ length: ROWS }, (_, n) => `approval${n}`);

// Fold the 13 optional approvals into (sigs, rows): stack [sigs rows]; an empty approval is skipped.
const fold = approvalIds.map((id, n) => `<${id}> OP_SIZE OP_0 OP_NUMEQUAL OP_IF OP_DROP OP_ELSE OP_ROT OP_SWAP OP_CAT OP_SWAP <${n}> OP_1 OP_NUM2BIN OP_CAT OP_ENDIF`).join(' ');

/** @type {import('@xo-cash/types').XOTemplate} */
export const tickerRotateTemplate = {
    $schema: 'https://libauth.org/schemas/wallet-template-v0.schema.json',
    name: 'Change the notary table (ticker.cash v27)',
    description: 'Rotates a v27 oracle to a new notary table. A strict majority of the current rows each sign one approval; the transaction carries them and the covenant verifies them. Rows that do not take part are absent.',
    icon: 'governance',
    version: '1',
    supported: SUPPORTED,
    resources: [
        { name: 'ticker.cash governance', description: 'Rotation, migration and retirement by majority approval.', url: 'https://usd.ticker.cash/docs#governance' },
    ],

    roles: {
        operator: { name: 'Operator', description: 'Proposes the new table, collects approvals and posts the rotation. Holds no power: without a majority nothing moves.', icon: 'owner' },
        ...Object.fromEntries(rowIds.map((id, n) => [id, { name: `Row ${n}`, description: `The notary in table row ${n}. Approves by signing the approval message with the row's key.`, icon: 'signer' }])),
    },

    start: [
        { action: 'rotate', role: 'operator' },
    ],

    actions: {
        rotate: {
            name: 'Change the notary table',
            description: 'Rotate the oracle to a new table. Rows: sign this message with `ticker-notary sign-rotate` and paste the approval: $(approvalMessageHex)',
            icon: 'governance',
            roles: {
                operator: {
                    name: 'Propose and post',
                    description: 'Name the head, the current table and the new table; post the rotation once a majority has approved.',
                    icon: 'owner',
                    requirements: {
                        // The operator also lists every approval so it can record absent rows as empty approvals.
                        variables: [ 'category', 'headCommitment', 'headValue', 'rotationFee', 'oldTable', 'newTable', ...approvalIds ],
                    },
                },
                ...Object.fromEntries(rowIds.map((id, n) => [id, {
                    name: `Approve as row ${n}`,
                    description: `Paste the 64-byte approval signed by row ${n}'s key.`,
                    icon: 'signer',
                    requirements: { variables: [ approvalIds[n] ] },
                }])),
            },
            requirements: {
                participants: [
                    { role: 'operator', slots: { min: 1, max: 1 } },
                    ...rowIds.map(id => ({ role: id, slots: { min: 0, max: 1 } })),
                ],
            },
            transaction: 'rotateTransaction',
        },
    },

    transactions: {
        rotateTransaction: {
            name: 'Notary table changed',
            description: 'The oracle moved to a new notary table by majority approval. Category, counter, price and rows carry over.',
            icon: 'governance',
            inputs: [ { input: 'headInput', inputIndex: 0 } ],
            outputs: [ { output: 'headOutput', outputIndex: 0 } ],
            version: 2,
            locktime: 0,
        },
    },

    inputs: {
        headInput: {
            name: 'Oracle head',
            description: 'The current head: minting NFT, commitment = state ‖ hash160(current table), holding the reserve.',
            icon: 'contract',
            valueSatoshis: '$(<headValue>)',
            token: {
                category: '$(<category>)',
                amount: null,
                nft: { capability: 'minting', commitment: '$(<headCommitment>)' },
            },
            unlockingScript: 'rotateUnlock',
        },
    },

    outputs: {
        headOutput: {
            name: 'Oracle head (new table)',
            description: 'The same head with the new table hash in its commitment; the reserve minus the fee.',
            icon: 'contract',
            lockingScript: 'oracleLockingScript',
            valueSatoshis: '$(<headValue> <rotationFee> OP_SUB)',
            token: {
                category: '$(<category>)',
                amount: null,
                nft: { capability: 'minting', commitment: '$(nextCommitmentHex)' },
            },
        },
    },

    lockingScripts: {
        oracleLockingScript: {
            name: 'Oracle head',
            description: 'The v27 Oracle covenant (P2SH-32), shared by every v27 oracle. The operator\'s wallet tracks it to find heads; nothing here is spendable without approvals.',
            icon: 'contract',
            lockingType: 'p2s',
            lockingBytecode: 'oracleLockingBytecode',
            unlockingBytecode: 'rotateUnlock',
            actions: [ { action: 'rotate', role: 'operator' } ],
            selectable: false,
        },
    },

    scripts: {
        oracleLockingBytecode: '0x' + ORACLE_LOCKING_BYTECODE,

        // --- unlocking script (libauth path: hex variables are raw bytes here)
        // rotate(table, rows, sigs): push(sigs) push(rows) push(table) OP_1 push(redeem)
        approvalSigs: `<""> <""> ${fold} OP_DROP`,
        approvalRows: `<""> <""> ${fold} OP_NIP`,
        rotateUnlock: `<$(approvalSigs)> <$(approvalRows)> <oldTable> OP_1 <0x${ORACLE_REDEEM}>`,

        // --- token fields and descriptions (utils path: text in, hex text out)
        newTableBytes: `<newTable> ${HEX_DECODE}`,
        tail: 'newTableBytes OP_HASH160',
        state: '<headCommitment.toBytes> <17> OP_SPLIT OP_DROP',
        oldTableHash: '<headCommitment.toBytes> <17> OP_SPLIT OP_NIP',
        nextCommitment: 'state tail OP_CAT',
        nextCommitmentHex: `nextCommitment ${HEX_ENCODE}`,
        approvalMessage: `<0x52> <category.toBytes> ${REVERSE_BYTES} OP_CAT oldTableHash OP_CAT <0x${ORACLE_LOCKING_BYTECODE}> OP_CAT tail OP_CAT`,
        approvalMessageHex: `approvalMessage ${HEX_ENCODE}`,
    },

    variables: {
        category: { name: 'Category', description: 'The oracle\'s category (display order).', type: 'token_category' },
        headCommitment: { name: 'Head commitment', description: 'The current head\'s 37-byte commitment: state (17) ‖ hash160(current table) (20).', type: 'nft_commitment' },
        headValue: { name: 'Head value', description: 'Satoshis held by the head (the reserve).', type: 'satoshis' },
        rotationFee: { name: 'Fee', description: 'Satoshis the reserve pays for this transaction: its size plus one. The covenant caps it at 1,000 + 2 × the unlocking data length.', type: 'satoshis' },
        oldTable: { name: 'Current table', description: 'The current table, n × (compressed pubkey 33 ‖ exchange id 1), hex. Must hash to the head\'s table hash.', type: 'bytes' },
        newTable: { name: 'New table', description: 'The proposed table, same layout, hex. Its hash160 becomes the head\'s new table hash.', type: 'bytes' },
        ...Object.fromEntries(approvalIds.map((id, n) => [id, { name: `Approval of row ${n}`, description: `64-byte Schnorr signature by row ${n}'s key over the approval message, hex; empty when row ${n} does not take part.`, type: 'bytes' }])),
    },
};
