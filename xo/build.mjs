// Round-trip the templates through XO's own serializer and parser, and write the JSON the XO Web
// Dev Wallet's import modal accepts into dist/.
import fs from 'node:fs';
import { parseTemplate, serializeTemplate, generateTemplateIdentifier } from '@xo-cash/utils';
import { tickerStampTemplate } from './templates/ticker-stamp.mjs';
import { tickerReadTemplate } from './templates/ticker-read.mjs';
import { tickerGenesisTemplate } from './templates/ticker-genesis.mjs';
import { tickerRotateTemplate } from './templates/ticker-rotate.mjs';

fs.mkdirSync(new URL('./dist/', import.meta.url), { recursive: true });
let failed = 0;
for (const [file, template] of [['ticker-stamp', tickerStampTemplate], ['ticker-read', tickerReadTemplate], ['ticker-genesis', tickerGenesisTemplate], ['ticker-rotate', tickerRotateTemplate]]) {
  try {
    const json = serializeTemplate(template);
    const parsed = parseTemplate(json);
    const id = generateTemplateIdentifier(parsed);
    const pretty = JSON.stringify(JSON.parse(json), null, 2);
    fs.writeFileSync(new URL(`./dist/${file}.json`, import.meta.url), pretty + '\n');
    console.log(`ok   ${file}: ${pretty.length} bytes, identifier ${id.slice(0, 16)}…, sections ${Object.keys(parsed).length}`);
  } catch (e) {
    failed++;
    console.log(`FAIL ${file}: ${String(e.message || e).split('\n')[0].slice(0, 300)}`);
  }
}
process.exit(failed ? 1 : 0);
