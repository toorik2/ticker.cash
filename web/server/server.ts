/**
 * Ticker web server — serves the static dashboard pages.
 *
 * The site is now fully on-chain-consumed: there is no JSON API. The
 * server's only job is to ship `dist/index.html`, `dist/docs.html`, and
 * the `public/` assets. Live oracle data is read directly from BCH
 * Chipnet by clients; current contract addresses are published in
 * docs.html and the GitHub repo.
 */
import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const PORT = Number(process.env.PORT ?? 3001);
const HOST = process.env.HOST ?? '127.0.0.1';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIST_DIR = join(__dirname, '..', 'dist');

const app = express();
app.disable('x-powered-by');

app.use(express.static(DIST_DIR, {
  index: 'index.html',
  // extensions: ['html'] lets /docs serve dist/docs.html without the
  // .html suffix.
  extensions: ['html'],
  maxAge: '1h',
  setHeaders(res, path) {
    if (path.endsWith('.html')) {
      res.setHeader('cache-control', 'no-store');
    }
  },
}));

// SPA-style fallback: any unmatched path returns index.html.
app.get(/.*/, (_req, res) => {
  res.setHeader('cache-control', 'no-store');
  res.sendFile(join(DIST_DIR, 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`ticker-web listening on http://${HOST}:${PORT}`);
});
