#!/usr/bin/env node
// tools/serve.mjs — a local static server for trying the page (the live site is GitHub Pages; this is for development).
//   node tools/serve.mjs [port]      → http://127.0.0.1:8892
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, normalize, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../', import.meta.url)), port = Number(process.argv[2] || 8892);
const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.svg': 'image/svg+xml', '.csv': 'text/csv', '.txt': 'text/plain', '.xml': 'application/xml' };
createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^[/\\]+/, '');
  if (path.includes('..') || /^(secrets|data|config)[/\\]/.test(path)) { res.writeHead(403).end(); return; }
  try {
    const body = await readFile(join(ROOT, path || 'index.html'));
    res.writeHead(200, { 'content-type': TYPES[extname(path || 'index.html')] || 'application/octet-stream', 'cache-control': 'no-cache' }).end(body);
  } catch { res.writeHead(404).end('not found'); }
}).listen(port, '127.0.0.1', () => console.log('serving ' + ROOT + ' on http://127.0.0.1:' + port));
