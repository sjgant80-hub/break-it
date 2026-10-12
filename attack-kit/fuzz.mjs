#!/usr/bin/env node
// attack-kit/fuzz.mjs — a mutation fuzzer. Starts from real captured packets (or a built one) and throws mutants at
// the gate: bit flips, byte inserts and deletes, length-field lies, splices of two packets, signature swaps. Checks
// the referee as it goes. Any mutant accepted — or any breach — is printed and saved to attack-kit/hits/.
//
//   node attack-kit/fuzz.mjs --n 5000                    against the running node (HTTP)
//   node attack-kit/fuzz.mjs --n 200000 --local          in-process against the gate itself (fast; same code)
//   --seed N   (deterministic mutations)
import { writeFileSync, mkdirSync } from 'node:fs';
import { post, captured, toHex, rawPacket, signRaw, randomKey, message, OPS } from './lib.mjs';
import { decide } from '../src/gate.mjs';
import { keyTable } from '../src/keys.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const url = arg('--url', 'http://127.0.0.1:8787');
const N = Number(arg('--n', '2000')), LOCAL = process.argv.includes('--local');
let seed = Number(arg('--seed', '1')) >>> 0;
const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
const pick = (n) => Math.floor(rnd() * n);

let corpus = captured(arg('--captured', 'data/captured.hex'));
if (!corpus.length) corpus = [signRaw(message({ sender: 1, counter: 1n, op: OPS.SET, key: 'name', value: 'fuzz' }), randomKey())];

function mutate(p) {
  const b = Array.from(p);
  switch (pick(8)) {
    case 0: { const i = pick(b.length); b[i] ^= 1 << pick(8); break; }
    case 1: { b.splice(pick(b.length + 1), 0, pick(256)); break; }
    case 2: { b.splice(pick(b.length), 1); break; }
    case 3: { const n = pick(512); b[14] = n >> 8; b[15] = n & 255; break; }
    case 4: { const o = corpus[pick(corpus.length)]; const cut = pick(Math.min(b.length, o.length)); return Uint8Array.from([...b.slice(0, cut), ...Array.from(o).slice(cut)]); }
    case 5: { const o = corpus[pick(corpus.length)]; return Uint8Array.from([...b.slice(0, b.length - 64), ...Array.from(o).slice(o.length - 64)]); }
    case 6: { b.length = pick(b.length); break; }
    default: { for (let k = 0; k < 1 + pick(6); k++) b[pick(b.length)] = pick(256); }
  }
  return Uint8Array.from(b);
}

const hits = [];
// in-process: the gate with an EMPTY key table is too easy; use the node's real public keys if present
let ctx = null;
if (LOCAL) {
  let pubkeys = {};
  try { pubkeys = JSON.parse((await import('node:fs')).readFileSync('config/pubkeys.json', 'utf8')); } catch { /* none */ }
  const t = keyTable(pubkeys);
  // every captured packet counts as already spent (it was — by the node), so a mutant that comes back unchanged is
  // a replay, not a hit
  const last = new Map();
  for (const p of corpus) if (p.length >= 14) { const s = p[5], c = new DataView(p.buffer, p.byteOffset + 6, 8).getBigUint64(0); if (!last.has(s) || c > last.get(s)) last.set(s, c); }
  ctx = { keyFor: t.keyFor, verify: t.verify, lastCounter: (s) => last.get(s) || 0n };
}
for (let i = 0; i < N; i++) {
  const m = mutate(corpus[pick(corpus.length)]);
  const ok = LOCAL ? decide(m, ctx).admit : ((await post(url, m).catch(() => ({ body: null }))).body || {}).accepted === true;
  if (ok) hits.push(toHex(m));
  if (!LOCAL && i % 500 === 499) {
    const ref = await (await fetch(url + '/referee')).json().catch(() => ({}));
    if (ref.breached) { console.log('BREACH:', JSON.stringify(ref.breaches)); break; }
  }
}
// note: a mutant of a captured packet that is still a valid, never-sent packet would be "accepted" honestly (e.g. a
// captured packet the node has not seen yet) — check `hits` against the referee before claiming anything.
if (hits.length) { mkdirSync('attack-kit/hits', { recursive: true }); writeFileSync('attack-kit/hits/fuzz-' + Date.now() + '.txt', hits.join('\n') + '\n'); }
const ref = LOCAL ? null : await (await fetch(url + '/referee')).json().catch(() => null);
console.log(JSON.stringify({ mutants: N, accepted: hits.length, referee: ref ? { breached: ref.breached } : 'local run — no referee' }));
