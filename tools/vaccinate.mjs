#!/usr/bin/env node
// tools/vaccinate.mjs — every attack becomes a permanent vaccine. An attack that was refused once must be refused
// forever; this is the regression wall that proves it, re-runnably.
//
//   node tools/vaccinate.mjs            (re)build receipts/vaccines.json from a deterministic attack set,
//                                        folding in any real attacks found in data/node-*/journal.jsonl
//   node tools/vaccinate.mjs --check     replay every vaccine through a fresh gate and demand the SAME refusal
//                                        (exit 1 if any vaccine now admits, or the set does not reproduce)
//
// Each vaccine is { hex, sender, last, stage, note }: the attack bytes, the counter state it was refused under,
// and the gate stage that refused it. --check rebuilds the pinned key table from the recorded senders and asserts
// decide() still refuses at that stage. Deterministic (fixed seed keys), so the committed file reproduces exactly.
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../src/gate.mjs';
import { keyTable, keyFromSeed, rawPublic, signWith } from '../src/keys.mjs';
import { encodeUnsigned, signedBytes, SIG, OPS } from '../src/wire.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'receipts', 'vaccines.json');
const hex = (u8) => Buffer.from(u8).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const S1 = keyFromSeed(new Uint8Array(32).fill(1));
const ATTACKER = keyFromSeed(new Uint8Array(32).fill(0xee));
const PUBKEYS = { 1: hex(rawPublic(S1)) };

// append a signature by raw concat — NO rawCheck validation, because vaccines are deliberately malformed packets
function sign(unsigned, key, domain) {
  const n = (unsigned[14] << 8) | unsigned[15];
  const probe = new Uint8Array([...unsigned, ...new Uint8Array(SIG)]);
  const material = domain === undefined ? signedBytes(probe, n) : new Uint8Array([...Array.from(domain, (c) => c.charCodeAt(0)), ...unsigned]);
  const sig = signWith(key)(material);
  return new Uint8Array([...unsigned, ...sig]);
}
const raw = (sender, counter, payload, declaredLen) => {
  const body = Uint8Array.from(payload);
  const out = new Uint8Array(16 + body.length);
  out[0] = 0x42; out[1] = 0x52; out[2] = 0x4b; out[3] = 0x31; out[4] = 1; out[5] = sender & 0xff;
  new DataView(out.buffer).setBigUint64(6, BigInt.asUintN(64, counter));
  const n = declaredLen === undefined ? body.length : declaredLen;
  out[14] = (n >> 8) & 0xff; out[15] = n & 0xff; out.set(body, 16);
  return out;
};

// a deterministic battery of attacks that must stay refused, each with the counter state it is judged under
function seedVaccines() {
  const legit = (c, op) => sign(encodeUnsigned({ sender: 1, counter: c, ...op }), S1);
  const v = [];
  const add = (bytes, last, note) => v.push({ hex: hex(bytes), sender: bytes.length > 5 ? bytes[5] : 0, last: String(last), note });
  add(sign(encodeUnsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'name', value: 'x' }), ATTACKER), 0n, 'forgery: unpinned key');
  add(sign(encodeUnsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'name', value: 'x' }), S1, ''), 0n, 'forgery: no domain separation');
  add(sign(encodeUnsigned({ sender: 9, counter: 1n, op: OPS.SET, key: 'x', value: 'y' }), ATTACKER), 0n, 'unknown sender');
  add(legit(1n, { op: OPS.SET, key: 'name', value: 'x' }).slice(0, -1), 0n, 'truncated signature');
  add(new Uint8Array([...legit(1n, { op: OPS.SET, key: 'k', value: 'v' }), 0x41, 0x41]), 0n, 'extension');
  add((() => { const b = legit(1n, { op: OPS.SET, key: 'name', value: 'x' }).slice(); b.fill(0, b.length - SIG); return b; })(), 0n, 'all-zero signature');
  add(raw(1, 1n, [0x01, 0x09, ...Array.from('aaaaaaaaa', (c) => c.charCodeAt(0)), 0x01, 0x78]), 0n, 'schema: key __proto__-length junk');
  add(raw(1, 1n, [0x01, 0x04, 0x4e, 0x61, 0x6d, 0x65, 0x01, 0x78]), 0n, 'schema: upper-case key byte');
  add(raw(1, 1n, [0x04, 0x01, 0x61]), 0n, 'schema: unknown op');
  add(sign(raw(1, 1n, [0x01, 0x01, 0x61, 0x01, 0x61], 4), S1), 0n, 'schema: lying length');
  add(new Uint8Array([1, 2, 3]), 0n, 'size: far too short');
  add(sign(encodeUnsigned({ sender: 1, counter: 5n, op: OPS.ADD, key: 'bal', delta: 1 }), S1), 5n, 'replay: counter not after last');
  add(sign(encodeUnsigned({ sender: 1, counter: 7n, op: OPS.ADD, key: 'bal', delta: 1 }), S1), 5n, 'out of order: skips a counter');
  return v;
}

// fold in any real refusals recorded in live journals (their bytes + the sender's last counter at the time)
function fromJournals() {
  const dataDir = join(ROOT, 'data');
  const out = [];
  if (!existsSync(dataDir)) return out;
  for (const d of readdirSync(dataDir)) {
    const jp = join(dataDir, d, 'journal.jsonl');
    if (!existsSync(jp)) continue;
    for (const line of readFileSync(jp, 'utf8').split('\n').filter(Boolean)) {
      try {
        const r = JSON.parse(line);
        if (!r.bytes || r.detail !== 'full' || !/^(?:[0-9a-f]{2})+$/.test(r.bytes)) continue;
        const b = fromHex(r.bytes);
        if (b.length < 6) continue;
        out.push({ hex: r.bytes, sender: b[5], last: String(r.context && r.context.last ? r.context.last : '0'), note: 'journal: ' + (r.reason || r.stage).slice(0, 60) });
      } catch { /* skip */ }
    }
  }
  return out;
}

function build() {
  const seen = new Set(), all = [];
  for (const vac of [...seedVaccines(), ...fromJournals()]) { if (!seen.has(vac.hex)) { seen.add(vac.hex); all.push(vac); } }
  // judge each now, record the stage it is refused at (and refuse to vaccinate anything that ADMITS)
  const t = keyTable(PUBKEYS);
  const vaccines = [];
  for (const vac of all) {
    const bytes = fromHex(vac.hex);
    const ctx = { keyFor: t.keyFor, verify: t.verify, lastCounter: (s) => (s === vac.sender ? BigInt(vac.last) : 0n) };
    const r = decide(bytes, ctx);
    if (r.admit) { console.error('WILL NOT vaccinate a packet the gate ADMITS: ' + vac.note); process.exit(1); }
    vaccines.push({ hex: vac.hex, sender: vac.sender, last: vac.last, stage: r.stage, note: vac.note });
  }
  vaccines.sort((a, b) => (a.hex < b.hex ? -1 : a.hex > b.hex ? 1 : 0));   // stable order → reproducible file
  return { kind: 'break-it-vaccines', v: 1, count: vaccines.length, vaccines };
}

function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}

const text = canonical(build()) + '\n';
if (process.argv.includes('--check')) {
  if (!existsSync(OUT)) { console.error('no receipts/vaccines.json — run `node tools/vaccinate.mjs` first'); process.exit(1); }
  const committed = readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n');
  if (committed !== text) { console.error('the vaccine set does not reproduce (a known attack changed behaviour, or new ones were not committed)'); process.exit(1); }
  const n = JSON.parse(text).count;
  console.log('REPRODUCED — ' + n + ' vaccines, every known attack still refused');
} else {
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, text);
  console.log('wrote ' + JSON.parse(text).count + ' vaccines → receipts/vaccines.json');
}
