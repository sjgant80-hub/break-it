#!/usr/bin/env node
// attack-kit/replay.mjs — send one packet many times, as fast and as concurrently as you like.
//
//   node attack-kit/replay.mjs --from-captured 0 --times 50 --parallel 50     the replay race
//   node attack-kit/replay.mjs --hex 42524b31...                              a packet you built
// Prints how many were accepted (a fresh, never-sent packet: exactly one; a spent one: zero).
import { post, captured, fromHex } from './lib.mjs';

const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const url = arg('--url', 'http://127.0.0.1:8787');
const packet = arg('--hex') ? fromHex(arg('--hex')) : captured(arg('--captured', 'data/captured.hex'))[Number(arg('--from-captured', '0'))];
if (!packet) { console.error('no packet — pass --hex or run `node run.mjs` to capture traffic'); process.exit(1); }
const times = Number(arg('--times', '20')), parallel = Math.max(1, Number(arg('--parallel', '20')));

const results = [];
for (let i = 0; i < times; i += parallel) {
  const batch = Array.from({ length: Math.min(parallel, times - i) }, () => post(url, packet).catch(() => ({ status: 0, body: null })));
  results.push(...await Promise.all(batch));
}
const accepted = results.filter((r) => r.body && r.body.accepted).length;
const stages = {};
for (const r of results) { const s = r.body ? (r.body.stage || (r.body.accepted ? 'accepted' : '?')) : 'no-response'; stages[s] = (stages[s] || 0) + 1; }
console.log(JSON.stringify({ sent: results.length, accepted, stages }));
