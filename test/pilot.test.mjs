import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { judge, explained, REFUSAL_STAGES, GATE_STAGES, BIND_LOOKUP, RECORDS, ACCOUNTS, BOOK_KEYS, MIN_RATE, INJECTIONS, BATTERY } from '../pilot/judge.mjs';

const read = (p) => JSON.parse(readFileSync(new URL('../' + p, import.meta.url), 'utf8'));
const CLAIMS = { claims: [...read('pilot/claims.json').claims, ...read('pilot/claims-2.json').claims] };
const KINDS = ['replay', 'flip', 'unpinned', 'nodomain', 'truncated', 'out-of-range'];
const FIRST = ['counter', 'signature', 'signature', 'signature', 'size', 'schema'];

// facts under which every sealed claim holds, at its edge where it has one
const GOOD = Object.freeze({
  admitted: RECORDS, ledgerEntries: RECORDS, genuineRefused: 0, retries: 0,
  books: { equal: true, mismatches: 0, keys: BOOK_KEYS, accounts: ACCOUNTS },
  seconds: 1800, perSecond: MIN_RATE,
  egress: { tcp: 0, tls: 0, udp: 0, dns: 0, fetch: 0, outbound: 0, afterListening: 0, seen: [] },
  canarySeen: true, listening: ['127.0.0.1:5000'],
  injections: KINDS.map((kind, i) => ({ kind, first: { status: 403, stage: FIRST[i] }, second: { status: 403, stage: 'recognised' } })),
  referee: { breached: false, foldMatches: true, checked: RECORDS },
  redteam: { exit: 0, cases: BATTERY, held: true },
  explained: { answers: 12, unexplained: 0, journal: 12, journalUnexplained: 0 },
  chain: { ok: true, head: 'a'.repeat(64) }, derivedHead: 'a'.repeat(64),
});
const one = (id, facts) => judge({ claims: [CLAIMS.claims.find((c) => c.id === id)] }, facts).verdicts[0];
const holds = (id, over) => one(id, { ...GOOD, ...over }).held;

test('the sealed claims are the ten the judge has rules for, in order', () => {
  assert.deepEqual(CLAIMS.claims.map((c) => c.id), ['coo-1', 'coo-2', 'coo-3', 'ciso-1', 'ciso-2', 'sec-1', 'sec-2', 'sec-3', 'reg-1', 'ciso-3']);
  const r = judge(CLAIMS, GOOD);
  assert.equal(r.held, 10); assert.equal(r.failed, 0);
  for (const v of r.verdicts) { assert.equal(v.held, true, v.id + ': ' + v.measured); assert.ok(v.claim.length > 20); assert.ok(['COO', 'CISO', 'Security', 'Regulator'].includes(v.role)); }
});

test('coo-1: every record admitted and in the ledger, none refused', () => {
  assert.equal(holds('coo-1', { admitted: RECORDS - 1 }), false);
  assert.equal(holds('coo-1', { ledgerEntries: RECORDS - 1 }), false);
  assert.equal(holds('coo-1', { ledgerEntries: RECORDS + 1 }), false);
  assert.equal(holds('coo-1', { genuineRefused: 1 }), false);
  assert.equal(holds('coo-1', { retries: 40 }), true);
  assert.equal(one('coo-1', GOOD).measured, '180000 admitted, 180000 in the ledger, 0 genuine refused (0 rate-limit retries)');
});

test('coo-2: the books equal the feed on every key and every account', () => {
  assert.equal(holds('coo-2', { books: { ...GOOD.books, equal: false, mismatches: 1 } }), false);
  assert.equal(holds('coo-2', { books: { ...GOOD.books, keys: BOOK_KEYS - 1 } }), false);
  assert.equal(holds('coo-2', { books: { ...GOOD.books, accounts: ACCOUNTS - 1 } }), false);
  assert.equal(holds('coo-2', { books: null }), false);
  assert.equal(one('coo-2', GOOD).measured, 'equal across 210000 keys, 30000 accounts');
  assert.equal(one('coo-2', { ...GOOD, books: { ...GOOD.books, equal: false, mismatches: 3 } }).measured, 'NOT equal (3 keys differ) across 210000 keys, 30000 accounts');
});

test('coo-3: at least 100 records a second, exactly at the edge', () => {
  assert.equal(holds('coo-3', { perSecond: MIN_RATE }), true);
  assert.equal(holds('coo-3', { perSecond: MIN_RATE - 0.1 }), false);
  assert.equal(holds('coo-3', { perSecond: 'fast' }), false);
  assert.equal(holds('coo-3', { perSecond: NaN }), false);
  assert.equal(one('coo-3', GOOD).measured, '100 records a second (1800 s for 180000)');
});

test('ciso-1: zero outbound, and only once the canary proved the meter sees', () => {
  assert.equal(holds('ciso-1', { canarySeen: false }), false);
  assert.equal(holds('ciso-1', { egress: { ...GOOD.egress, outbound: 1, dns: 1 } }), false);
  assert.equal(holds('ciso-1', { egress: null }), false);
  assert.equal(one('ciso-1', GOOD).measured, 'outbound 0 (tcp 0, tls 0, udp 0, dns 0, fetch 0); the canary was seen');
  assert.match(one('ciso-1', { ...GOOD, canarySeen: false }).measured, /NOT seen/);
});

test('ciso-3: before listening only the bind lookup, after listening nothing, and the canary seen', () => {
  const bind = { ...GOOD.egress, dns: 1, outbound: 1, seen: [BIND_LOOKUP] };
  assert.equal(BIND_LOOKUP, 'dns lookup 127.0.0.1 (before listening)');
  assert.equal(holds('ciso-3', { egress: bind }), true);
  assert.equal(holds('ciso-3', { egress: GOOD.egress }), true);
  assert.equal(holds('ciso-3', { egress: bind, canarySeen: false }), false);
  assert.equal(holds('ciso-3', { egress: { ...bind, afterListening: 1, outbound: 2, seen: [BIND_LOOKUP, 'tcp 10.0.0.1:443 (after listening)'] } }), false);
  assert.equal(holds('ciso-3', { egress: { ...bind, seen: ['dns lookup example.com (before listening)'] } }), false);
  assert.equal(holds('ciso-3', { egress: { ...bind, outbound: 40 } }), false);
  assert.equal(holds('ciso-3', { egress: { ...bind, seen: 'x' } }), false);
  assert.equal(one('ciso-3', { ...GOOD, egress: bind }).measured, '0 attempts after listening; before: ' + BIND_LOOKUP + '; the canary was seen');
  assert.equal(one('ciso-3', GOOD).measured, '0 attempts after listening; before: none; the canary was seen');
});

test('ciso-2: listening on loopback only', () => {
  assert.equal(holds('ciso-2', { listening: ['0.0.0.0:5000'] }), false);
  assert.equal(holds('ciso-2', { listening: ['127.0.0.1:5000', '::1:5000'] }), false);
  assert.equal(holds('ciso-2', { listening: [] }), false);
  assert.equal(holds('ciso-2', { listening: [7] }), false);
  assert.equal(holds('ciso-2', { listening: 'x' }), false);
  assert.equal(one('ciso-2', { ...GOOD, listening: [] }).measured, 'listening on nothing recorded');
});

test('sec-1: six injections, each refused at a gate stage first and recognised second', () => {
  const inj = (i, over) => GOOD.injections.map((x, j) => (j === i ? { ...x, ...over } : x));
  assert.equal(holds('sec-1', { injections: GOOD.injections.slice(0, INJECTIONS - 1) }), false);
  assert.equal(holds('sec-1', { injections: [...GOOD.injections, GOOD.injections[0]] }), false);
  assert.equal(holds('sec-1', { injections: inj(2, { first: { status: 200, stage: 'signature' } }) }), false);
  assert.equal(holds('sec-1', { injections: inj(2, { first: { status: 403, stage: 'behavior' } }) }), false);
  assert.equal(holds('sec-1', { injections: inj(2, { first: { status: 403, stage: 'recognised' } }) }), false);
  assert.equal(holds('sec-1', { injections: inj(4, { second: { status: 403, stage: 'size' } }) }), false);
  assert.equal(holds('sec-1', { injections: inj(4, { second: { status: 200, stage: 'recognised' } }) }), false);
  assert.equal(holds('sec-1', { injections: 'x' }), false);
  assert.equal(holds('sec-1', { injections: [null, ...GOOD.injections.slice(1)] }), false);
  assert.equal(one('sec-1', { ...GOOD, injections: [] }).measured, 'no injections');
  assert.match(one('sec-1', GOOD).measured, /^replay: counter → recognised; flip: signature → recognised/);
});

test('sec-2, sec-3: the referee clean and the battery reproduced', () => {
  assert.equal(holds('sec-2', { referee: { ...GOOD.referee, breached: true } }), false);
  assert.equal(holds('sec-2', { referee: { ...GOOD.referee, foldMatches: false } }), false);
  assert.equal(holds('sec-2', { referee: null }), false);
  assert.match(one('sec-2', { ...GOOD, referee: { breached: true, foldMatches: false, checked: 3 } }).measured, /^BREACHED, fold does NOT match, 3 checked$/);
  assert.equal(holds('sec-3', { redteam: { ...GOOD.redteam, exit: 1 } }), false);
  assert.equal(holds('sec-3', { redteam: { ...GOOD.redteam, cases: BATTERY - 1 } }), false);
  assert.equal(holds('sec-3', { redteam: { ...GOOD.redteam, held: false } }), false);
  assert.equal(one('sec-3', GOOD).measured, '79 cases, all held, --check exit 0');
  assert.match(one('sec-3', { ...GOOD, redteam: { exit: 1, cases: 79, held: false } }).measured, /NOT all held/);
});

test('reg-1: every refusal explained, the chain verifies, and its head is the offline one', () => {
  assert.equal(holds('reg-1', { explained: { ...GOOD.explained, answers: 0 } }), false);
  assert.equal(holds('reg-1', { explained: { ...GOOD.explained, unexplained: 1 } }), false);
  assert.equal(holds('reg-1', { explained: { ...GOOD.explained, journal: 0 } }), false);
  assert.equal(holds('reg-1', { explained: { ...GOOD.explained, journalUnexplained: 1 } }), false);
  assert.equal(holds('reg-1', { chain: { ok: false, head: GOOD.derivedHead } }), false);
  assert.equal(holds('reg-1', { chain: { ok: true, head: 'b'.repeat(64) } }), false);
  assert.equal(holds('reg-1', { chain: { ok: true, head: null }, derivedHead: null }), false);
  assert.equal(one('reg-1', GOOD).measured, '12 refusal answers (0 unexplained), 12 journal records (0 unexplained); chain verifies, head equals the offline derivation');
  assert.match(one('reg-1', { ...GOOD, chain: { ok: false, head: 'b' } }).measured, /chain BROKEN, head DIFFERS/);
});

test('explained: a stage from the list and a reason of two words or more', () => {
  assert.equal(REFUSAL_STAGES.length, 13);
  assert.deepEqual(GATE_STAGES, ['size', 'magic', 'schema', 'sender', 'signature', 'counter']);
  for (const stage of REFUSAL_STAGES) assert.equal(explained({ stage, reason: 'two words' }), true, stage);
  for (const bad of [null, 'x', {}, { stage: 'nope', reason: 'two words' }, { stage: 'size', reason: 'one' }, { stage: 'size', reason: ' ' }, { stage: 'size' }, { stage: 7, reason: 'two words' }, { stage: 'size', reason: 9 }]) {
    assert.equal(explained(bad), false, JSON.stringify(bad));
  }
});

test('the judge is total: junk claims or facts are failures, never throws', () => {
  assert.deepEqual(judge(null, null), { held: 0, failed: 0, verdicts: [] });
  assert.deepEqual(judge({ claims: 'x' }, GOOD), { held: 0, failed: 0, verdicts: [] });
  const r = judge({ claims: [{ id: 'nope', role: 'X', claim: 'y' }, null, { id: 'toString' }] }, GOOD);
  assert.equal(r.failed, 3);
  assert.equal(r.verdicts[0].measured, 'no rule for this claim');
  assert.equal(r.verdicts[2].measured, 'no rule for this claim');
  const j = judge(CLAIMS, null);
  assert.equal(j.held, 0); assert.equal(j.failed, 10);
  const k = judge(CLAIMS, 'junk');
  assert.equal(k.held, 0);
});
