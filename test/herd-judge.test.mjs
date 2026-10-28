// test/herd-judge.test.mjs — the herd's judge (herd/judge.mjs): every sealed claim held on good facts, and each one
// failed by the fact that should fail it. Pure; no node runs here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { judge, RULES, DOOR, REFUSED } from '../herd/judge.mjs';

const CLAIMS = JSON.parse(readFileSync(new URL('../herd/claims.json', import.meta.url), 'utf8'));
const peer = (node, ms, same = DOOR) => ({ node, patchedAfterMs: ms, by: 'peer', same });
const GOOD = {
  h1: { sent: 5, outcomes: { schema: 5 }, breaches: 0 },
  h2: { sent: 5, outcomes: { admitted: 5 }, breaches: 5, patched: 0 },
  h3: { first: 'admitted', node1: { patch: true, by: 'self' }, peers: [peer(2, 20), peer(3, 25, 'recognised'), peer(4, 2000), peer(5, 0)], breaches: 1 },
  h4: { sent: 100, outcomes: { [DOOR]: 100 }, breaches: 1 },
  h5: { shareStatus: { 200: 4 }, patched: 0, nextGenuine: { admitted: 5 } },
  h6: { sent: 15000, outcomes: { admitted: 15000 }, booksMatch: [true, true, true, true, true] },
  h7: { restarted: [{ node: 1, patch: true, by: 'ledger', variant: DOOR }, { node: 2, patch: true, by: 'journal', variant: DOOR }] },
};
const one = (id, facts) => judge(CLAIMS, facts).verdicts.find((v) => v.id === id);
const holds = (id, facts) => one(id, facts).held;
const set = (path, value) => { const f = structuredClone(GOOD); let o = f; const ks = path.split('.'); for (const k of ks.slice(0, -1)) o = o[k]; o[ks.at(-1)] = value; return f; };

test('the judge has a rule for every sealed claim, and good facts hold all seven', () => {
  assert.deepEqual(CLAIMS.claims.map((c) => c.id), Object.keys(RULES));
  const j = judge(CLAIMS, GOOD);
  assert.equal(j.held, 7); assert.equal(j.failed, 0);
  assert.deepEqual(REFUSED, [DOOR, 'recognised']);
});

test('each claim fails on the fact that should fail it', () => {
  for (const [id, path, v] of [
    ['h-1', 'h1.sent', 4], ['h-1', 'h1.outcomes', { schema: 4, admitted: 1 }], ['h-1', 'h1.outcomes', { schema: 5, admitted: 1 }], ['h-1', 'h1.breaches', 1],
    ['h-2', 'h2.sent', 4], ['h-2', 'h2.outcomes', { admitted: 4, schema: 1 }], ['h-2', 'h2.breaches', 4], ['h-2', 'h2.patched', 1],
    ['h-3', 'h3.first', 'schema'], ['h-3', 'h3.node1.patch', false], ['h-3', 'h3.node1.by', 'peer'], ['h-3', 'h3.breaches', 2], ['h-3', 'h3.breaches', 0],
    ['h-3', 'h3.peers', GOOD.h3.peers.slice(1)], ['h-3', 'h3.peers.0.patchedAfterMs', 2001], ['h-3', 'h3.peers.0.patchedAfterMs', null],
    ['h-3', 'h3.peers.0.by', 'journal'], ['h-3', 'h3.peers.0.same', 'admitted'], ['h-3', 'h3.peers.0.same', 'counter'],
    ['h-4', 'h4.sent', 99], ['h-4', 'h4.outcomes', { [DOOR]: 99, admitted: 1 }], ['h-4', 'h4.outcomes', { recognised: 100 }], ['h-4', 'h4.breaches', 2],
    ['h-5', 'h5.shareStatus', { 200: 3, 403: 1 }], ['h-5', 'h5.patched', 1], ['h-5', 'h5.nextGenuine', { admitted: 4, schema: 1 }],
    ['h-6', 'h6.sent', 14999], ['h-6', 'h6.outcomes', { admitted: 14999, counter: 1 }], ['h-6', 'h6.booksMatch', [true, true, true, true, false]], ['h-6', 'h6.booksMatch', [true, true, true, true]],
    ['h-7', 'h7.restarted', GOOD.h7.restarted.slice(0, 1)], ['h-7', 'h7.restarted.0.patch', false], ['h-7', 'h7.restarted.0.by', 'journal'],
    ['h-7', 'h7.restarted.1.by', 'peer'], ['h-7', 'h7.restarted.1.variant', 'admitted'], ['h-7', 'h7.restarted.0.variant', 'recognised'],
  ]) assert.equal(holds(id, set(path, v)), false, id + ' with ' + path + ' = ' + JSON.stringify(v));
});

test('what each verdict says it measured', () => {
  assert.match(one('h-6', GOOD).measured, /books equal to the records held on 5 of 5 nodes$/);
  assert.match(one('h-6', set('h6.booksMatch', [true, false, true, true, true])).measured, /on 4 of 5 nodes$/);
  assert.match(one('h-1', { h1: { sent: 5, outcomes: {}, breaches: 0 } }).measured, /5 nodes: nothing; breaches 0$/);
  assert.match(one('h-1', GOOD).measured, /^the shipped gate, 5 nodes: 5 schema; breaches 0$/);
});

test('total: missing or junk facts fail every claim and never throw', () => {
  for (const f of [null, undefined, 5, 'x', [], {}, { h1: 5, h3: { peers: 'x' }, h7: { restarted: 5 } }]) {
    const j = judge(CLAIMS, f);
    assert.equal(j.held, 0, JSON.stringify(f)); assert.equal(j.failed, 7);
  }
  assert.deepEqual(judge(null, GOOD), { held: 0, failed: 0, verdicts: [] });
  assert.equal(judge({ claims: [{ id: 'h-9', role: 'x', claim: 'y' }] }, GOOD).verdicts[0].measured, 'no rule for this claim');
});
