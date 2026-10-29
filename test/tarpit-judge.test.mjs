// test/tarpit-judge.test.mjs — the tarpit's judge (tarpit/judge.mjs): every sealed claim held on good facts, each one
// failed by the fact that should fail it, and garbage judged, never thrown. Pure; no node runs here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { judge, RULES, SEALED } from '../tarpit/judge.mjs';

const CLAIMS = JSON.parse(readFileSync(new URL('../tarpit/claims.json', import.meta.url), 'utf8'));
const held = { status: 403, spaces: 20, spacesOnly: true };
const same = { status: true, headers: true, lengthCountsSpaces: true, spacesOnly: true, spaces: 20, jsonEqual: true };
const GOOD = {
  p1: { sent: 3000, admitted: 3000, held: 0, attackerHeldMeanwhile: 2 },
  books: { records: 3500, match: true },
  p2: { sent: 100, admitted: 100, held: 0, paidWork: 100, bits: [18] },
  p3: { first: 500, firstRefused: 500, firstAnsweredAtOnce: 500, then: 3, thenHeld: [held, held, held] },
  p4: { off: { answers: 300, held: 0, seconds: 120 }, on: { answers: 6, held: 6, seconds: 121 } },
  p5: { sent: 100, maxHolding: 64, cap: 64, heldWhenGenuineBegan: 64, heldWhenGenuineEnded: 64, held: 64, quick: 36, full: 36,
    genuine: { sent: 200, admittedBase: 200, admittedBusy: 200, medianBaseMs: 4.1, medianBusyMs: 6.2, heldBusy: 0 } },
  p6: [same, same, same], p6all: true,
  p7: { libraryEqual: true, exact: 503, shapes: 1, journalEqual: true, journalRecords: 503 },
  p8: { aborted: true, bytes: 5, spacesOnly: true, holdingAfter: 0, abandonedRose: 1 },
};
const one = (id, facts) => judge(CLAIMS, facts).verdicts.find((v) => v.id === id);
const holds = (id, facts) => one(id, facts).held;
const set = (path, value) => { const f = structuredClone(GOOD); let o = f; const ks = path.split('.'); for (const k of ks.slice(0, -1)) o = o[k]; o[ks.at(-1)] = value; return f; };

test('the judge has a rule for every sealed claim, and good facts hold all eight', () => {
  assert.deepEqual(CLAIMS.claims.map((c) => c.id), Object.keys(RULES));
  const j = judge(CLAIMS, GOOD);
  assert.equal(j.held, 8); assert.equal(j.failed, 0);
  assert.ok(Object.isFrozen(SEALED));
});

test('each claim fails on the fact that should fail it', () => {
  const cases = [
    ['p-1', 'p1.admitted', 2999], ['p-1', 'p1.held', 1], ['p-1', 'p1.sent', 2000], ['p-1', 'books.match', false], ['p-1', 'p1.attackerHeldMeanwhile', 0],
    ['p-2', 'p2.admitted', 99], ['p-2', 'p2.held', 1], ['p-2', 'p2.paidWork', 99], ['p-2', 'p2.sent', 50],
    ['p-3', 'p3.firstAnsweredAtOnce', 499], ['p-3', 'p3.firstRefused', 499], ['p-3', 'p3.first', 400], ['p-3', 'p3.thenHeld', [held, held]], ['p-3', 'p3.thenHeld', [held, held, { ...held, spaces: 19 }]],
    ['p-3', 'p3.thenHeld', [held, held, { ...held, spacesOnly: false }]], ['p-3', 'p3.thenHeld', [held, held, { ...held, status: 402 }]],
    ['p-4', 'p4.off.answers', 59], ['p-4', 'p4.on.answers', 0], ['p-4', 'p4.on', {}],
    ['p-5', 'p5.maxHolding', 65], ['p-5', 'p5.held', 65], ['p-5', 'p5.quick', 35], ['p-5', 'p5.heldWhenGenuineBegan', 63], ['p-5', 'p5.heldWhenGenuineEnded', 0], ['p-5', 'p5.sent', 99],
    ['p-5', 'p5.genuine.medianBusyMs', 14.2], ['p-5', 'p5.genuine.admittedBusy', 199], ['p-5', 'p5.genuine.admittedBase', 199], ['p-5', 'p5.genuine.heldBusy', 1], ['p-5', 'p5.genuine.sent', 100], ['p-5', 'p5.genuine.medianBaseMs', null],
    ['p-6', 'p6', [same, same]], ['p-6', 'p6', [same, same, { ...same, jsonEqual: false }]], ['p-6', 'p6', [same, same, { ...same, headers: false }]], ['p-6', 'p6', [same, same, { ...same, status: false }]],
    ['p-6', 'p6', [same, same, { ...same, lengthCountsSpaces: false }]], ['p-6', 'p6', [same, same, { ...same, spacesOnly: false }]], ['p-6', 'p6', [same, same, { ...same, spaces: 21 }]],
    ['p-7', 'p7.libraryEqual', false], ['p-7', 'p7.journalEqual', false],
    ['p-8', 'p8.aborted', false], ['p-8', 'p8.spacesOnly', false], ['p-8', 'p8.bytes', 6], ['p-8', 'p8.holdingAfter', 1], ['p-8', 'p8.abandonedRose', 0], ['p-8', 'p8.abandonedRose', 2],
  ];
  for (const [id, path, value] of cases) assert.equal(holds(id, set(path, value)), false, id + ' with ' + path + ' = ' + JSON.stringify(value));
  for (const id of Object.keys(RULES)) assert.equal(holds(id, GOOD), true, id);
});

test('edges that hold: exactly ten times fewer, exactly 10 ms slower, fewer spaces than the cap', () => {
  assert.equal(holds('p-4', set('p4.off.answers', 60)), true);
  assert.equal(holds('p-5', set('p5.genuine.medianBusyMs', 14.1)), true);
  assert.equal(holds('p-8', set('p8.bytes', 0)), true);
  assert.equal(holds('p-5', set('p5.maxHolding', 63)), true);
  assert.equal(holds('p-1', set('p1.attackerHeldMeanwhile', 1)), true, 'held once meanwhile is held');
  assert.equal(holds('p-4', { ...structuredClone(GOOD), p4: { off: { answers: 10, seconds: 120 }, on: { answers: 1, seconds: 120 } } }), true, 'one answer against ten is ten times fewer');
});

test('the measured words carry the numbers', () => {
  assert.match(one('p-4', GOOD).measured, /300; in 121 s with it on: 6 \(50 times fewer\)/);
  assert.match(one('p-5', GOOD).measured, /median 6\.2 ms, against 4\.1 ms/);
  assert.match(one('p-6', GOOD).measured, /every answer of the sequence equal/);
  assert.doesNotMatch(one('p-6', set('p6all', false)).measured, /every answer/);
  assert.match(one('p-2', GOOD).measured, /at 18 bits/);
});

test('garbage is judged, never thrown', () => {
  for (const f of [null, undefined, 0, 'x', [], {}, { p1: 'x', p3: { thenHeld: 'x' }, p6: {} }]) {
    const j = judge(CLAIMS, f);
    assert.equal(j.held, 0); assert.equal(j.verdicts.length, 8);
  }
  assert.deepEqual(judge(null, GOOD), { held: 0, failed: 0, verdicts: [] });
  assert.equal(judge({ claims: [{ id: 'p-9' }] }, GOOD).verdicts[0].measured, 'no rule for this claim');
  const bad = { get p1() { throw new Error('boom'); } };
  assert.match(judge(CLAIMS, bad).verdicts[0].measured, /could not be read: boom/);
});
