// tarpit.test.mjs — the tarpit holds only a confirmed attacker's permanent refusal, with room; never an admission, a work
// challenge, a refusal a genuine client could cause, or anything below CONFIRM; what it drips is spaces only; its
// settings never widen it; nonsense is answered, never thrown.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TARPIT, HELD_STAGES, SPACE, settings, decide, ticks, inert, heldBody } from '../src/tarpit.mjs';
import { REBOUND_LADDER } from '../src/rebound.mjs';

const C = TARPIT.CONFIRM;

test('the defaults: confirmation is the rebound ladder’s top rung; a full hold is twenty one-space ticks', () => {
  assert.equal(TARPIT.CONFIRM, REBOUND_LADDER.ISOLATE);
  assert.deepEqual({ ...TARPIT }, { CONFIRM: 500, HOLD_MS: 20000, DRIP_MS: 1000, CAP: 64 });
  assert.equal(ticks(), 20); assert.equal(SPACE, 0x20);
  assert.ok(Object.isFrozen(TARPIT) && Object.isFrozen(HELD_STAGES));
  assert.deepEqual([...HELD_STAGES], ['size', 'magic', 'schema', 'sender', 'signature', 'recognised']);
});

test('held: a confirmed attacker’s permanent refusal, while there is room', () => {
  for (const s of HELD_STAGES) assert.equal(decide(403, s, C, 0).hold, true, s);
  assert.equal(decide(403, 'signature', C + 1000, TARPIT.CAP - 1).hold, true);
  assert.match(decide(403, 'signature', C, 0).why, /held 20000 ms/);
});

test('separation: an admission, a work challenge, and a refusal a genuine client could cause are answered at once', () => {
  for (const code of [200, 201, 402, 429, 400, 500, 0, -403, 403.5]) assert.equal(decide(code, 'signature', C * 10, 0).hold, false, String(code));
  assert.match(decide(402, 'rebound', C * 10, 0).why, /anyone can pay/);
  assert.match(decide(200, 'admitted', C * 10, 0).why, /not a refusal/);
  for (const s of ['counter', 'replay', 'behavior', 'error', 'flood', 'http', 'rebound', 'door', '', 'SIGNATURE', null, undefined, 7])
    assert.equal(decide(403, s, C * 10, 0).hold, false, String(s));
  assert.match(decide(403, 'behavior', C, 0).why, /genuine client could cause/);
});

test('graduated: below CONFIRM refusals nothing is held — exactly at CONFIRM it is', () => {
  assert.equal(decide(403, 'signature', C - 1, 0).hold, false);
  assert.match(decide(403, 'signature', C - 1, 0).why, /not a confirmed attacker/);
  assert.equal(decide(403, 'signature', C, 0).hold, true);
  for (const r of [0, 1, 99, 100, 499, -1, 1.5, NaN, Infinity, '600', null]) assert.equal(decide(403, 'signature', r, 0).hold, false, String(r));
});

test('bounded: at CAP holds the next refusal goes out at once; a count that is no count is full', () => {
  assert.equal(decide(403, 'signature', C, TARPIT.CAP).hold, false);
  assert.match(decide(403, 'signature', C, TARPIT.CAP).why, /full/);
  for (const a of [TARPIT.CAP + 1, -1, 1.5, NaN, '0', null, undefined]) assert.equal(decide(403, 'signature', C, a).hold, false, String(a));
});

test('settings: whole positive numbers replace a default; anything else keeps it; a drip never outlasts its hold', () => {
  const t = settings({ CONFIRM: 3, HOLD_MS: 300, DRIP_MS: 100, CAP: 2 });
  assert.deepEqual({ ...t }, { CONFIRM: 3, HOLD_MS: 300, DRIP_MS: 100, CAP: 2 });
  assert.equal(ticks(t), 3);
  assert.equal(decide(403, 'magic', 3, 1, t).hold, true); assert.equal(decide(403, 'magic', 2, 1, t).hold, false); assert.equal(decide(403, 'magic', 3, 2, t).hold, false);
  assert.deepEqual({ ...settings({ CONFIRM: 0, HOLD_MS: -5, DRIP_MS: 2.5, CAP: '9', extra: 1 }) }, { ...TARPIT });
  assert.deepEqual({ ...settings(null) }, { ...TARPIT }); assert.deepEqual({ ...settings('x') }, { ...TARPIT });
  assert.equal(settings({ HOLD_MS: 500, DRIP_MS: 2000 }).DRIP_MS, 500, 'clamped to the hold');
  assert.ok(Object.isFrozen(t));
  for (const bad of [{}, { CONFIRM: 'x' }, { CONFIRM: 0, CAP: 0 }, null, () => 0, 'x'])
    assert.equal(decide(403, 'signature', 0, 0, bad).hold, false, 'a malformed setting never widens it: ' + String(JSON.stringify(bad)));
  assert.equal(decide(403, 'signature', C, TARPIT.CAP, { CAP: 'many' }).hold, false);
});

test('ticks: a hold over its drip, rounded down; no whole drip, no ticks', () => {
  assert.equal(ticks({ HOLD_MS: 2500, DRIP_MS: 1000 }), 2);
  assert.equal(ticks({ HOLD_MS: 1000, DRIP_MS: 1000 }), 1);
  for (const t of [{ HOLD_MS: 1000, DRIP_MS: 0 }, { HOLD_MS: -1, DRIP_MS: 1 }, { HOLD_MS: 1, DRIP_MS: 1.5 }, null, 'x', {}]) assert.equal(ticks(t), 0, JSON.stringify(t));
});

test('inert: spaces only — any other byte, or no bytes object, is not', () => {
  assert.equal(inert(new Uint8Array(0)), true);
  assert.equal(inert(Buffer.from('     ')), true);
  for (const b of [Buffer.from('  \n'), Buffer.from(' \t'), Uint8Array.of(0x20, 0x00), Uint8Array.of(0x21), Buffer.from(' <')]) assert.equal(inert(b), false);
  for (const b of [null, undefined, 5, {}, { length: 'x' }]) assert.equal(inert(b), false);
});

test('the held body is the dripped spaces, then the refusal exactly — and it still parses as the refusal', () => {
  const refusal = JSON.stringify({ dropped: true, stage: 'signature', reason: 'bad signature' });
  const b = heldBody(20, refusal);
  assert.equal(b, ' '.repeat(20) + refusal);
  assert.deepEqual(JSON.parse(b), JSON.parse(refusal));
  assert.equal(inert(Buffer.from(b.slice(0, 20))), true);
  assert.equal(heldBody(-3, refusal), refusal); assert.equal(heldBody(1.5, refusal), refusal); assert.equal(heldBody(0, 'x'), 'x');
});

test('fuzz: garbage never throws', () => {
  const junk = [undefined, null, 0, -1, NaN, Infinity, '', 'x', {}, [], 403, 'signature', Symbol('s'), () => 0, new Uint8Array(3)];
  for (const a of junk) for (const b of junk) assert.doesNotThrow(() => { decide(a, b, a, b, a); decide(403, b, C, a, settings(a)); settings(a); ticks(a); inert(a); heldBody(a, b === undefined ? '' : 'r'); });
});
