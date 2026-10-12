import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, isAdmitted, STAGES } from '../src/gate.mjs';
import { OPS, SIG, HEADER } from '../src/wire.mjs';
import { packet, ctxFor, pubHex, S1, ATTACKER } from './helpers.mjs';

test('admits a valid, in-sequence packet and hands out a frozen, admitted message', () => {
  const ctx = ctxFor({ last: 0n });
  const r = decide(packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'alice' }), ctx);
  assert.equal(r.admit, true);
  assert.equal(r.stage, 'admitted');
  assert.equal(r.msg.key, 'name');
  assert.equal(r.msg.value, 'alice');
  assert.ok(Object.isFrozen(r.msg));
  assert.equal(isAdmitted(r.msg), true);
});

test('isAdmitted is false for any object the gate did not admit', () => {
  assert.equal(isAdmitted({ sender: 1, counter: 1n, op: OPS.SET, key: 'name', value: 'alice' }), false);
  assert.equal(isAdmitted(null), false);
  assert.equal(isAdmitted('x'), false);
});

test('stage order: a size failure is reported before anything else', () => {
  const r = decide(new Uint8Array(5), ctxFor());
  assert.equal(r.admit, false);
  assert.equal(r.stage, 'size');
});

test('sender: no pinned key → refused at sender, before any signature work', () => {
  const r = decide(packet({ sender: 9, counter: 1n, op: OPS.SET, key: 'a', value: 'b', signer: ATTACKER }), ctxFor());
  assert.equal(r.stage, 'sender');
});

test('signature: a forgery under a pinned sender id is refused at signature', () => {
  const r = decide(packet({ sender: 1, counter: 1n, op: OPS.SET, key: 'a', value: 'b', signer: ATTACKER }), ctxFor({ last: 0n }));
  assert.equal(r.stage, 'signature');
});

test('signature: the right key but the wrong (empty) domain is refused at signature', () => {
  const r = decide(packet({ sender: 1, counter: 1n, op: OPS.SET, key: 'a', value: 'b', domain: '' }), ctxFor({ last: 0n }));
  assert.equal(r.stage, 'signature');
});

test('counter: a replay (≤ last) is refused, and the reason names a replay', () => {
  const r = decide(packet({ counter: 5n }), ctxFor({ last: 5n }));
  assert.equal(r.stage, 'counter');
  assert.match(r.reason, /^replay/);
});

test('counter: out of order (last + 2) is refused and NOT called a replay', () => {
  const r = decide(packet({ counter: 7n }), ctxFor({ last: 5n }));
  assert.equal(r.stage, 'counter');
  assert.doesNotMatch(r.reason, /^replay/);
});

test('counter: exactly last + 1 admits', () => {
  assert.equal(decide(packet({ counter: 6n }), ctxFor({ last: 5n })).admit, true);
});

test('fails closed when the injected crypto throws', () => {
  const ctx = ctxFor({ last: 0n });
  const boom = { keyFor: ctx.keyFor, lastCounter: ctx.lastCounter, verify: () => { throw new Error('boom'); } };
  const r = decide(packet({ counter: 1n }), boom);
  assert.equal(r.admit, false);
  assert.equal(r.stage, 'error');
});

test('fails closed when keyFor returns a wrong-sized key', () => {
  const r = decide(packet({ counter: 1n }), { keyFor: () => new Uint8Array(16), verify: () => true, lastCounter: () => 0n });
  assert.equal(r.stage, 'sender');
});

test('fails closed when lastCounter is not a bigint', () => {
  const ctx = ctxFor({ last: 0n });
  const r = decide(packet({ counter: 1n }), { keyFor: ctx.keyFor, verify: ctx.verify, lastCounter: () => 0 });
  assert.equal(r.stage, 'error');
});

test('STAGES lists the stages in order and is frozen', () => {
  assert.deepEqual(STAGES, ['size', 'magic', 'schema', 'sender', 'signature', 'counter', 'error', 'admitted']);
  assert.ok(Object.isFrozen(STAGES));
});
