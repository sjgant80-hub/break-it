// test/patch.test.mjs — the herd patch's two rules, every input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evidence, door, REASON } from '../src/patch.mjs';
import { grammarOk } from '../src/referee.mjs';
import { decide } from '../src/gate.mjs';
import { packet, ctxFor } from './helpers.mjs';
import { OPS } from '../src/wire.mjs';

const VALUES = [true, false, null, undefined, 0, 1, 'true', 'false', {}, []];

test('evidence: a zero-day is proven only when the gate admits the bytes and the independent grammar rejects them', () => {
  for (const a of VALUES) for (const g of VALUES) assert.equal(evidence(a, g), a === true && g === false, JSON.stringify([a, g]));
});

test('door: once on, a packet the grammar rejects is refused at stage schema; otherwise the gate’s verdict stands', () => {
  for (const on of VALUES) for (const g of VALUES) {
    const d = door(on, g);
    if (on === true && g === false) assert.deepEqual(d, { stage: 'schema', reason: REASON });
    else assert.equal(d, null, JSON.stringify([on, g]));
  }
});

test('a genuine packet is never evidence and never shut out: the gate admits it and the grammar accepts it', () => {
  for (const [i, p] of [packet({ counter: 1n }), packet({ counter: 2n, op: OPS.DEL, key: 'k' }), packet({ counter: 3n, op: OPS.ADD, key: 'bal', delta: -5 })].entries()) {
    assert.equal(decide(p, ctxFor({ last: BigInt(i) })).admit, true, 'genuine ' + i);
    assert.equal(evidence(true, grammarOk(p)), false);
    assert.equal(door(true, grammarOk(p)), null);
  }
});
