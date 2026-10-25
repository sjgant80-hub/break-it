import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judge, freshState, deviation, WINDOW, HALF, CALIBRATE, DRAIN_CAP, DEL_CAP, DEVIATION } from '../src/sentinel.mjs';
import { OPS } from '../src/wire.mjs';

const run = (ops) => ops.reduce((st, m) => judge(st, m).state, freshState());
const last = (ops) => { let st = freshState(), r; for (const m of ops) { r = judge(st, m); st = r.state; } return r; };

test('a fresh sender is allowed and within its own baseline', () => {
  const r = judge(freshState(), { op: OPS.SET, key: 'k', value: 'v' });
  assert.equal(r.allow, true);
  assert.equal(r.level, 'ALLOW');
});

test('an op the store does not know is blocked', () => {
  const r = judge(freshState(), { op: 0x09, key: 'k' });
  assert.equal(r.allow, false);
  assert.equal(r.level, 'BLOCK');
});

test('drain: cumulative |delta| over the window past DRAIN_CAP blocks the sender', () => {
  const big = Array.from({ length: 51 }, () => ({ op: OPS.ADD, key: 'vault', delta: 1000000 }));  // 51M > 50M
  const r = last(big);
  assert.equal(r.allow, false);
  assert.equal(r.level, 'BLOCK');
  assert.match(r.reason, /drain/);
  assert.ok(51 * 1000000 > DRAIN_CAP);
});

test('a drain just under the cap is allowed', () => {
  const ok = Array.from({ length: 49 }, () => ({ op: OPS.ADD, key: 'vault', delta: 1000000 }));  // 49M < 50M
  assert.equal(last(ok).allow, true);
});

test('destruction: more than DEL_CAP deletes in the window is STEP-UP, not admitted', () => {
  const dels = Array.from({ length: DEL_CAP + 1 }, () => ({ op: OPS.DEL, key: 'k' }));
  const r = last(dels);
  assert.equal(r.allow, false);
  assert.equal(r.level, 'STEP-UP');
});

test('deviation: once calibrated, an op-mix far from the baseline blocks', () => {
  const calibrate = Array.from({ length: CALIBRATE }, () => ({ op: OPS.SET, key: 'k', value: 'v' }));  // baseline all-SET
  const stBase = run(calibrate);
  assert.deepEqual(stBase.baseline, [1000, 0, 0, 0]);   // set · del · add · rec
  const flip = Array.from({ length: HALF + 4 }, () => ({ op: OPS.ADD, key: 'k', delta: 1 }));          // now all-ADD
  let st = stBase, blocked = null;
  for (const m of flip) { const r = judge(st, m); st = r.state; if (!r.allow) { blocked = r; break; } }   // the judgment that blocks
  assert.ok(blocked, 'an all-ADD swing from an all-SET baseline must eventually be refused');
  assert.equal(blocked.level, 'BLOCK');
  assert.match(blocked.reason, /deviation/);
});

test('a BLOCK sticks until the operator resets the sender', () => {
  const blocked = { total: 10, baseline: [1000, 0, 0], recent: [], blocked: true };
  const r = judge(blocked, { op: OPS.SET, key: 'k', value: 'v' });
  assert.equal(r.allow, false);
  assert.equal(r.level, 'BLOCK');
});

test('deviation() is 0 before a baseline and is the L1 permille distance after', () => {
  assert.equal(deviation([OPS.SET, OPS.ADD], null), 0);
  assert.equal(deviation([OPS.ADD, OPS.ADD], [1000, 0, 0]), 2000);  // all-ADD vs all-SET
});

test('judge is total: hostile state or message never throws', () => {
  for (const s of [null, undefined, 42, {}, { recent: 'no' }]) {
    for (const m of [null, undefined, 'x', { op: 99 }, {}]) {
      assert.doesNotThrow(() => judge(s, m));
      assert.equal(typeof judge(s, m).allow, 'boolean');
    }
  }
});

test('the thresholds are ordered THROTTLE < STEP_UP < BLOCK', () => {
  assert.ok(DEVIATION.THROTTLE < DEVIATION.STEP_UP);
  assert.ok(DEVIATION.STEP_UP < DEVIATION.BLOCK);
  assert.ok(WINDOW >= HALF);
});

// ── boundaries ───────────────────────────────────────────────────────────────────────────────────────────────
test('the deviation gate opens at exactly CALIBRATE + HALF packets, not before', () => {
  const calib = Array.from({ length: CALIBRATE }, () => ({ op: OPS.SET, key: 'k', value: 'v' }));
  let st = run(calib);                                            // total = CALIBRATE, baseline all-SET
  for (let i = 0; i < HALF; i++) { const r = judge(st, { op: OPS.ADD, key: 'k', delta: 1 }); st = r.state; assert.equal(r.allow, true, 'ADD ' + i + ' (prior total ' + (CALIBRATE + i) + ') is still calibrating'); }
  const r = judge(st, { op: OPS.ADD, key: 'k', delta: 1 });      // prior total = CALIBRATE + HALF → gate opens
  assert.equal(r.allow, false);
  assert.equal(r.level, 'BLOCK');
});

test('exactly DEL_CAP deletes are allowed; one more is STEP-UP', () => {
  const dels = Array.from({ length: DEL_CAP }, () => ({ op: OPS.DEL, key: 'k' }));
  assert.equal(last(dels).allow, true);
  assert.equal(last([...dels, { op: OPS.DEL, key: 'k' }]).level, 'STEP-UP');
});

test('a drain of exactly DRAIN_CAP is allowed; one unit over blocks', () => {
  const at = Array.from({ length: 50 }, () => ({ op: OPS.ADD, key: 'v', delta: 1000000 }));   // 50M === DRAIN_CAP
  assert.equal(50 * 1000000, DRAIN_CAP);
  assert.equal(last(at).allow, true);
  assert.equal(last([...at, { op: OPS.ADD, key: 'v', delta: 1 }]).allow, false);              // 50M + 1 > cap
});

test('a junk state is coerced to fresh — a valid first op is still allowed, not failed closed', () => {
  assert.equal(judge(null, { op: OPS.SET, key: 'k', value: 'v' }).allow, true);
  assert.equal(judge('nonsense', { op: OPS.ADD, key: 'k', delta: 1 }).allow, true);
});

test('a delta field carried on a non-ADD op does NOT count toward the drain', () => {
  assert.equal(judge(freshState(), { op: OPS.SET, key: 'k', value: 'v', delta: 60000000 }).allow, true);
});

test('STEP-UP gates deletes only — a SET from the same sender right after is still allowed', () => {
  const dels = Array.from({ length: DEL_CAP + 1 }, () => ({ op: OPS.DEL, key: 'k' }));
  let st = freshState(); for (const m of dels) st = judge(st, m).state;
  assert.equal(judge(st, { op: OPS.SET, key: 'k', value: 'v' }).allow, true);
});

test('the baseline is captured at CALIBRATE from the whole window, not on the first packet', () => {
  let st = judge(freshState(), { op: OPS.ADD, key: 'k', delta: 1 }).state;        // first packet ADD
  for (let i = 0; i < CALIBRATE - 1; i++) st = judge(st, { op: OPS.SET, key: 'k', value: 'v' }).state;
  assert.deepEqual(st.baseline, [Math.floor((CALIBRATE - 1) * 1000 / CALIBRATE), 0, Math.floor(1000 / CALIBRATE), 0]);
});

test('judge returns the reason that matches the verdict (ALLOW baseline vs unknown op)', () => {
  assert.match(judge(freshState(), { op: OPS.SET, key: 'k', value: 'v' }).reason, /within its own baseline/);
  assert.match(judge(freshState(), null).reason, /not an op/);     // null msg → {} → op undefined → this reason
});
