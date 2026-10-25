// ingest.test.mjs — REC, the ingest gateway's record: three integers on raw bytes, range-checked before any parse; the
// naive app posts it; the referee checks it with its own grammar; the sentinel caps what one key can post in a window.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rawCheck, parse, encodeUnsigned, withSignature, signedBytes, OPS, HEADER, SIG, REC_N, MAX_ACCOUNT, MAX_PERIOD, MAX_AMOUNT } from '../src/wire.mjs';
import { decide } from '../src/gate.mjs';
import { makeApp } from '../src/app.mjs';
import { makeReferee, grammarOk } from '../src/referee.mjs';
import { judge, freshState, POST_CAP, WINDOW, CALIBRATE, HALF, DEVIATION } from '../src/sentinel.mjs';
import { makeClient } from '../src/client.mjs';
import { signWith } from '../src/keys.mjs';
import { S1, ATTACKER, ctxFor } from './helpers.mjs';

/** a real signed record */
function record({ sender = 1, counter = 1n, account = 1, period = 63, amount = 100, signer = S1 } = {}) {
  const u = encodeUnsigned({ sender, counter, op: OPS.REC, account, period, amount });
  if (!u) throw new Error('test built an invalid record');
  return withSignature(u, signWith(signer)(signedBytes(new Uint8Array([...u, ...new Uint8Array(SIG)]), REC_N)));
}
/** raw record bytes with any field values at all (bypassing the encoder), a zero signature: for the raw checks */
function rawRecord({ account = 1, period = 0, amount = 0, n = REC_N, extra = [] } = {}) {
  const body = [OPS.REC, (account >>> 24) & 0xff, (account >>> 16) & 0xff, (account >>> 8) & 0xff, account & 0xff, (period >> 8) & 0xff, period & 0xff,
    (amount >>> 24) & 0xff, (amount >>> 16) & 0xff, (amount >>> 8) & 0xff, amount & 0xff, ...extra].slice(0, n);
  const b = new Uint8Array(HEADER + body.length + SIG);
  b.set([0x42, 0x52, 0x4b, 0x31, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, body.length >> 8, body.length & 0xff], 0);
  b.set(body, HEADER);
  return b;
}

test('the wire: a record is exactly three range-checked integers, parsed into exactly those fields', () => {
  assert.deepEqual([OPS.REC, REC_N, MAX_ACCOUNT, MAX_PERIOD, MAX_AMOUNT], [5, 11, 99999999, 1199, 100000000]);
  const p = record({ account: 30000, period: 68, amount: 1684259 });
  assert.deepEqual(rawCheck(p), { ok: true, n: 11 });
  assert.equal(p.length, HEADER + 11 + SIG);
  assert.deepEqual(parse(p), { sender: 1, counter: 1n, op: OPS.REC, account: 30000, period: 68, amount: 1684259 });
  assert.equal('key' in parse(p), false, 'a record carries no key');
  // canonical: the one encoding of what parse returns is the very bytes
  for (const f of [{ account: 1, period: 0, amount: 0 }, { account: MAX_ACCOUNT, period: MAX_PERIOD, amount: MAX_AMOUNT }, { account: 16777217, period: 257, amount: 65537 }]) {
    const b = record(f), m = parse(b);
    assert.deepEqual(encodeUnsigned(m), b.subarray(0, HEADER + 11), JSON.stringify(f));
  }
});

test('the wire: every field is checked at its exact edge on the raw bytes, before anything is parsed', () => {
  const ok = (f) => rawCheck(rawRecord(f));
  assert.equal(ok({ account: 1 }).ok, true);
  assert.equal(ok({ account: MAX_ACCOUNT }).ok, true);
  assert.equal(ok({ period: MAX_PERIOD }).ok, true);
  assert.equal(ok({ amount: MAX_AMOUNT }).ok, true);
  const refused = [
    [{ account: 0 }, 'an account is 1–99999999'], [{ account: MAX_ACCOUNT + 1 }, 'an account is 1–99999999'],
    [{ account: 0x80000000 }, 'an account is 1–99999999'], [{ account: 0xffffffff }, 'an account is 1–99999999'],
    [{ period: MAX_PERIOD + 1 }, 'a period is a month from January 2000 to December 2099 (0–1199)'], [{ period: 0xffff }, 'a period is a month from January 2000 to December 2099 (0–1199)'],
    [{ amount: MAX_AMOUNT + 1 }, 'an amount is 0–100000000'], [{ amount: 0x80000000 }, 'an amount is 0–100000000'], [{ amount: 0xffffffff }, 'an amount is 0–100000000'],
    [{ n: 10 }, 'a record is exactly 11 bytes'], [{ n: 12, extra: [0] }, 'a record is exactly 11 bytes'],
  ];
  for (const [f, why] of refused) assert.deepEqual(ok(f), { ok: false, stage: 'schema', reason: why }, JSON.stringify(f));
  assert.equal(parse(rawRecord({ account: 0 })), null, 'the parser itself refuses what the raw check refuses');
});

test('the encoder refuses every record outside the grammar, so a client can never sign one', () => {
  const base = { sender: 1, counter: 1n, op: OPS.REC, account: 5, period: 3, amount: 9 };
  assert.ok(encodeUnsigned(base));
  for (const bad of [{ account: 0 }, { account: MAX_ACCOUNT + 1 }, { account: 1.5 }, { account: '5' }, { period: -1 }, { period: MAX_PERIOD + 1 }, { period: 2.5 },
    { amount: -1 }, { amount: MAX_AMOUNT + 1 }, { amount: 1.5 }, { amount: 9n }, { account: undefined }]) assert.equal(encodeUnsigned({ ...base, ...bad }), null, JSON.stringify(bad, (k, v) => typeof v === 'bigint' ? 'big' : v));
  assert.equal(encodeUnsigned({ ...base, account: MAX_ACCOUNT, period: MAX_PERIOD, amount: MAX_AMOUNT }).length, HEADER + 11);
  assert.equal(encodeUnsigned({ ...base, account: 1, period: 0, amount: 0 }).length, HEADER + 11);
});

test('the gate: a genuine record is admitted; a forged one, a replayed one and an out-of-order one are not', () => {
  const ctx = ctxFor();
  const r = decide(record({ counter: 1n }), ctx);
  assert.equal(r.admit, true);
  assert.equal(r.msg.amount, 100);
  assert.equal(decide(record({ counter: 1n, signer: ATTACKER }), ctx).stage, 'signature');
  ctx.set(1, 1n);
  assert.equal(decide(record({ counter: 1n }), ctx).stage, 'counter');
  assert.equal(decide(record({ counter: 3n }), ctx).stage, 'counter');
  assert.equal(decide(record({ counter: 2n }), ctx).admit, true);
  assert.equal(decide(rawRecord({ amount: MAX_AMOUNT + 1 }), ctx).stage, 'schema', 'schema refuses before the signature is even tried');
});

test('the app: a record posts its amount to its account and keeps the posting, apart from every key a SET can write', () => {
  const app = makeApp();
  app.apply({ op: OPS.REC, account: 7, period: 63, amount: 500 });
  app.apply({ op: OPS.REC, account: 7, period: 64, amount: 250 });
  app.apply({ op: OPS.REC, account: 9, period: 63, amount: 0 });
  app.apply({ op: OPS.SET, key: 'a7', value: 'x' });
  assert.deepEqual(app.state(), { A7: 750, 'P7.63': 500, 'P7.64': 250, A9: 0, 'P9.63': 0, a7: 'x' });
  app.apply({ op: OPS.REC, account: 7, period: 63, amount: 500 });
  assert.equal(app.state().A7, 1250, 'naive: a record posted twice counts twice — the app checks nothing');
});

test('the referee: its own grammar takes a genuine record and refuses each field past its edge', () => {
  assert.equal(grammarOk(record({ account: MAX_ACCOUNT, period: MAX_PERIOD, amount: MAX_AMOUNT })), true);
  assert.equal(grammarOk(record({ account: 1, period: 0, amount: 0 })), true);
  for (const f of [{ account: 0 }, { account: MAX_ACCOUNT + 1 }, { period: MAX_PERIOD + 1 }, { amount: MAX_AMOUNT + 1 }, { n: 10 }, { n: 12, extra: [0] }]) assert.equal(grammarOk(rawRecord(f)), false, JSON.stringify(f));
  for (const v of [1, MAX_ACCOUNT]) assert.equal(grammarOk(rawRecord({ account: v })), true);
  assert.equal(grammarOk(rawRecord({ period: MAX_PERIOD })), true);
  assert.equal(grammarOk(rawRecord({ amount: MAX_AMOUNT })), true);
});

test('the referee: an admitted record raises nothing; the app acting on another amount is a breach; the fold replays records', () => {
  const ctx = ctxFor(), ref = makeReferee(), app = makeApp(), packets = [];
  for (let i = 1; i <= 3; i++) {
    const p = record({ counter: BigInt(i), account: i, amount: i * 10 }), d = decide(p, ctx);
    ctx.set(1, BigInt(i)); packets.push(p);
    app.apply(d.msg);
    assert.equal(ref.after(d.msg, p), null);
  }
  assert.equal(ref.fold(app, packets), true);
  const p = record({ counter: 4n, amount: 40 }), d = decide(p, ctx);
  const b = ref.after(Object.freeze({ ...d.msg }), p);
  assert.equal(b.why, 'the app was handed a message the gate never admitted');
  const other = record({ counter: 4n, amount: 41 });
  assert.equal(ref.after(d.msg, other).why, 'the app acted on something other than the ledger entry');
  app.apply({ op: OPS.REC, account: 1, period: 63, amount: 1 });
  assert.equal(ref.fold(app, packets), false, 'a posting the ledger does not hold breaks the fold');
});

test('the sentinel: records within the cap are allowed; past POST_CAP in a window the key is blocked — to the unit', () => {
  assert.equal(POST_CAP, 10000000);
  let s = freshState();
  const post = (amount) => { const r = judge(s, { op: OPS.REC, account: 1, period: 0, amount }); s = r.state; return r; };
  assert.equal(post(POST_CAP - 1).allow, true);
  assert.equal(post(1).allow, true, 'exactly the cap is allowed');
  const over = post(1);
  assert.deepEqual([over.allow, over.level], [false, 'BLOCK']);
  assert.equal(over.reason, 'inflation — ' + (POST_CAP + 1) + ' posted in 3 packets is over ' + POST_CAP);
  assert.equal(judge(over.state, { op: OPS.REC, account: 1, period: 0, amount: 0 }).reason, 'this sender is blocked until its operator resets it');
  // the window slides: what fell out of the last WINDOW packets no longer counts
  s = freshState();
  post(POST_CAP);
  for (let i = 0; i < WINDOW - 1; i++) assert.equal(post(0).allow, true);
  assert.equal(post(POST_CAP).allow, true, 'the first big posting has left the window');
  assert.equal(post(1).allow, false);
});

test('the sentinel: a record is its own kind in the op mix — an all-record baseline sees an all-SET swing', () => {
  let s = freshState();
  for (let i = 0; i < CALIBRATE; i++) s = judge(s, { op: OPS.REC, account: 1, period: 0, amount: 1 }).state;
  assert.deepEqual(s.baseline, [0, 0, 0, 1000]);
  let blocked = false;
  for (let i = 0; i < HALF * 2 && !blocked; i++) { const r = judge(s, { op: OPS.SET, key: 'k', value: 'v' }); s = r.state; blocked = !r.allow && r.level === 'BLOCK'; }
  assert.ok(blocked, 'an all-SET swing from an all-record baseline is refused');
  assert.ok(DEVIATION.BLOCK <= 2000);
});

test('the client builds a record feed the gate admits, in order', () => {
  const c = makeClient({ privateKey: S1 }), ctx = ctxFor();
  for (let i = 1; i <= 3; i++) {
    const d = decide(c.next({ op: OPS.REC, account: i, period: 63 + i, amount: 1000 * i }), ctx);
    assert.deepEqual([d.admit, d.msg.account, d.msg.period, d.msg.amount, d.msg.counter], [true, i, 63 + i, 1000 * i, BigInt(i)]);
    ctx.set(1, BigInt(i));
  }
});

test('the app: ADD on a fresh key starts from nothing; SET and DEL do exactly what they say', () => {
  const app = makeApp();
  app.apply({ op: OPS.ADD, key: 'k', delta: 5 });
  assert.equal(app.state().k, 5, 'a fresh key adds from 0, not from nothing-at-all');
  app.apply({ op: OPS.ADD, key: 'k', delta: -2 });
  app.apply({ op: OPS.SET, key: 's', value: 'v' });
  app.apply({ op: OPS.SET, key: 'n', value: '7' });
  app.apply({ op: OPS.ADD, key: 'n', delta: 1 });
  assert.deepEqual(app.state(), { k: 3, s: 'v', n: 8 });
  app.apply({ op: OPS.DEL, key: 's' });
  assert.deepEqual(app.state(), { k: 3, n: 8 });
  assert.equal(app.log.length, 6);
});

test('the sentinel: only an ADD moves the drain and only a REC moves the posted total — a stray field counts for nothing', () => {
  const { DRAIN_CAP } = { DRAIN_CAP: 50000000 };
  const set = judge(freshState(), { op: OPS.SET, key: 'k', value: 'v', delta: DRAIN_CAP + 1, amount: POST_CAP + 1 });
  assert.deepEqual([set.allow, set.level], [true, 'ALLOW'], 'a SET carrying a delta and an amount is just a SET');
  const add = judge(freshState(), { op: OPS.ADD, key: 'k', delta: 1, amount: POST_CAP + 1 });
  assert.equal(add.allow, true, 'an ADD carrying an amount posts nothing');
  const rec = judge(freshState(), { op: OPS.REC, account: 1, period: 0, amount: 1, delta: DRAIN_CAP + 1 });
  assert.equal(rec.allow, true, 'a record carrying a delta drains nothing');
  assert.equal(judge(freshState(), { op: OPS.ADD, key: 'k', delta: DRAIN_CAP + 1 }).allow, false);
  assert.equal(judge(freshState(), { op: OPS.REC, account: 1, period: 0, amount: POST_CAP + 1 }).allow, false);
  assert.equal(judge(freshState(), { op: OPS.REC, account: 1, period: 0, amount: 1.5 }).allow, true, 'a fractional amount posts nothing (the wire never yields one)');
});
