import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rawCheck, parse, encodeUnsigned, signedBytes, headerOf, withSignature,
  MAGIC, VERSION, HEADER, SIG, MIN_PACKET, MAX_PACKET, MAX_VALUE, MAX_KEY, MAX_DELTA, OPS, DOMAIN } from '../src/wire.mjs';
import { packet } from './helpers.mjs';

// a packet's raw bytes, unsigned, for poking at the raw check (signature content is irrelevant to rawCheck)
const unsigned = (m) => encodeUnsigned(m);
const full = (m) => { const u = unsigned(m); return u && new Uint8Array([...u, ...new Uint8Array(SIG)]); };

test('rawCheck accepts a well-formed packet and reports its payload length', () => {
  const b = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'name', value: 'alice' });
  const r = rawCheck(b);
  assert.equal(r.ok, true);
  assert.equal(r.n, b.length - HEADER - SIG);
});

test('rawCheck is total on hostile input — never throws, always a verdict', () => {
  for (const x of [null, undefined, 42, 'str', {}, [], new Uint8Array(0), new Uint8Array(5), new Uint8Array(1000)]) {
    const r = rawCheck(x);
    assert.equal(typeof r.ok, 'boolean');
    if (!r.ok) assert.ok(['size', 'magic', 'schema'].includes(r.stage));
  }
});

test('size: below MIN_PACKET and above MAX_PACKET are refused at size', () => {
  assert.equal(rawCheck(new Uint8Array(MIN_PACKET - 1)).stage, 'size');
  assert.equal(rawCheck(new Uint8Array(MAX_PACKET + 1)).stage, 'size');
});

test('magic and version are enforced', () => {
  const b = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'a', value: 'b' });
  const bad = b.slice(); bad[0] ^= 0xff;
  assert.equal(rawCheck(bad).stage, 'magic');
  const wrongV = b.slice(); wrongV[4] = VERSION + 1;
  assert.equal(rawCheck(wrongV).stage, 'magic');
});

test('a length field that does not match the packet size is refused at size', () => {
  const b = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'a', value: 'b' });
  const lie = b.slice(); lie[15] = (lie[15] + 1) & 0xff;
  assert.equal(rawCheck(lie).stage, 'size');
});

test('schema: keys must be 1..MAX_KEY of [a-z][a-z0-9_]', () => {
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: '', value: 'x' }), null);
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'A', value: 'x' }), null);
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: '1abc', value: 'x' }), null);
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'a'.repeat(MAX_KEY + 1), value: 'x' }), null);
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'a'.repeat(MAX_KEY), value: 'x' }));
});

test('schema: a value over MAX_VALUE, or non-printable, is refused', () => {
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'x'.repeat(MAX_VALUE + 1) }), null);
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'x'.repeat(MAX_VALUE) }));
  // a control byte in the value → rawCheck schema refusal
  const b = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'ab' });
  const ctrl = b.slice(); ctrl[HEADER + 3 + 1 + 1] = 0x7f;       // second value byte → DEL char
  assert.equal(rawCheck(ctrl).stage, 'schema');
});

test('schema: a delta beyond ±MAX_DELTA is refused', () => {
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.ADD, key: 'k', delta: MAX_DELTA + 1 }), null);
  assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.ADD, key: 'k', delta: -(MAX_DELTA + 1) }), null);
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.ADD, key: 'k', delta: MAX_DELTA }));
});

test('schema: an unknown op is refused', () => {
  const b = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'a', value: 'b' });
  const bad = b.slice(); bad[HEADER] = 0x09;
  assert.equal(rawCheck(bad).stage, 'schema');
});

test('CANONICAL: for every packet rawCheck accepts, encode(parse(b)) === b', () => {
  const cases = [
    { op: OPS.SET, key: 'name', value: 'alice' },
    { op: OPS.SET, key: 'k', value: '' },
    { op: OPS.DEL, key: 'gone' },
    { op: OPS.ADD, key: 'balance', delta: 123456 },
    { op: OPS.ADD, key: 'balance', delta: -1 },
    { op: OPS.ADD, key: 'z', delta: 0 },
  ];
  for (const c of cases) {
    const u = unsigned({ sender: 7, counter: 99n, ...c });
    assert.ok(u, JSON.stringify(c));
    const b = new Uint8Array([...u, ...new Uint8Array(SIG)]);
    assert.equal(rawCheck(b).ok, true);
    const m = parse(b);
    const re = unsigned(m);
    assert.deepEqual(Array.from(re), Array.from(u), 'encode(parse(b)) must equal the header+payload of b for ' + JSON.stringify(c));
  }
});

test('parse returns null for anything rawCheck rejects (total for direct callers)', () => {
  assert.equal(parse(new Uint8Array(10)), null);
  assert.equal(parse('nope'), null);
});

test('encodeUnsigned rejects an ASCII-truncating (>0x7f) key or value char', () => {
  assert.equal(encodeUnsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'š', value: 'x' }), null);
  assert.equal(encodeUnsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'š' }), null);
});

test('encodeUnsigned rejects out-of-range sender and counter', () => {
  assert.equal(encodeUnsigned({ sender: 256, counter: 1n, op: OPS.SET, key: 'k', value: 'v' }), null);
  assert.equal(encodeUnsigned({ sender: -1, counter: 1n, op: OPS.SET, key: 'k', value: 'v' }), null);
  assert.equal(encodeUnsigned({ sender: 1, counter: 0n, op: OPS.SET, key: 'k', value: 'v' }), null);
  assert.equal(encodeUnsigned({ sender: 1, counter: 5, op: OPS.SET, key: 'k', value: 'v' }), null);  // not a bigint
});

test('headerOf reads sender and the big-endian counter', () => {
  const b = packet({ sender: 3, counter: 0x0102030405060708n, op: OPS.DEL, key: 'k' });
  const r = rawCheck(b);
  const h = headerOf(b, r.n);
  assert.equal(h.sender, 3);
  assert.equal(h.counter, 0x0102030405060708n);
  assert.equal(h.sig.length, SIG);
});

test('signedBytes is DOMAIN followed by header+payload, and withSignature round-trips', () => {
  const u = unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'a', value: 'b' });
  const b = new Uint8Array([...u, ...new Uint8Array(SIG)]);
  const n = rawCheck(b).n;
  const sb = signedBytes(b, n);
  assert.equal(sb.length, DOMAIN.length + HEADER + n);
  assert.deepEqual(Array.from(sb.subarray(0, DOMAIN.length)), Array.from(DOMAIN, (c) => c.charCodeAt(0)));
  assert.ok(withSignature(u, new Uint8Array(SIG)));
  assert.equal(withSignature(u, new Uint8Array(SIG - 1)), null);
});

// ── boundaries (the reachable edges the mutation gate probes) ────────────────────────────────────────────────
test('a MAX-size packet (payload = MAX_PAYLOAD-shaped) is accepted; one byte over is refused at size', () => {
  const big = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'x'.repeat(MAX_VALUE) });
  assert.equal(rawCheck(big).ok, true);
  assert.equal(rawCheck(new Uint8Array(MAX_PACKET + 1)).stage, 'size');
  // exactly MAX_PACKET and exactly MIN_PACKET are the accepted edges
  const min = full({ sender: 1, counter: 1n, op: OPS.DEL, key: 'a' });   // smallest payload (DEL, 1-char key) = 3
  assert.equal(min.length, MIN_PACKET);
  assert.equal(rawCheck(min).ok, true);
});

test('key tail accepts digits, lowercase and underscore; rejects punctuation and uppercase', () => {
  for (const k of ['a0', 'a9', 'a_', 'az', 'a_z9']) assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.DEL, key: k }), k);
  for (const k of ['a/', 'a:', 'a@', 'aB', 'a~']) assert.equal(unsigned({ sender: 1, counter: 1n, op: OPS.DEL, key: k }), null, k);
});

test('value accepts the printable edges 0x20 and 0x7e; a byte just outside is refused', () => {
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: ' ' }));   // 0x20
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: '~' }));   // 0x7e
  const b = full({ sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'a' });
  const lo = b.slice(); lo[HEADER + 3 + 1] = 0x1f; assert.equal(rawCheck(lo).stage, 'schema');
  const hi = b.slice(); hi[HEADER + 3 + 1] = 0x7f; assert.equal(rawCheck(hi).stage, 'schema');
});

test('delta accepts exactly ±MAX_DELTA and 0', () => {
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.ADD, key: 'k', delta: MAX_DELTA }));
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.ADD, key: 'k', delta: -MAX_DELTA }));
  assert.ok(unsigned({ sender: 1, counter: 1n, op: OPS.ADD, key: 'k', delta: 0 }));
});

test('sender accepts the edges 0 and 255; counter accepts 1 and 2^64-1', () => {
  assert.ok(unsigned({ sender: 0, counter: 1n, op: OPS.DEL, key: 'k' }));
  assert.ok(unsigned({ sender: 255, counter: 1n, op: OPS.DEL, key: 'k' }));
  assert.ok(unsigned({ sender: 1, counter: (2n ** 64n) - 1n, op: OPS.DEL, key: 'k' }));
  assert.equal(unsigned({ sender: 1, counter: 2n ** 64n, op: OPS.DEL, key: 'k' }), null);
});

test('a 336-byte packet claiming n=256 passes the size guard but fails at SCHEMA (the > MAX_PACKET edge)', () => {
  const b = new Uint8Array(MAX_PACKET); b.set(MAGIC, 0); b[4] = VERSION; b[14] = 0x01; b[15] = 0x00;  // n = 256
  assert.equal(b.length, HEADER + 256 + SIG);      // length matches, so size passes; a 256-byte payload is never valid grammar
  assert.equal(rawCheck(b).stage, 'schema');
});
