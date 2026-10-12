import { test } from 'node:test';
import assert from 'node:assert/strict';
import { immuneStage, features, distance, mint, adopt, recognise, emptyLibrary,
  PERMANENT, STAGE_INDEX, WEIGHTS, RADIUS, MAX_LIBRARY } from '../src/antibody.mjs';
import { MAGIC, VERSION, HEADER, SIG } from '../src/wire.mjs';

const H = (c) => String(c).repeat(64);
const bytesOf = (len, { sender = 1, op = 1 } = {}) => { const b = new Uint8Array(len); b.set(MAGIC.slice(0, Math.min(4, len)), 0); if (len > 4) b[4] = VERSION; if (len > 5) b[5] = sender; if (len > HEADER) b[HEADER] = op; return b; };

test('immuneStage splits a counter refusal into replay (permanent) vs out-of-order (not)', () => {
  assert.equal(immuneStage({ stage: 'counter', reason: 'replay — x' }), 'replay');
  assert.equal(immuneStage({ stage: 'counter', reason: 'out of order' }), 'out-of-order');
  assert.equal(immuneStage({ stage: 'signature' }), 'signature');
  assert.equal(immuneStage({ stage: 'bogus' }), 'error');
  assert.equal(PERMANENT.includes('replay'), true);
  assert.equal(PERMANENT.includes('out-of-order'), false);
});

test('features is ten integers and the stage dominates the distance', () => {
  const f = features(bytesOf(83), 'signature');
  assert.equal(f.length, WEIGHTS.length);
  assert.ok(f.every(Number.isInteger));
  // two packets identical but for the stage are far apart (stage weight is large)
  const a = features(bytesOf(83), 'size'), b = features(bytesOf(83), 'signature');
  assert.ok(distance(a, b) > RADIUS);
});

test('distance is Infinity on malformed points', () => {
  assert.equal(distance([1, 2], [1, 2, 3]), Infinity);
  assert.equal(distance(features(bytesOf(83), 'size'), 'x'), Infinity);
});

test('mint makes an exact antibody ONLY for a permanent stage, under a named key set', () => {
  const permanent = mint(bytesOf(83), { hash: H('a'), stage: 'signature', keyset: H('b'), family: 'forgery' });
  assert.ok(permanent.exact);
  assert.equal(permanent.exact.kind, 'exact');
  const notPermanent = mint(bytesOf(83), { hash: H('a'), stage: 'out-of-order', keyset: H('b'), family: 'out-of-order' });
  assert.equal(notPermanent.exact, null);          // could still become valid → recognition only
  assert.ok(notPermanent.shape);
});

test('mint will not make an exact antibody without a valid hash and keyset', () => {
  assert.equal(mint(bytesOf(83), { hash: 'short', stage: 'signature', keyset: H('b') }).exact, null);
  assert.equal(mint(bytesOf(83), { hash: H('a'), stage: 'signature' }).exact, null);
});

test('adopt deduplicates an exact antibody and covers a shape family within RADIUS', () => {
  let lib = emptyLibrary();
  const ab = mint(bytesOf(83), { hash: H('a'), stage: 'signature', keyset: H('b'), family: 'forgery' });
  lib = adopt(lib, [ab.exact, ab.shape]).library;
  const again = adopt(lib, [ab.exact, ab.shape]);
  assert.equal(again.added, 0);                    // same exact hash + a shape already covered
  assert.equal(Object.keys(lib.exact).length, 1);
});

test('recognise drops on an exact hash match, but a key-bound antibody only under the SAME key set', () => {
  let lib = emptyLibrary();
  const ab = mint(bytesOf(83), { hash: H('a'), stage: 'signature', keyset: H('b'), family: 'forgery' });
  lib = adopt(lib, [ab.exact]).library;
  assert.equal(recognise(lib, H('a'), null, H('b')).drop, true);          // same key set → drops
  assert.equal(recognise(lib, H('a'), null, H('c')).drop, false);         // key set changed → does not fire
  assert.equal(recognise(lib, H('z'), null, H('b')).drop, false);         // unknown hash
});

test('recognise names the nearest family by shape even without an exact match', () => {
  let lib = emptyLibrary();
  const ab = mint(bytesOf(90, { op: 2 }), { stage: 'schema', family: 'schema-escape' });
  lib = adopt(lib, [ab.shape]).library;
  const near = recognise(lib, null, features(bytesOf(90, { op: 2 }), 'schema'), H('b'));
  assert.equal(near.drop, false);                  // shapes never drop
  assert.equal(near.family, 'schema-escape');
  assert.ok(near.nearest);
});

test('a size-stage exact antibody (not key-bound) drops regardless of the key set', () => {
  let lib = emptyLibrary();
  const ab = mint(bytesOf(83), { hash: H('d'), stage: 'size', keyset: H('b'), family: 'truncation' });
  lib = adopt(lib, [ab.exact]).library;
  assert.equal(recognise(lib, H('d'), null, H('anything')).drop, true);
  assert.equal(STAGE_INDEX.size, 0);
  assert.ok(MAX_LIBRARY > 0);
});

test('mint/adopt/recognise are total on junk', () => {
  assert.doesNotThrow(() => mint(null, null));
  assert.doesNotThrow(() => adopt(null, null));
  assert.doesNotThrow(() => recognise(null, null, null, null));
});

// ── boundaries ───────────────────────────────────────────────────────────────────────────────────────────────
test('features flags turn on their exact byte-length and signature edges', () => {
  // magicOk: len >= 4 with the magic present
  assert.equal(features(bytesOf(4), 'size')[2], 1);
  assert.equal(features(bytesOf(3), 'size')[2], 0);
  // sigZero (index 8) and sHigh (index 9): need a full-length packet so the signature region exists (len >= 80)
  const withSig = (fill) => { const b = bytesOf(83); b.fill(fill, 83 - SIG); return b; };
  assert.equal(features(withSig(0), 'signature')[8], 1);          // all-zero signature
  assert.equal(features(withSig(1), 'signature')[8], 0);
  const b10 = bytesOf(83); b10[82] = 0x10; assert.equal(features(b10, 'signature')[9], 1);   // s high ≥ 0x10
  const b0f = bytesOf(83); b0f[82] = 0x0f; assert.equal(features(b0f, 'signature')[9], 0);
  // a packet one byte short of a signature region has no sig flags set
  assert.equal(features(bytesOf(HEADER + SIG - 1), 'signature')[8], 0);
});

test('recognise/adopt treat distance == RADIUS as covered, RADIUS + 1 as new', () => {
  const base = Array(WEIGHTS.length).fill(0);
  const near = base.slice(); near[1] = RADIUS;                    // WEIGHTS[1] === 1 → distance exactly RADIUS
  const far = base.slice(); far[1] = RADIUS + 1;                  // distance RADIUS + 1
  assert.equal(distance(base, near), RADIUS);
  assert.equal(distance(base, far), RADIUS + 1);
  let lib = adopt(emptyLibrary(), [{ kind: 'shape', point: base, family: 'forgery', stage: 'signature' }]).library;
  // a same-family shape within RADIUS is already covered (adds nothing); beyond RADIUS is new
  assert.equal(adopt(lib, [{ kind: 'shape', point: near, family: 'forgery', stage: 'signature' }]).added, 0);
  assert.equal(adopt(lib, [{ kind: 'shape', point: far, family: 'forgery', stage: 'signature' }]).added, 1);
  // recognise names a nearest within RADIUS, none beyond
  assert.ok(recognise(lib, null, near, 'b'.repeat(64)).nearest);
  assert.equal(recognise({ exact: {}, shapes: [{ point: base, family: 'forgery', stage: 'signature' }], size: 1 }, null, far, 'b'.repeat(64)).nearest, null);
});

// ── kill the feature-read and adopt-guard mutants ────────────────────────────────────────────────────────────
test('features reads a field only where the bytes reach it, else 256 — and magicOk needs the real magic', () => {
  assert.equal(features(new Uint8Array([0x42, 0x52, 0x4b, 0x31]), 'size')[3], 256);   // version byte absent at len 4
  assert.equal(features(new Uint8Array([1, 2, 3, 4]), 'size')[2], 0);                 // no magic → magicOk 0
});

test('features declared-length feature: free below 16 bytes, computed from n otherwise (n=0 edge)', () => {
  const short = new Uint8Array(15);
  assert.equal(features(short, 'size')[5], 128);                 // len < 16 → declared -1 → 128
  const b100 = new Uint8Array(100); b100[14] = 0; b100[15] = 0;  // declared 0, actual 100-80 = 20
  assert.equal(features(b100, 'size')[5], 44);                   // declared<0 is false at 0 → clamp(0-20)+64 = 44
});

test('features signature flags need the full 64-byte region (len >= HEADER + SIG)', () => {
  assert.equal(features(new Uint8Array(HEADER + SIG), 'signature')[8], 1);       // all-zero sig at exactly 80
  assert.equal(features(new Uint8Array(HEADER + SIG - 1), 'signature')[8], 0);   // one short → no sig region
});

test('features keyLen feature reads b[HEADER+1] exactly, not an adjacent byte', () => {
  const b = new Uint8Array(20); b[15] = 0xaa; b[HEADER] = 0x01; b[HEADER + 1] = 0x05;
  assert.equal(features(b, 'schema')[7], 0x05);                  // must be b[17], never b[15]
  assert.equal(features(new Uint8Array(16), 'schema')[7], 256);  // b[17] absent at len 16 → 256
});

test('adopt rejects every malformed EXACT antibody and accepts a well-formed one', () => {
  const H = (c) => String(c).repeat(64);
  const bad = [
    { kind: 'nope', hash: H('a'), stage: 'signature', keyset: H('b') },     // wrong kind
    { kind: 'exact', hash: 123, stage: 'signature', keyset: H('b') },       // hash not a string
    { kind: 'exact', hash: 'short', stage: 'signature', keyset: H('b') },   // hash not 64 hex
    { kind: 'exact', hash: H('a'), stage: 'out-of-order', keyset: H('b') }, // not a permanent stage
    { kind: 'exact', hash: H('a'), stage: 'signature', keyset: 456 },       // keyset not a string
    { kind: 'exact', hash: H('a'), stage: 'signature', keyset: 'nothex' },  // keyset not 64 hex
  ];
  for (const b of bad) assert.equal(adopt(emptyLibrary(), [{ ...b, family: 'f' }]).added, 0, JSON.stringify([b.kind, b.stage, b.keyset]));
  assert.equal(adopt(emptyLibrary(), [{ kind: 'exact', hash: H('a'), stage: 'signature', keyset: H('b'), family: 'f' }]).added, 1);
});

test('adopt rejects every malformed SHAPE antibody and accepts a well-formed one', () => {
  const vp = Array(WEIGHTS.length).fill(0);
  const bad = [
    { kind: 'notshape', point: vp },
    { kind: 'shape', point: 'x' },
    { kind: 'shape', point: [1, 2, 3] },
    { kind: 'shape', point: vp.map((_, i) => (i === 0 ? 0.5 : 0)) },
  ];
  for (const b of bad) assert.equal(adopt(emptyLibrary(), [{ ...b, family: 'f', stage: 'size' }]).added, 0, JSON.stringify(b.kind));
  assert.equal(adopt(emptyLibrary(), [{ kind: 'shape', point: vp, family: 'f', stage: 'size' }]).added, 1);
});

test('distance returns Infinity (never NaN) when a point holds a non-integer element', () => {
  const ints = Array(WEIGHTS.length).fill(1);
  const bad = ints.slice(); bad[0] = 'x';
  assert.equal(distance(ints, bad), Infinity);
  assert.equal(distance(bad, ints), Infinity);
});

test('recognise breaks a distance tie toward the FIRST-seen shape (strict <, not <=)', () => {
  const pt = Array(WEIGHTS.length).fill(0); pt[1] = 5;         // distance 5 from the origin query
  let lib = adopt(emptyLibrary(), [{ kind: 'shape', point: pt, family: 'alpha', stage: 'size' }]).library;
  lib = adopt(lib, [{ kind: 'shape', point: pt, family: 'bravo', stage: 'size' }]).library;
  assert.equal(recognise(lib, null, Array(WEIGHTS.length).fill(0), 'b'.repeat(64)).nearest.family, 'alpha');
});
