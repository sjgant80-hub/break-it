import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, fingerprint, learn, standing, detail, emptyMemory, FAMILIES, LADDER, WINDOW, MAX_FINGERPRINTS } from '../src/immune.mjs';
import { HEADER, SIG, MAGIC, VERSION, MIN_PACKET, MAX_PACKET } from '../src/wire.mjs';

const bytesOf = (len) => { const b = new Uint8Array(len); b.set(MAGIC.slice(0, Math.min(4, len)), 0); if (len > 4) b[4] = VERSION; return b; };

test('classify maps each gate stage to the right family', () => {
  assert.equal(classify({ stage: 'http' }, {}), 'http');
  assert.equal(classify({ stage: 'flood' }, {}), 'flood');
  assert.equal(classify({ stage: 'behavior' }, {}), 'behavior');
  assert.equal(classify({ stage: 'magic' }, {}), 'malformed');
  assert.equal(classify({ stage: 'schema' }, {}), 'schema-escape');
  assert.equal(classify({ stage: 'sender' }, {}), 'unknown-sender');
  assert.equal(classify({ stage: 'signature' }, {}), 'forgery');
  assert.equal(classify({ stage: 'weird' }, {}), 'fault');
});

test('classify splits a size failure into truncation vs extension by the declared length', () => {
  const declaredLength = 10;
  const want = HEADER + declaredLength + SIG;
  assert.equal(classify({ stage: 'size' }, { bytes: bytesOf(want - 4), declaredLength }), 'truncation');
  assert.equal(classify({ stage: 'size' }, { bytes: bytesOf(want + 4), declaredLength }), 'extension');
  assert.equal(classify({ stage: 'size' }, { bytes: bytesOf(5), declaredLength: null }), 'malformed');
});

test('classify splits a counter failure into replay (exact) vs out-of-order', () => {
  assert.equal(classify({ stage: 'counter', reason: 'replay — ...' }, {}), 'replay');
  assert.equal(classify({ stage: 'counter', reason: 'out of order — ...' }, { exactReplay: true }), 'replay');
  assert.equal(classify({ stage: 'counter', reason: 'out of order — ...' }, {}), 'out-of-order');
});

test('fingerprint is a stable pipe-joined signature of how the attack was built', () => {
  const b = bytesOf(83); b[5] = 7; b[HEADER] = 3;
  assert.equal(fingerprint('forgery', { bytes: b }), 'forgery|fits|brk1|op3|s7');
  assert.equal(fingerprint('nonsense', { bytes: b }).startsWith('fault|'), true);
});

test('learn flags the FIRST sighting of a fingerprint as novel, not later ones', () => {
  let m = emptyMemory();
  const a = learn(m, { family: 'forgery', print: 'p1', source: 'x' });
  assert.equal(a.novel, true);
  const b = learn(a.memory, { family: 'forgery', print: 'p1', source: 'x' });
  assert.equal(b.novel, false);
  assert.equal(b.memory.prints.p1, 2);
  assert.equal(b.memory.novel, 1);
});

test('learn counts per source and per family', () => {
  let m = emptyMemory();
  m = learn(m, { family: 'replay', print: 'a', source: 's' }).memory;
  m = learn(m, { family: 'replay', print: 'b', source: 's' }).memory;
  assert.equal(m.sources.s, 2);
  assert.equal(m.families.replay, 2);
});

test('standing climbs the GEP ladder with a source refusal count', () => {
  const at = (n) => { let m = emptyMemory(); m.sources.s = n; return standing(m, 's'); };
  assert.equal(at(0), 'ALLOW');
  assert.equal(at(LADDER.THROTTLE), 'THROTTLE');
  assert.equal(at(LADDER.BLOCK), 'BLOCK');
  assert.equal(at(LADDER.ISOLATE), 'ISOLATE');
  assert.equal(at(LADDER.THROTTLE - 1), 'ALLOW');
});

test('detail keeps a novel attack in full even from a BLOCK source; otherwise counts', () => {
  assert.equal(detail('ALLOW', false), 'full');
  assert.equal(detail('THROTTLE', false), 'full');
  assert.equal(detail('BLOCK', false), 'count');
  assert.equal(detail('ISOLATE', false), 'count');
  assert.equal(detail('ISOLATE', true), 'full');   // a vaccine is always kept whole
});

test('source counts halve every WINDOW events (recent behaviour decays)', () => {
  let m = emptyMemory();
  for (let i = 0; i < WINDOW; i++) m = learn(m, { family: 'forgery', print: 'p' + (i % 3), source: 's' }).memory;
  assert.ok(m.sources.s <= WINDOW / 2 + 1);   // halved at the WINDOW boundary
});

test('learn is total on junk and respects the fingerprint bound', () => {
  assert.doesNotThrow(() => learn(null, null));
  assert.equal(FAMILIES.includes('forgery'), true);
  assert.ok(MAX_FINGERPRINTS > 0);
});

// ── boundaries ───────────────────────────────────────────────────────────────────────────────────────────────
test('truncation vs extension turns exactly on the wanted length', () => {
  const declaredLength = 10, want = HEADER + declaredLength + SIG;
  assert.equal(classify({ stage: 'size' }, { bytes: bytesOf(want - 1), declaredLength }), 'truncation');
  assert.equal(classify({ stage: 'size' }, { bytes: bytesOf(want), declaredLength }), 'extension');   // < want is false at want
  assert.equal(classify({ stage: 'size' }, { bytes: bytesOf(want + 1), declaredLength }), 'extension');
});

test('fingerprint length class turns on MIN_PACKET and MAX_PACKET', () => {
  const cls = (len) => fingerprint('forgery', { bytes: bytesOf(len) }).split('|')[1];
  assert.equal(cls(0), 'empty');
  assert.equal(cls(MIN_PACKET - 1), 'short');
  assert.equal(cls(MIN_PACKET), 'fits');
  assert.equal(cls(MAX_PACKET), 'fits');
  assert.equal(cls(MAX_PACKET + 1), 'long');
});

test('standing sits one below each rung before stepping up', () => {
  const at = (n) => { let m = emptyMemory(); m.sources.s = n; return standing(m, 's'); };
  assert.equal(at(LADDER.BLOCK - 1), 'THROTTLE');
  assert.equal(at(LADDER.ISOLATE - 1), 'BLOCK');
});

test('learn increments the event counter', () => {
  let m = emptyMemory();
  m = learn(m, { family: 'forgery', print: 'p', source: 's' }).memory;
  m = learn(m, { family: 'forgery', print: 'q', source: 's' }).memory;
  assert.equal(m.events, 2);
});

test('a print of exactly 128 and a source of exactly 64 are kept; one longer is replaced', () => {
  const keep = learn(emptyMemory(), { family: 'forgery', print: 'p'.repeat(128), source: 's'.repeat(64) }).memory;
  assert.ok(Object.prototype.hasOwnProperty.call(keep.prints, 'p'.repeat(128)));
  assert.ok(Object.prototype.hasOwnProperty.call(keep.sources, 's'.repeat(64)));
  const drop = learn(emptyMemory(), { family: 'forgery', print: 'p'.repeat(129), source: 's'.repeat(65) }).memory;
  assert.ok(Object.prototype.hasOwnProperty.call(drop.prints, 'fault|unprintable'));
  assert.ok(Object.prototype.hasOwnProperty.call(drop.sources, 'unknown'));
});

test('fingerprint marks BRK1 only with magic AND version present (len >= 5), else other', () => {
  assert.ok(fingerprint('forgery', { bytes: bytesOf(5) }).includes('brk1'));
  assert.ok(fingerprint('forgery', { bytes: bytesOf(4) }).includes('other'));
});

test('fingerprint reads op and sender only when the bytes reach those offsets', () => {
  const withOp = (() => { const b = bytesOf(HEADER + 1); b[HEADER] = 3; return b; })();
  assert.ok(fingerprint('forgery', { bytes: withOp }).includes('op3'));
  assert.ok(fingerprint('forgery', { bytes: bytesOf(HEADER) }).includes('op-1'));   // no payload byte → op -1
  assert.ok(fingerprint('forgery', { bytes: bytesOf(6) }).includes('|s0'));         // len 6 → sender byte at [5] present (0)
  assert.ok(fingerprint('forgery', { bytes: bytesOf(5) }).includes('|s-1'));        // len 5 → index 5 absent → s-1
});

test('fingerprint marks other unless BOTH magic and version are present', () => {
  assert.ok(fingerprint('forgery', { bytes: new Uint8Array([1, 2, 3, 4, 5]) }).includes('other'));             // no magic
  assert.ok(fingerprint('forgery', { bytes: new Uint8Array([0x42, 0x52, 0x4b, 0x31, 0x09]) }).includes('other')); // magic, wrong version
});

test('learn stops minting new fingerprints at MAX_FINGERPRINTS (novel goes false, no room)', () => {
  let m = emptyMemory();
  for (let i = 0; i < MAX_FINGERPRINTS; i++) m = learn(m, { family: 'forgery', print: 'p' + i, source: 's' }).memory;
  assert.equal(learn(m, { family: 'forgery', print: 'overflow', source: 's' }).novel, false);
});
