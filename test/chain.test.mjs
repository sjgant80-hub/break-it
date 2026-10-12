import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { GENESIS, material, entryFor, verifyChain } from '../src/chain.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');
const chain = (packets) => { let prev = GENESIS; return packets.map((p, i) => { const e = entryFor(prev, i, p, sha); prev = e.hash; return e; }); };
const PK = (n) => 'ab'.repeat(n);   // a valid packet-hex of n bytes

test('entryFor builds an entry that commits to the previous hash', () => {
  const e = entryFor(GENESIS, 0, PK(83), sha);
  assert.deepEqual(Object.keys(e).sort(), ['hash', 'packet', 'prev', 'seq']);
  assert.equal(e.prev, GENESIS);
  assert.equal(e.hash, sha(material(0, GENESIS, PK(83))));
});

test('entryFor returns null on malformed inputs', () => {
  assert.equal(entryFor('short', 0, PK(83), sha), null);
  assert.equal(entryFor(GENESIS, -1, PK(83), sha), null);
  assert.equal(entryFor(GENESIS, 0, 'nothex', sha), null);
  assert.equal(entryFor(GENESIS, 0, '', sha), null);
});

test('verifyChain accepts an honest chain and returns the head', () => {
  const entries = chain([PK(83), PK(90), PK(100)]);
  const v = verifyChain(entries, sha);
  assert.equal(v.ok, true);
  assert.equal(v.head, entries[entries.length - 1].hash);
});

test('an altered packet anywhere breaks the chain', () => {
  const entries = chain([PK(83), PK(90), PK(100)]);
  entries[1].packet = PK(91);
  const v = verifyChain(entries, sha);
  assert.equal(v.ok, false);
  assert.equal(v.at, 1);
});

test('a deleted entry breaks the sequence', () => {
  const entries = chain([PK(83), PK(90), PK(100)]);
  const v = verifyChain([entries[0], entries[2]], sha);
  assert.equal(v.ok, false);
});

test('reordering two entries breaks the prev links', () => {
  const entries = chain([PK(83), PK(90), PK(100), PK(110)]);
  const v = verifyChain([entries[0], entries[2], entries[1], entries[3]], sha);
  assert.equal(v.ok, false);
});

test('an entry with extra or missing fields is rejected', () => {
  const entries = chain([PK(83)]);
  const extra = { ...entries[0], note: 'x' };
  assert.equal(verifyChain([extra], sha).ok, false);
  const { hash, ...missing } = entries[0];
  assert.equal(verifyChain([missing], sha).ok, false);
});

test('the empty chain verifies to GENESIS', () => {
  const v = verifyChain([], sha);
  assert.equal(v.ok, true);
  assert.equal(v.head, GENESIS);
});

test('verifyChain is total on junk', () => {
  assert.equal(verifyChain('nope', sha).ok, false);
  assert.equal(verifyChain([null], sha).ok, false);
});

test('verifyChain names a non-object entry as not-an-object (caught by the guard, not a later check)', () => {
  assert.match(verifyChain([42], sha).reason, /not an object/);
  assert.match(verifyChain([[1, 2, 3, 4]], sha).reason, /not an object/);
});
