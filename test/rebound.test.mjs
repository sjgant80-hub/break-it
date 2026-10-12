import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { leadingZeroBits, difficultyFor, challenge, verifyWork, solve, obeys, released,
  elasticHolds, ratchetHolds, BITS, REBOUND_LADDER, DEFENDER_COST, MAX_BITS } from '../src/rebound.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');

test('leadingZeroBits counts zero BITS, not nibbles', () => {
  assert.equal(leadingZeroBits('00ff'), 8);
  assert.equal(leadingZeroBits('08ff'), 4);
  assert.equal(leadingZeroBits('ffff'), 0);
  assert.equal(leadingZeroBits('1fff'), 3);
  assert.equal(leadingZeroBits(''), 0);
  assert.equal(leadingZeroBits(null), 0);
});

test('difficultyFor steps at BLOCK and ISOLATE, and is 0 below the elastic limit', () => {
  assert.equal(difficultyFor(0), 0);
  assert.equal(difficultyFor(REBOUND_LADDER.BLOCK - 1), 0);
  assert.equal(difficultyFor(REBOUND_LADDER.BLOCK), BITS.BLOCK);
  assert.equal(difficultyFor(REBOUND_LADDER.ISOLATE - 1), BITS.BLOCK);
  assert.equal(difficultyFor(REBOUND_LADDER.ISOLATE), BITS.ISOLATE);
  assert.equal(difficultyFor('nonsense'), 0);
});

test('challenge binds epoch, source and packet hash', () => {
  const h = 'a'.repeat(64);
  assert.notEqual(challenge(1, 'x', h), challenge(2, 'x', h));
  assert.notEqual(challenge(1, 'x', h), challenge(1, 'y', h));
  assert.notEqual(challenge(1, 'x', h), challenge(1, 'x', 'b'.repeat(64)));
  assert.ok(challenge(1, 'x', h).startsWith('BREAK-IT/rebound/v1|'));
});

test('verifyWork: zero bits is free; a solved token verifies in one hash; a wrong one fails', () => {
  assert.equal(verifyWork('c', null, 0, sha), true);
  const c = challenge(1, 's', 'a'.repeat(64));
  const n = solve(c, 8, sha);
  assert.ok(n);
  assert.equal(verifyWork(c, n, 8, sha), true);
  assert.equal(verifyWork(c, '0', 8, sha), leadingZeroBits(sha(c + '|0')) >= 8);  // almost surely false
  assert.equal(verifyWork(c, 'zz', 8, sha), false);                               // not a hex nonce
});

test('a token solved for one challenge does not satisfy another', () => {
  const c1 = challenge(1, 's', 'a'.repeat(64)), c2 = challenge(1, 's', 'b'.repeat(64));
  const n = solve(c1, 8, sha);
  assert.equal(verifyWork(c1, n, 8, sha), true);
  assert.equal(verifyWork(c2, n, 8, sha), leadingZeroBits(sha(c2 + '|' + n)) >= 8);  // not transferable
});

test('verifyWork never throws, is free for a non-positive ask, and clamps a huge ask to MAX_BITS', () => {
  assert.equal(verifyWork(null, null, 8, sha), false);
  assert.doesNotThrow(() => verifyWork('c', 'ff', 999, sha));
  const c = challenge(1, 's', 'a'.repeat(64));
  assert.equal(verifyWork(c, 'ff', 0, sha), true);                // a non-positive ask is always free
  assert.equal(verifyWork(c, '-5', -5, sha), true);
  // clamp: an ask above MAX_BITS is treated as MAX_BITS — same verdict as asking exactly MAX_BITS, for any nonce
  for (const n of ['0', '1', 'ab', 'ffff']) assert.equal(verifyWork(c, n, 999, sha), verifyWork(c, n, MAX_BITS, sha));
});

test('THE LAW — obeys: O(1) defender, attacker ≥ defender, ratchet never slips', () => {
  assert.equal(obeys({ attackerWork: 4096, defenderWork: 1 }).ok, true);
  assert.equal(obeys({ attackerWork: 0, defenderWork: 2 }).ok, false);          // amplification at the defender
  assert.equal(obeys({ attackerWork: 1, defenderWork: 1 }).ok, true);
  assert.equal(obeys({ attackerWork: 0, defenderWork: 1 }).ok, false);          // attacker spent less than defender
  assert.equal(obeys({ attackerWork: 10, defenderWork: 1, bitsBefore: 12, bitsAfter: 8 }).ok, false);  // ratchet slipped
  assert.equal(obeys({ attackerWork: 10, defenderWork: 1, bitsBefore: 12, bitsAfter: 18 }).ok, true);
  assert.equal(DEFENDER_COST, 1);
});

test('THE ELASTIC LAW — released: free under the limit, rising past it, never unwinding', () => {
  assert.equal(released(0), 1);
  assert.equal(released(REBOUND_LADDER.BLOCK - 1), 1);
  assert.equal(released(REBOUND_LADDER.BLOCK), Math.pow(2, BITS.BLOCK));
  assert.ok(released(REBOUND_LADDER.ISOLATE) > released(REBOUND_LADDER.BLOCK));
  assert.equal(elasticHolds().ok, true);
  assert.equal(ratchetHolds(), true);
});

test('solve returns a verifiable nonce and respects the cap', () => {
  const c = challenge(1, 's', 'a'.repeat(64));
  assert.equal(solve(c, 0, sha), '0');
  assert.equal(solve(c, 24, sha, 2), null);        // 2 attempts cannot find a 24-bit token
});

// ── boundaries ───────────────────────────────────────────────────────────────────────────────────────────────
test('obeys treats equal before/after bits as holding (the ratchet may stay, not only rise)', () => {
  assert.equal(obeys({ attackerWork: 10, defenderWork: 1, bitsBefore: 12, bitsAfter: 12 }).ok, true);
  assert.equal(obeys({ attackerWork: 1, defenderWork: 1 }).ok, true);     // attacker == defender is allowed
});

test('verifyWork turns on exactly `bits`: a token with precisely b leading zero bits passes', () => {
  const c = challenge(1, 's', 'a'.repeat(64));
  // find a nonce whose digest has EXACTLY 1 leading zero bit (first nibble 4..7)
  let exact1 = null;
  for (let i = 0; i < 100000 && exact1 === null; i++) { if (leadingZeroBits(sha(c + '|' + i.toString(16))) === 1) exact1 = i.toString(16); }
  assert.ok(exact1, 'expected to find a 1-bit nonce');
  assert.equal(verifyWork(c, exact1, 1, sha), true);               // >= 1 holds at exactly 1
  assert.equal(verifyWork(c, exact1, 2, sha), false);              // but not >= 2
});

test('verifyWork fails CLOSED when the hash function throws (never fail-open)', () => {
  assert.equal(verifyWork('c', 'ab', 8, () => { throw new Error('boom'); }), false);
});

test('solve returns a token meeting AT LEAST the asked bits', () => {
  const c = challenge(1, 's', 'a'.repeat(64));
  const n = solve(c, 4, sha);
  assert.ok(leadingZeroBits(sha(c + '|' + n)) >= 4);
});
