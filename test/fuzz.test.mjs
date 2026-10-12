import { test } from 'node:test';
import assert from 'node:assert/strict';
// Every kernel entry point is documented TOTAL — it returns a safe verdict on any input, it never throws. A guard
// like `x && typeof x === 'object' ? x : {}` that is mutated to `||` stops being total (it keeps the junk and
// crashes downstream); this battery is what kills those mutants. It throws the hostile-input classes at each
// function and asserts: no throw, and the safe/typed return.
import * as wire from '../src/wire.mjs';
import { decide, isAdmitted } from '../src/gate.mjs';
import * as immune from '../src/immune.mjs';
import * as ab from '../src/antibody.mjs';
import { judge, deviation } from '../src/sentinel.mjs';
import { verifyChain, entryFor } from '../src/chain.mjs';
import { grammarOk } from '../src/referee.mjs';
import { questLog, inscription } from '../src/loot.mjs';
import { verifyWork, solve, difficultyFor, released, obeys, challenge, leadingZeroBits } from '../src/rebound.mjs';
import { createHash } from 'node:crypto';

const circular = {}; circular.self = circular;
const toxic = { get stage() { throw new Error('toxic'); }, get length() { throw new Error('toxic'); } };
const HOSTILE = [null, undefined, NaN, Infinity, -1, 0, 1, '', '  ', 'str', true, false, 10n, [], {}, circular, toxic,
  new Uint8Array(0), new Uint8Array(5), new Uint8Array(400), { stage: 'x' }, { reason: 1 }, () => {}];
const sha = (s) => createHash('sha256').update(String(s)).digest('hex');

const neverThrows = (name, fn, extraArgs = []) => test('total: ' + name + ' never throws on hostile input', () => {
  for (const x of HOSTILE) assert.doesNotThrow(() => fn(x, ...extraArgs), name + ' threw on ' + String(x));
});

// wire
neverThrows('rawCheck', wire.rawCheck);
neverThrows('parse', wire.parse);
neverThrows('encodeUnsigned', wire.encodeUnsigned);
neverThrows('withSignature', (x) => wire.withSignature(x, new Uint8Array(wire.SIG)));
test('total: these return the safe value, not junk, on null', () => {
  assert.equal(wire.parse(null), null);
  assert.equal(wire.encodeUnsigned(null), null);
  assert.equal(wire.rawCheck(null).ok, false);
});

// gate — decide must fail closed, never throw, never admit
test('total: decide never throws and never admits junk', () => {
  const ctx = { keyFor: () => new Uint8Array(32), verify: () => true, lastCounter: () => 0n };
  for (const x of HOSTILE) {
    let r;
    assert.doesNotThrow(() => { r = decide(x, ctx); });
    assert.equal(r.admit, false);
  }
  assert.equal(isAdmitted(null), false);
});

// immune
neverThrows('classify', immune.classify, [{}]);
neverThrows('classify(facts junk)', (x) => immune.classify({ stage: 'size' }, x));
neverThrows('fingerprint', (x) => immune.fingerprint('forgery', { bytes: x }));
neverThrows('learn', (x) => immune.learn(x, { family: 'forgery', print: 'p', source: 's' }));
neverThrows('learn(event junk)', (x) => immune.learn(immune.emptyMemory(), x));
neverThrows('standing', (x) => immune.standing(immune.emptyMemory(), x));
neverThrows('standing(mem junk)', (x) => immune.standing(x, 's'));
neverThrows('detail', (x) => immune.detail(x, false));

// antibody
neverThrows('immuneStage', ab.immuneStage);
neverThrows('features', (x) => ab.features(x, 'signature'));
neverThrows('distance', (x) => ab.distance(x, x));
neverThrows('mint', (x) => ab.mint(x, { hash: 'a'.repeat(64), stage: 'signature', keyset: 'b'.repeat(64) }));
neverThrows('mint(facts junk)', (x) => ab.mint(new Uint8Array(83), x));
neverThrows('adopt', (x) => ab.adopt(ab.emptyLibrary(), x));
neverThrows('adopt(lib junk)', (x) => ab.adopt(x, []));
neverThrows('recognise', (x) => ab.recognise(x, 'a'.repeat(64), null, 'b'.repeat(64)));

// sentinel
neverThrows('judge(state junk)', (x) => judge(x, { op: 1, key: 'k', value: 'v' }));
neverThrows('judge(msg junk)', (x) => judge(undefined, x));
neverThrows('deviation', (x) => deviation(x, [1000, 0, 0]));

// chain
neverThrows('verifyChain', (x) => verifyChain(x, sha));
neverThrows('entryFor', (x) => entryFor(x, 0, 'ab', sha));

// referee
neverThrows('grammarOk', grammarOk);

// loot
neverThrows('questLog', questLog);
neverThrows('inscription', inscription);

// rebound
neverThrows('verifyWork', (x) => verifyWork(x, 'ff', 8, sha));
neverThrows('verifyWork(nonce junk)', (x) => verifyWork('c', x, 8, sha));
neverThrows('difficultyFor', difficultyFor);
neverThrows('released', released);
neverThrows('obeys', obeys);
neverThrows('challenge', (x) => challenge(1, x, 'a'.repeat(64)));
neverThrows('leadingZeroBits', leadingZeroBits);
test('total: solve terminates and returns null past its cap on junk', () => {
  assert.doesNotThrow(() => solve('c', 0, sha));
  assert.equal(solve(null, 24, sha, 1), null);
});
