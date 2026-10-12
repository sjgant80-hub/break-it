import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verify as edVerify } from 'node:crypto';
import { inscription, runeMaterial, mintRune, questLog, QUESTS, RUNE_DOMAIN } from '../src/loot.mjs';
import { packet, S1, pubHex } from './helpers.mjs';
import { signWith, publicFromRaw } from '../src/keys.mjs';
import { OPS } from '../src/wire.mjs';

const hex = (u8) => Buffer.from(u8).toString('hex');

test('inscription reads what the breaker smuggled into the packet (its value)', () => {
  const p = packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'I WAS HERE' });
  assert.equal(inscription(p), 'I WAS HERE');
});

test('inscription falls back to the key, then to hex, and strips non-printables', () => {
  assert.equal(inscription(packet({ counter: 1n, op: OPS.DEL, key: 'gone' })), 'gone');
  assert.match(inscription(new Uint8Array([1, 2, 3])), /^hex:/);
});

test('mintRune produces a LEGENDARY whose signature verifies under the node key', () => {
  const p = packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'pwned' });
  const rune = mintRune({ node: pubHex(S1), at: '2026-01-01T00:00:00.000Z', seq: 3, why: 'the gate admitted a forgery', packet: hex(p) }, signWith(S1));
  assert.equal(rune.tier, 'LEGENDARY');
  assert.equal(rune.name, "The Breaker's Rune");
  assert.equal(rune.inscription, 'pwned');
  const ok = edVerify(null, Buffer.from(runeMaterial(rune)), publicFromRaw(Buffer.from(pubHex(S1), 'hex')), Buffer.from(rune.sig, 'hex'));
  assert.equal(ok, true);
});

test('the rune signature does NOT verify if the breach packet is swapped', () => {
  const p = packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'pwned' });
  const rune = mintRune({ node: pubHex(S1), at: 't', seq: 1, why: 'w', packet: hex(p) }, signWith(S1));
  const forged = { ...rune, packet: hex(packet({ counter: 2n, op: OPS.SET, key: 'name', value: 'other' })) };
  const ok = edVerify(null, Buffer.from(runeMaterial(forged)), publicFromRaw(Buffer.from(pubHex(S1), 'hex')), Buffer.from(forged.sig, 'hex'));
  assert.equal(ok, false);
  assert.ok(runeMaterial(rune).startsWith(RUNE_DOMAIN));
});

test('questLog counts a RARE shard per NOVEL attack, credited to its source, not to peers', () => {
  const records = [
    { family: 'forgery', novel: true, source: '1.2.3.4' },
    { family: 'forgery', novel: false, source: '1.2.3.4' },
    { family: 'replay', novel: true, source: '1.2.3.4' },
    { family: 'schema-escape', novel: true, source: 'peer:abcd' },   // learned from a peer, not a shard
  ];
  const ql = questLog(records);
  assert.equal(ql.shards['1.2.3.4'], 2);
  assert.equal(ql.shards['peer:abcd'], undefined);
});

test('questLog lights a quest by attempts and never marks it won from refusals alone', () => {
  const ql = questLog([{ family: 'forgery', novel: true, source: 'x' }, { family: 'unknown-sender', novel: true, source: 'x' }]);
  const forge = ql.quests.find((q) => q.id === 'forge');
  assert.equal(forge.attempts, 2);
  assert.match(forge.status, /every one refused/);
  assert.equal(ql.quests.every((q) => q.won === false), true);
  assert.ok(QUESTS.length >= 6);
});

test('questLog is total on junk records', () => {
  assert.doesNotThrow(() => questLog(null));
  assert.doesNotThrow(() => questLog([null, 42, {}]));
});

test('mintRune preserves the exact ledger seq it was minted at', () => {
  const rune = mintRune({ node: pubHex(S1), at: 't', seq: 7, why: 'w', packet: hex(packet({ counter: 1n, op: OPS.SET, key: 'k', value: 'v' })) }, signWith(S1));
  assert.equal(rune.seq, 7);
});
