import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { meshOrder, antigensToBytes, bytesToAntigens, nextCounter, MAX_ANTIGENS, MIN_ANTIGEN, MAX_ANTIGEN } from '../src/share.mjs';

const K = (c) => c.repeat(64);
const pkt = (n, seed) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 255);

test('constants', () => { assert.deepEqual([MAX_ANTIGENS, MIN_ANTIGEN, MAX_ANTIGEN], [64, 1, 336]); });

test('meshOrder: unique, sorted, and refused when any key is junk or there are too many', () => {
  assert.deepEqual(meshOrder([K('c'), K('a'), K('b'), K('a')]), [K('a'), K('b'), K('c')]);
  assert.deepEqual(meshOrder([]), []);
  for (const junk of [null, 'x', [K('a'), 'nope'], [K('A')], [K('a').slice(1)], [5]]) assert.equal(meshOrder(junk), null, JSON.stringify(junk));
  const many = Array.from({ length: 257 }, (_, i) => i.toString(16).padStart(64, '0'));
  assert.equal(meshOrder(many), null);
  assert.equal(meshOrder(many.slice(0, 256)).length, 256);
});

test('antigens ⇄ bytes: exact, with the edges of every bound', () => {
  const list = [pkt(1, 1), pkt(127, 2), pkt(128, 3), pkt(336, 4)];
  const b = antigensToBytes(list);
  assert.deepEqual([...b.slice(0, 3)], [4, 1, 1]);
  assert.equal(b.length, 1 + (1 + 1) + (1 + 127) + (2 + 128) + (2 + 336));
  const back = bytesToAntigens(b);
  assert.equal(back.ok, true);
  assert.deepEqual(back.list.map((x) => [...x]), list.map((x) => [...x]));
  const full = Array.from({ length: 64 }, (_, i) => pkt(91, i));
  assert.equal(bytesToAntigens(antigensToBytes(full)).list.length, 64);
  for (const bad of [null, [], Array.from({ length: 65 }, () => pkt(5, 0)), [new Uint8Array(0)], [pkt(337, 0)], ['x'], [pkt(5, 0), null]]) assert.equal(antigensToBytes(bad), null);
});

test('bytesToAntigens refuses every malformed body, with a reason', () => {
  assert.deepEqual(bytesToAntigens('x'), { ok: false, why: 'not bytes' });
  assert.deepEqual(bytesToAntigens(new Uint8Array(0)), { ok: false, why: 'a share carries 1–64 antigens' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(0)), { ok: false, why: 'a share carries 1–64 antigens' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(65)), { ok: false, why: 'a share carries 1–64 antigens' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(0x80, 0x80, 0x80, 1)), { ok: false, why: 'a share carries 1–64 antigens' });
  assert.equal(bytesToAntigens(antigensToBytes([pkt(5, 0), pkt(5, 1)]), 1).why, 'a share carries 1–1 antigens');
  assert.equal(bytesToAntigens(antigensToBytes([pkt(5, 0)]), 0).ok, true, 'a junk cap falls back to 64');
  assert.equal(bytesToAntigens(antigensToBytes([pkt(5, 0)]), 99).ok, true);
  assert.deepEqual(bytesToAntigens(Uint8Array.of(1, 0)), { ok: false, why: 'antigen 0 is not 1–336 bytes' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(1, 0xd1, 0x02)), { ok: false, why: 'antigen 0 is not 1–336 bytes' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(1)), { ok: false, why: 'antigen 0 is not 1–336 bytes' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(1, 3, 9, 9)), { ok: false, why: 'antigen 0 runs past the body' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(1, 2, 9, 9, 7)), { ok: false, why: 'bytes after the last antigen' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(2, 1, 9)), { ok: false, why: 'antigen 1 is not 1–336 bytes' });
  assert.deepEqual(bytesToAntigens(Uint8Array.of(1, 0xd0, 0x02, ...pkt(336, 0))).ok, true);
});

test('nextCounter: after the last, never behind the clock, junk is zero', () => {
  assert.equal(nextCounter(0n, 1000), 1000n);
  assert.equal(nextCounter(5000n, 1000), 5001n);
  assert.equal(nextCounter(999n, 1000), 1000n);
  assert.equal(nextCounter(1000n, 1000), 1001n);
  assert.equal(nextCounter(undefined, 0), 1n);
  assert.equal(nextCounter(-5n, 1.5), 1n);
  assert.equal(nextCounter(7n, 'x'), 8n);
  assert.equal(nextCounter(7, 3), 3n);
});

test('the vendored LIGHT is the estate\'s one codec, byte for byte as SOURCE.json pins it', () => {
  const src = JSON.parse(readFileSync(new URL('../vendor/light/SOURCE.json', import.meta.url), 'utf8'));
  assert.equal(src.repo, 'sjgant80-hub/konomi-tongue');
  assert.match(src.commit, /^[0-9a-f]{40}$/);
  for (const [f, sha] of Object.entries(src.files)) {
    assert.equal(createHash('sha256').update(readFileSync(new URL('../vendor/light/' + f, import.meta.url))).digest('hex'), sha, f);
  }
  assert.deepEqual(Object.keys(src.files).sort(), ['codec.mjs', 'packet.mjs', 'sha256.mjs']);
});
