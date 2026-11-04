// the mutation gate is pinned: .witness/ holds witness v0.6 byte for byte, and witness-all.mjs runs that engine.
// CI also clones the tag and compares the files (gate.yml), so a local edit to the engine cannot pass as v0.6.
// And no kernel slips out of the gate unnoticed: every file in src/ is gated, or named with its reason.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const read = (p) => readFileSync(new URL('../' + p, import.meta.url));
const sha = (b) => createHash('sha256').update(b).digest('hex');
const ALL = read('witness-all.mjs').toString();

test('the vendored engine is witness v0.6, file for file', () => {
  const pin = JSON.parse(read('.witness/SOURCE.json'));
  assert.equal(pin.tag, 'v0.6');
  assert.match(pin.commit, /^[0-9a-f]{40}$/);
  assert.deepEqual(Object.keys(pin.files).sort(), ['runner.mjs', 'witness.mjs']);
  for (const [f, want] of Object.entries(pin.files)) assert.equal(sha(read('.witness/' + f)), want, '.witness/' + f + ' is the pinned file');
});

test('witness-all.mjs runs the pinned engine, and nothing else', () => {
  const local = [...ALL.matchAll(/from '([^']+)'/g)].map((m) => m[1]).filter((p) => p.startsWith('.'));
  assert.deepEqual(local, ['./.witness/witness.mjs']);
});

test('every file in src/ is gated by witness-all.mjs, or named there with its reason', () => {
  const gated = new Set([...ALL.matchAll(/\['(src\/[a-z]+\.mjs)'/g)].map((m) => m[1]));
  const notGated = ALL.slice(ALL.indexOf('NOT gated here'), ALL.indexOf('Reviewed-equivalent survivors'));
  const files = readdirSync(new URL('../src/', import.meta.url)).filter((f) => f.endsWith('.mjs')).sort();
  assert.ok(files.length >= 20, 'src/ was read');
  for (const f of files) {
    if (gated.has('src/' + f)) continue;
    assert.ok(new RegExp('\\b' + f.replace('.', '\\.') + '\\b').test(notGated), 'src/' + f + ' is gated, or its reason is written under "NOT gated here"');
  }
});
