// node/breakit-node.test.mjs — break-it as a cell of the foundation: the screen skill, on break-it's own gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { breakitNode, screen, NAME } from '../node/breakit-node.mjs';
import { makeIdentity, hex } from '../vendor/fall-kit-core/identity.mjs';
import { createNode, receiptHolds, readCard } from '../vendor/fall-kit-core/node.mjs';
import { encodeUnsigned, withSignature, rawCheck, signedBytes, OPS } from '../src/wire.mjs';

const pins = JSON.parse(readFileSync(new URL('../config/pubkeys.json', import.meta.url), 'utf8'));
const seed = (n) => new Uint8Array(32).fill(n);
const rec = (sender) => encodeUnsigned({ sender, counter: 1n, op: OPS.REC, account: 1000, period: 63, amount: 100 });

test('the vendored foundation is exactly what its pin names', () => {
  const pin = JSON.parse(readFileSync(new URL('../vendor/fall-kit-core/FALL-KIT-CORE.json', import.meta.url), 'utf8'));
  assert.match(pin.commit, /^[0-9a-f]{40}$/);
  for (const [f, sha] of Object.entries(pin.files)) assert.equal(createHash('sha256').update(readFileSync(new URL('../vendor/fall-kit-core/' + f, import.meta.url))).digest('hex'), sha, f);
});

test('screen: break-it’s own gate decides, at the stage it names', async () => {
  assert.equal((await screen(pins, Uint8Array.of(0xde, 0xad))).stage, 'size');
  const zero = withSignature(rec(1), new Uint8Array(64));
  assert.equal((await screen(pins, zero)).stage, 'signature');
  assert.equal((await screen(pins, withSignature(rec(9), new Uint8Array(64)))).stage, 'sender');
  const stranger = await makeIdentity(seed(30));
  const forged = withSignature(rec(1), await stranger.sign(signedBytes(zero, rawCheck(zero).n)));
  assert.equal((await screen(pins, forged)).stage, 'signature');
  // a packet signed by a key break-it pins, at any counter (the screen is stateless): admitted
  const own = await makeIdentity(seed(31));
  const myPins = { 5: own.id };
  const u = encodeUnsigned({ sender: 5, counter: 42n, op: OPS.REC, account: 7, period: 1, amount: 9 });
  const tmp = withSignature(u, new Uint8Array(64));
  const good = withSignature(u, await own.sign(signedBytes(tmp, rawCheck(tmp).n)));
  assert.equal((await screen(myPins, good)).admit, true);
  assert.equal((await screen({}, good)).stage, 'sender', 'no pins, no sender');
});

test('as a node: one skill, a receipt that re-hashes, an abstain for junk', async () => {
  const { node, keyset } = await breakitNode({ identity: await makeIdentity(seed(21)), pins });
  assert.equal(node.name, NAME);
  assert.deepEqual(node.card().skills, ['screen']);
  assert.equal((await readCard(node.card())).ok, true);
  assert.match(keyset, /^[0-9a-f]{64}$/);
  const asker = await createNode({ name: 'asker', identity: await makeIdentity(seed(22)) });
  await asker.pin(node.card()); await node.pin(asker.card());
  const ask = async (input) => { const a = await asker.ask('screen', input); return asker.hear((await node.hear(a.bytes)).replies[0].bytes); };
  const r = await ask({ hex: hex(withSignature(rec(9), new Uint8Array(64))) });
  assert.equal(r.outcome, 'verified');
  assert.equal(r.answer.stage, 'sender');
  assert.equal(r.answer.admit, false);
  assert.equal(receiptHolds(r.answer), true);
  assert.equal(r.answer.receipt.stateless, true);
  assert.equal(r.answer.receipt.keyset, keyset);
  for (const junk of [{}, { hex: 'xyz' }, { hex: 'abc' }, { hex: 'aa'.repeat(4097) }]) assert.equal((await ask(junk)).outcome, 'abstain', JSON.stringify(junk).slice(0, 30));
  assert.equal((await ask({ hex: 'aa'.repeat(4096) })).outcome, 'verified', 'the largest screen it takes');
  await assert.rejects(breakitNode({ pins }), /identity/, 'a node needs an identity');
  const bare = await breakitNode({ identity: await makeIdentity(seed(25)) });
  assert.equal(bare.node.card().skills[0], 'screen', 'with no pins it still screens (and refuses every sender)');
});
