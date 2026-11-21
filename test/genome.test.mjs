// genome.test.mjs — BREAK IT as a cell of the estate genome: its judge (the gate itself), its lane and its health.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { judge, inLane, health, stage } from '../genome/cell.mjs';
import { packet, hex, pubHex, S1, S2 } from './helpers.mjs';

const seed = JSON.parse(readFileSync(new URL('../seed.json', import.meta.url), 'utf8'));
const PIN = { 1: pubHex(S1) };
const GENUINE = hex(packet());                          // sender 1, counter 1, SET name = alice, signed by S1
const on = (p, over = {}) => ({ packet: p, pinned: PIN, last: { 1: '0' }, ...over });

test('the seed is built from the repository\'s own test keys, and its cases are judged right', async () => {
  assert.equal(seed.boundary.inLane.packet, GENUINE, 'the in-lane packet is helpers.packet() as it stands');
  assert.deepEqual(seed.judge.cases.good.pinned, PIN);
  assert.equal(seed.judge.cases.good.packet.length, GENUINE.length);
  assert.notEqual(seed.judge.cases.good.packet, GENUINE, 'the forged packet differs from the genuine one');
  assert.equal(await judge(seed.judge.cases.good), 'verified');
  assert.equal(await judge(seed.judge.cases.bad), 'unverified');
});

test('the judge reads with the gate, stage by stage', async () => {
  assert.equal(stage(on(GENUINE)), 'admitted');
  assert.equal(await judge({ ...on(GENUINE), claim: 'admitted' }), 'verified');
  assert.equal(await judge({ ...on(GENUINE), claim: 'signature' }), 'unverified');
  assert.equal(await judge({ ...on(GENUINE, { last: { 1: '1' } }), claim: 'counter' }), 'verified', 'a replay is stopped at the counter');
  assert.equal(await judge({ ...on(GENUINE, { last: { 1: 1 } }), claim: 'counter' }), 'verified', 'a counter may be a number');
  assert.equal(await judge({ ...on(hex(packet({ counter: 3n }))), claim: 'counter' }), 'verified', 'out of order is stopped at the counter');
  assert.equal(await judge({ ...on(GENUINE, { pinned: { 1: pubHex(S2) } }), claim: 'signature' }), 'verified', 'the wrong pinned key is stopped at the signature');
  assert.equal(await judge({ ...on(GENUINE, { pinned: { 2: pubHex(S1) } }), claim: 'sender' }), 'verified', 'an unpinned sender is stopped at the sender');
  assert.equal(await judge({ ...on('deadbeef'), claim: 'size' }), 'verified', 'four bytes are stopped at the size');
  assert.equal(await judge({ ...on(GENUINE, { last: undefined }), claim: 'admitted' }), 'verified', 'no counters given means none admitted yet');
});

test('refusals: a claim that is not a stage, or an input that is not a raw packet', async () => {
  for (const x of [
    { ...on(GENUINE), claim: 'ok' }, { ...on(GENUINE), claim: 'ADMITTED' }, on(GENUINE),
    { ...seed.boundary.outOfLane, claim: 'admitted' }, null, 'x', {},
  ]) assert.equal(await judge(x), 'refused', JSON.stringify(x));
});

test('the lane: raw bytes in hex, a pinned key table the kernel accepts, counters as whole numbers', async () => {
  assert.equal(await inLane(seed.boundary.inLane), true);
  assert.equal(await inLane(seed.boundary.outOfLane), false);
  assert.equal(await inLane(on(GENUINE, { last: undefined })), true, 'counters are optional');
  assert.equal(await inLane(on('deadbeef')), true, 'hostile bytes are in lane: refusing them is the gate\'s job');
  assert.equal(await inLane(on(42)), false, 'a number is not bytes, even when it reads as hex');
  assert.equal(await inLane(on('abc')), false, 'an odd number of hex digits is not bytes');
  assert.equal(await inLane(on('DEADBEEF')), false, 'upper-case hex is not the lane');
  assert.equal(await inLane(on('')), false, 'no bytes is not a packet');
  assert.equal(await inLane(on(GENUINE, { pinned: {} })), false, 'an empty key table pins nobody');
  assert.equal(await inLane(on(GENUINE, { pinned: [pubHex(S1)] })), false, 'a key table is an object, not a list');
  assert.equal(await inLane(on(GENUINE, { pinned: { 1: 'zz' } })), false, 'a key keyTable() refuses is out of lane');
  assert.equal(await inLane(on(GENUINE, { pinned: { 300: pubHex(S1) } })), false, 'a sender id past 255 is out of lane');
  assert.equal(await inLane(on(GENUINE, { last: null })), false, 'counters that are null are out of lane');
  assert.equal(await inLane(on(GENUINE, { last: ['0'] })), false, 'counters that are a list are out of lane');
  assert.equal(await inLane(on(GENUINE, { last: { 1: '-1' } })), false, 'a negative counter is out of lane');
  assert.equal(await inLane(on(GENUINE, { last: { 1: 'x' } })), false, 'a counter that is not a number is out of lane');
  assert.equal(await inLane(on(GENUINE, { last: { 1: 1.5 } })), false, 'a fractional counter is out of lane');
  assert.equal(await inLane(null), false);
});

test('health says what it cannot measure from inside the repository', async () => {
  assert.deepEqual(await health(), { used: null, dependedOn: null, lastEarned: null });
});
