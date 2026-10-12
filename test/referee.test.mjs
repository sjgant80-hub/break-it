import { test } from 'node:test';
import assert from 'node:assert/strict';
import { grammarOk, makeReferee } from '../src/referee.mjs';
import { decide } from '../src/gate.mjs';
import { makeApp } from '../src/app.mjs';
import { parse, OPS } from '../src/wire.mjs';
import { packet, ctxFor } from './helpers.mjs';

const admit = (pkt, last) => { const r = decide(pkt, ctxFor({ last })); assert.equal(r.admit, true, 'test needs an admitted packet'); return r.msg; };

test('grammarOk accepts a real, well-formed packet', () => {
  assert.equal(grammarOk(packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'alice' })), true);
  assert.equal(grammarOk(packet({ counter: 2n, op: OPS.DEL, key: 'k' })), true);
  assert.equal(grammarOk(packet({ counter: 3n, op: OPS.ADD, key: 'bal', delta: -5 })), true);
});

test('grammarOk — the SECOND, independent validator — also rejects schema escapes', () => {
  assert.equal(grammarOk(new Uint8Array(83)), false);                 // not a BRK1 frame
  assert.equal(grammarOk('nope'), false);
  // a counter of zero is rejected by the independent grammar too
  const z = packet({ counter: 1n }); z.set([0, 0, 0, 0, 0, 0, 0, 0], 6);
  assert.equal(grammarOk(z), false);
});

test('after(): a message the gate never admitted is a breach', () => {
  const ref = makeReferee();
  const plain = { sender: 1, counter: 1n, op: OPS.SET, key: 'name', value: 'mallory' };
  const b = ref.after(plain, packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'mallory' }));
  assert.ok(b);
  assert.match(b.why, /never admitted/);
  assert.equal(ref.breaches.length, 1);
});

test('after(): an admitted message that matches its packet is clean', () => {
  const ref = makeReferee();
  const pkt = packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'alice' });
  const msg = admit(pkt, 0n);
  assert.equal(ref.after(msg, pkt), null);
  assert.equal(ref.checked, 1);
  assert.equal(ref.breaches.length, 0);
});

test('after(): an admitted message whose packet is a DIFFERENT entry is a breach', () => {
  const ref = makeReferee();
  const pktA = packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'alice' });
  const msgA = admit(pktA, 0n);
  const pktB = packet({ counter: 2n, op: OPS.SET, key: 'name', value: 'bob' });
  const b = ref.after(msgA, pktB);                                    // right (admitted) msg, wrong ledger packet
  assert.ok(b);
  assert.match(b.why, /other than the ledger entry/);
});

test('fold(): the app state must equal a fresh replay of the ledger', () => {
  const ref = makeReferee();
  const app = makeApp();
  const packets = [
    packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'alice' }),
    packet({ counter: 2n, op: OPS.ADD, key: 'bal', delta: 10 }),
  ];
  for (const p of packets) app.apply(parse(p));
  assert.equal(ref.fold(app, packets), true);
  // corrupt the app and the fold must fail
  app.apply({ op: OPS.SET, key: 'name', value: 'tampered' });
  assert.equal(ref.fold(app, packets), false);
});

test('grammarOk is total on junk', () => {
  for (const x of [null, undefined, 42, {}, new Uint8Array(0)]) assert.doesNotThrow(() => grammarOk(x));
});

// ── boundaries: the independent grammar validator, by field edge ─────────────────────────────────────────────
const Hx = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));
const frame = (body, { sender = '01', counter = '0000000000000001' } = {}) => {
  const nHex = (body.length / 2).toString(16).padStart(4, '0');
  return Hx('42524b3101' + sender + counter + nHex + body + '0'.repeat(128));
};
const setBody = (keyHex, valHex) => '01' + (keyHex.length / 2).toString(16).padStart(2, '0') + keyHex + (valHex.length / 2).toString(16).padStart(2, '0') + valHex;
const addBody = (keyHex, deltaHex) => '03' + (keyHex.length / 2).toString(16).padStart(2, '0') + keyHex + deltaHex;

test('grammarOk rejects a zero counter', () => {
  assert.equal(grammarOk(frame(setBody('61', '62'), { counter: '0000000000000000' })), false);
  assert.equal(grammarOk(frame(setBody('61', '62'), { counter: '0000000000000001' })), true);
});

test('grammarOk: payload length n must be ≥ 3 — a 3-byte DEL is the accepted edge', () => {
  assert.equal(grammarOk(frame('020161')), true);      // DEL, key 'a', n = 3
  assert.equal(grammarOk(frame('0101')), false);       // n = 2
});

test('grammarOk: a SET value of exactly 200 bytes passes, 201 fails', () => {
  assert.equal(grammarOk(frame(setBody('61', '62'.repeat(200)))), true);
  assert.equal(grammarOk(frame(setBody('61', '62'.repeat(201)))), false);
});

test('grammarOk: an ADD delta of exactly ±1,000,000 passes, beyond fails, and must be 4 bytes', () => {
  assert.equal(grammarOk(frame(addBody('61', '000f4240'))), true);    // +1,000,000
  assert.equal(grammarOk(frame(addBody('61', 'fff0bdc0'))), true);    // -1,000,000
  assert.equal(grammarOk(frame(addBody('61', '000f4241'))), false);   // +1,000,001
  assert.equal(grammarOk(frame(addBody('61', '0000ff'))), false);     // 3-byte delta
});

test('grammarOk: a value byte outside 0x20..0x7e fails the PRINTS check', () => {
  assert.equal(grammarOk(frame(setBody('61', '7f'))), false);         // 0x7f
  assert.equal(grammarOk(frame(setBody('61', '20'))), true);          // 0x20 (space)
  assert.equal(grammarOk(frame(setBody('61', '7e'))), true);          // 0x7e (~)
});

test('grammarOk: a key with an uppercase/punctuation byte fails KEY', () => {
  assert.equal(grammarOk(frame(setBody('41', '62'))), false);         // 'A'
  assert.equal(grammarOk(frame(setBody('2f', '62'))), false);         // '/'
});

test('fold(): a matching replay pushes NO breach (not just returns true)', () => {
  const ref = makeReferee();
  const app = makeApp();
  const packets = [packet({ counter: 1n, op: OPS.SET, key: 'name', value: 'alice' })];
  app.apply(parse(packets[0]));
  assert.equal(ref.fold(app, packets), true);
  assert.equal(ref.breaches.length, 0);               // the a!==b branch must NOT fire on a match
});

test('after(): a breach records the offending packet as hex (not an empty string)', () => {
  const ref = makeReferee();
  const plain = { sender: 1, counter: 1n, op: OPS.SET, key: 'k', value: 'v' };
  const pkt = packet({ counter: 1n, op: OPS.SET, key: 'k', value: 'v' });
  ref.after(plain, pkt);
  assert.equal(ref.breaches[0].packet, Buffer.from(pkt).toString('hex'));
});

test('same(): a breach fires when the admitted msg differs from its packet in ANY ONE field', () => {
  const base = { counter: 1n, op: OPS.SET, key: 'name', value: 'alice' };
  const msg = admit(packet(base), 0n);
  const differ = [
    packet({ ...base, value: 'bob' }),            // value
    packet({ ...base, key: 'other' }),            // key
    packet({ ...base, counter: 2n }),             // counter
    packet({ ...base, op: OPS.DEL }),             // op (DEL drops value)
  ];
  for (const p of differ) {
    const ref = makeReferee();
    assert.ok(ref.after(msg, p), 'a packet differing from the admitted msg must breach: ' + Buffer.from(p).toString('hex').slice(0, 20));
  }
  // and an ADD whose delta differs
  const addMsg = admit(packet({ counter: 1n, op: OPS.ADD, key: 'bal', delta: 5 }), 0n);
  const ref = makeReferee();
  assert.ok(ref.after(addMsg, packet({ counter: 1n, op: OPS.ADD, key: 'bal', delta: 6 })));
});

test('grammarOk rejects an unknown op and fails closed on input it cannot read', () => {
  assert.equal(grammarOk(frame('090161')), false);     // op 0x09
  assert.equal(grammarOk(null), false);                // the catch must return false, never true
});

test('grammarOk accepts an empty-value SET (the rest.length >= 2 edge)', () => {
  assert.equal(grammarOk(frame(setBody('61', ''))), true);
});

test('grammarOk rejects a frame whose declared n does not match the body it carries', () => {
  const b = Hx('42524b3101' + '01' + '0000000000000001' + '0006' + '0101610162' + '0'.repeat(128)); // n=6, body 5 bytes
  assert.equal(grammarOk(b), false);
});
