#!/usr/bin/env node
// attack-kit/forge.mjs — build a packet and (optionally) send it.
//
//   node attack-kit/forge.mjs --op set --key name --value hi            sign with a RANDOM key (a forgery)
//   node attack-kit/forge.mjs --from-captured 0 --flip 20                take a captured packet, flip byte 20
//   node attack-kit/forge.mjs --from-captured 0 --truncate 5 --send      …cut 5 bytes off the end and send it
//   node attack-kit/forge.mjs --sender 7 --counter 99 --raw 01ff41       raw payload bytes (any grammar)
//   flags: --send [--url http://127.0.0.1:8787]   --nodomain (sign without the domain prefix)   --extend N   --zero-sig
import { rawPacket, signRaw, randomKey, post, captured, toHex, fromHex, OPS, message } from './lib.mjs';

const has = (k) => process.argv.includes(k);
const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const url = arg('--url', 'http://127.0.0.1:8787');

let packet;
if (arg('--from-captured') !== undefined) {
  const c = captured(arg('--captured', 'data/captured.hex'));
  const i = Number(arg('--from-captured'));
  if (!c[i]) { console.error('no captured packet #' + i + ' — run `node run.mjs` first'); process.exit(1); }
  packet = c[i].slice();
} else {
  const op = { set: OPS.SET, del: OPS.DEL, add: OPS.ADD }[arg('--op', 'set')];
  const m = { sender: Number(arg('--sender', '1')), counter: BigInt(arg('--counter', '1')), op, key: arg('--key', 'name'), value: arg('--value', 'forged'), delta: Number(arg('--delta', '1')) };
  const unsigned = arg('--raw') !== undefined ? rawPacket({ sender: m.sender, counter: m.counter, payload: fromHex(arg('--raw')) }) : message(m);
  if (!unsigned) { console.error('those fields are out of the grammar — use --raw to send them anyway'); process.exit(1); }
  packet = signRaw(unsigned, randomKey(), { domain: has('--nodomain') ? '' : undefined });
}
if (arg('--flip') !== undefined) { const i = Number(arg('--flip')); packet[i] ^= Number(arg('--mask', '1')); }
if (arg('--truncate') !== undefined) packet = packet.slice(0, packet.length - Number(arg('--truncate')));
if (arg('--extend') !== undefined) packet = Uint8Array.from([...packet, ...new Uint8Array(Number(arg('--extend')))]);
if (has('--zero-sig')) packet.fill(0, packet.length - 64);

console.log(toHex(packet));
if (has('--send')) console.log(JSON.stringify(await post(url, packet)));
