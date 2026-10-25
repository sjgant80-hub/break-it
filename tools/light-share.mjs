#!/usr/bin/env node
// tools/light-share.mjs — the mesh speaking LIGHT, measured (konomi-tongue light/claims.json K1–K3).
//   K1  three real nodes pinned to each other; a packet signed by a key that is not pinned is refused by node 0 and
//       becomes an exact antibody; node 0 tells its peers in one signed LIGHT packet; the same bytes sent to nodes 1
//       and 2 — which never saw them — are dropped on sight
//   K2  a LIGHT share signed by a key that is not pinned, and node 0's genuine share with one byte changed in transit,
//       are each refused at the LIGHT door; node 1's count of decoded shares does not move
//   K3  the same antigens as one LIGHT packet and as the JSON shares of before: bytes on the wire
// Writes receipts/light-share.json.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { startNode } from '../src/server.mjs';
import { rawPublic, signWith } from '../src/keys.mjs';
import { makeClient } from '../src/client.mjs';
import { OPS } from '../src/wire.mjs';
import { meshOrder, antigensToBytes, nextCounter } from '../src/share.mjs';
import { prepare, finish, KINDS } from '../vendor/light/packet.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const hex = (u8) => Buffer.from(u8).toString('hex');
const key = () => generateKeyPairSync('ed25519').privateKey;
const sender = key(), stranger = key(), nodeKeys = [key(), key(), key()];
const pubkeys = { 1: hex(rawPublic(sender)) };
const dir = mkdtempSync(join(tmpdir(), 'light-share-'));
const post = async (url, bytes, type = 'application/octet-stream') => { const r = await fetch(url, { method: 'POST', headers: { 'content-type': type }, body: bytes }); let b = null; try { b = await r.json(); } catch { b = null; } return { status: r.status, body: b }; };
const immune = async (n) => (await fetch(n.url + '/immune')).json();

// a mesh: start on free ports, learn them, restart pinned to each other (as the red-team battery does)
const opts = (i, port, peers) => ({ port, ledgerPath: join(dir, 'n' + i, 'ledger.jsonl'), journalPath: join(dir, 'n' + i, 'journal.jsonl'), pubkeys, nodeKey: nodeKeys[i], peers });
let nodes = [];
for (let i = 0; i < 3; i++) nodes.push(await startNode(opts(i, 0, [])));
const urls = nodes.map((n) => n.url);
for (const n of nodes) await n.close();
const keyHex = nodeKeys.map((k) => hex(rawPublic(k)));
nodes = [];
for (let i = 0; i < 3; i++) nodes.push(await startNode(opts(i, Number(new URL(urls[i]).port), [0, 1, 2].filter((j) => j !== i).map((j) => ({ url: urls[j], key: keyHex[j] })))));

const facts = {};
try {
  // K1 — one packet signed by a key that is not pinned, shown only to node 0
  const forged = makeClient({ privateKey: stranger, sender: 1 }).next({ op: OPS.SET, key: 'name', value: 'x' });
  const first = await post(nodes[0].url + '/packet', forged);
  await new Promise((r) => setTimeout(r, 900));                  // one share interval, and then some
  const on1 = await post(nodes[1].url + '/packet', forged), on2 = await post(nodes[2].url + '/packet', forged);
  const s0 = await immune(nodes[0]), s1 = await immune(nodes[1]), s2 = await immune(nodes[2]);
  facts.k1 = { node0: first.body && first.body.stage, node1: on1.body && on1.body.stage, node2: on2.body && on2.body.stage,
    sentLight: s0.stats.light.sent, admittedLight: [s1.stats.light.admitted, s2.stats.light.admitted], adopted: [s1.stats.adoptedFromPeers, s2.stats.adoptedFromPeers] };

  // K2 — the door: a share signed by a key that is not pinned, and a genuine share changed in transit
  const order = meshOrder(keyHex), from0 = order.indexOf(keyHex[0]);
  const shareOf = (signer, counter, list) => { const p = prepare({ sender: from0, counter, kind: KINDS.BYTES, bytes: antigensToBytes(list), dictId: 0 }); return finish(p.unsigned, new Uint8Array(edSign(null, Buffer.from(p.signed), signer))).bytes; };
  const decodedBefore = (await immune(nodes[1])).stats.light.decoded;
  const bad = await post(nodes[1].url + '/immune/share', shareOf(stranger, nextCounter(0n, Date.now()) + 1000n, [forged]), 'application/x-light');
  const genuine = shareOf(nodeKeys[0], nextCounter(0n, Date.now()) + 2000n, [forged]);
  const changed = genuine.slice(); changed[30] ^= 1;
  const tampered = await post(nodes[1].url + '/immune/share', changed, 'application/x-light');
  const after = await immune(nodes[1]);
  facts.k2 = { unpinned: { status: bad.status, stage: bad.body && bad.body.stage }, tampered: { status: tampered.status, stage: tampered.body && tampered.body.stage },
    decodedBefore, decodedAfter: after.stats.light.decoded, refused: after.stats.light.refused };
  const ok = await post(nodes[1].url + '/immune/share', genuine, 'application/x-light');
  facts.k2.genuineAfter = { status: ok.status, adopted: ok.body && ok.body.adopted, decodedAfter: (await immune(nodes[1])).stats.light.decoded };

  // K3 — the same antigens both ways: one antigen (as K1 shared it) and a full batch of 64
  const sizes = (list) => {
    const antigens = list.map(hex), from = keyHex[0];
    const json = JSON.stringify({ v: 1, from, antigens, sig: hex(signWith(nodeKeys[0])(Buffer.from('BREAK-IT/share/v1|' + from + '|' + JSON.stringify(antigens)))) });
    const light = shareOf(nodeKeys[0], 1n, list);
    return { antigens: list.length, json: Buffer.byteLength(json), light: light.length, ratio: Math.round((Buffer.byteLength(json) / light.length) * 1000) / 1000 };
  };
  const c = makeClient({ privateKey: stranger, sender: 1 });
  const batch = Array.from({ length: 64 }, (_, i) => c.next({ op: OPS.SET, key: 'k' + (i % 6), value: 'v' + i }));
  facts.k3 = { one: sizes([forged]), batch: sizes(batch) };
} finally {
  for (const n of nodes) await n.close();
  rmSync(dir, { recursive: true, force: true });
}
const receipt = { kind: 'break-it.light-share', v: 1, ran: new Date().toISOString(), node: process.version, facts };
writeFileSync(join(ROOT, 'receipts', 'light-share.json'), JSON.stringify(receipt, null, 1) + '\n');
console.log(JSON.stringify(facts, null, 1));
