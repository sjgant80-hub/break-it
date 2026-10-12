#!/usr/bin/env node
// attack-kit/redteam.mjs — our own swing at every vector in the brief, against real nodes (in-process, fixed keys),
// written to a receipt CI regenerates byte for byte:
//   node attack-kit/redteam.mjs           write receipts/redteam.json
//   node attack-kit/redteam.mjs --check   regenerate and demand it is identical to the committed receipt
// Every case records what was tried and what happened; the battery passes only if the app was never reached by
// anything the gate should refuse (the referee stays clean) and every case lands where it should.
import { mkdtempSync, rmSync, readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sign as edSign, createPrivateKey, createHash } from 'node:crypto';
import { startNode } from '../src/server.mjs';
import { keyFromSeed, rawPublic, keyTable } from '../src/keys.mjs';
import { makeClient } from '../src/client.mjs';
import { decide } from '../src/gate.mjs';
import { GENESIS, entryFor } from '../src/chain.mjs';
import { sha256hex } from '../src/ledger.mjs';
import { OPS, DOMAIN } from '../src/wire.mjs';
import { solve, verifyWork, difficultyFor, BITS, obeys, ratchetHolds, elasticHolds, released } from '../src/rebound.mjs';
import { rawPacket, signRaw, post, rawHttp, toHex, message } from './lib.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'receipts', 'redteam.json');
const hex = (k) => toHex(rawPublic(k));
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function canonicalJson(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalJson(v[k])).join(',') + '}';
}
const stageOf = (r) => (r && r.body ? (r.body.accepted ? 'ACCEPTED' : r.body.stage) : 'no-response:' + r.status);

export async function run() {
  const dir = mkdtempSync(join(tmpdir(), 'break-it-redteam-'));
  const S1 = keyFromSeed(new Uint8Array(32).fill(1)), S2 = keyFromSeed(new Uint8Array(32).fill(2));
  const ATTACKER = keyFromSeed(new Uint8Array(32).fill(0xee));
  const nodeKeys = [21, 22, 23].map((b) => keyFromSeed(new Uint8Array(32).fill(b)));
  const pubkeys = { 1: hex(S1), 2: hex(S2) };
  const cases = [];
  const add = (group, name, tried, outcome, ok) => cases.push({ group, name, tried, outcome, held: ok === true });

  // three nodes, pinned to each other
  const ports = [0, 0, 0];
  const nodes = [];
  for (let i = 0; i < 3; i++) {
    nodes.push(await startNode({ port: 0, ledgerPath: join(dir, 'n' + i, 'ledger.jsonl'), journalPath: join(dir, 'n' + i, 'journal.jsonl'), lootPath: join(dir, 'n' + i, 'loot.jsonl'), pubkeys, nodeKey: nodeKeys[i], peers: [] }));
  }
  // re-open with peers now that the ports are known
  for (const n of nodes) await n.close();
  const urls = nodes.map((n) => n.url);
  const peersFor = (i) => [0, 1, 2].filter((j) => j !== i).map((j) => ({ url: urls[j], key: hex(nodeKeys[j]) }));
  for (let i = 0; i < 3; i++) {
    nodes[i] = await startNode({ port: Number(new URL(urls[i]).port), ledgerPath: join(dir, 'n' + i, 'ledger.jsonl'), journalPath: join(dir, 'n' + i, 'journal.jsonl'), lootPath: join(dir, 'n' + i, 'loot.jsonl'), pubkeys, nodeKey: nodeKeys[i], peers: peersFor(i) });
  }
  const N0 = nodes[0].url;
  const c1 = makeClient({ privateKey: S1, sender: 1 });
  const sendAll = async (p) => { const r = []; for (const n of nodes) r.push(await post(n.url, p)); return r; };

  // a little legitimate history
  const legit = [];
  for (let i = 0; i < 6; i++) { const p = c1.next(i % 2 ? { op: OPS.ADD, key: 'balance', delta: 5 } : { op: OPS.SET, key: 'name', value: 'alice ' + i }); legit.push(p); await sendAll(p); }

  // ── FORGE ─────────────────────────────────────────────────────────────────────────────────────────────────
  const forged = signRaw(message({ sender: 1, counter: 7n, op: OPS.SET, key: 'name', value: 'mallory' }), ATTACKER);
  const f1 = stageOf(await post(N0, forged)), f2 = stageOf(await post(N0, forged));
  add('forge', 'signed with a key that is not pinned', 'a perfect packet for sender 1, counter 7, signed by an attacker key — sent twice', f1 + ', then ' + f2, f1 === 'signature' && f2 === 'recognised');
  const unknownSender = signRaw(message({ sender: 9, counter: 1n, op: OPS.SET, key: 'name', value: 'x' }), ATTACKER);
  const us = stageOf(await post(N0, unknownSender));
  add('forge', 'a sender with no pinned key', 'sender 9', us, us === 'sender');
  const noDomain = signRaw(message({ sender: 1, counter: 7n, op: OPS.SET, key: 'name', value: 'x' }), S1, { domain: '' });
  const nd = stageOf(await post(N0, noDomain));
  add('forge', 'the legitimate key, but signed without the domain prefix (cross-protocol)', 'S1 signs header‖payload with no domain', nd, nd === 'signature');
  const v2 = signRaw(rawPacket({ sender: 1, counter: 7n, payload: [1, 1, 0x61, 1, 0x61], version: 2 }), S1);
  const v2s = stageOf(await post(N0, v2));
  add('forge', 'algorithm / version confusion', 'version byte 2, signed by the legitimate key', v2s, v2s === 'magic');
  const twice = [signRaw(message({ sender: 1, counter: 7n, op: OPS.SET, key: 'a', value: 'b' }), S1), signRaw(message({ sender: 1, counter: 7n, op: OPS.SET, key: 'a', value: 'b' }), S1)];
  add('signature', 'nonce reuse', 'sign the same message twice — Ed25519 has no per-signature nonce to reuse', toHex(twice[0]) === toHex(twice[1]) ? 'identical signatures (deterministic)' : 'signatures differ', toHex(twice[0]) === toHex(twice[1]));
  // every single-bit flip of a valid, never-sent packet — straight through the gate (exhaustive, in-process)
  const fresh = c1.next({ op: OPS.SET, key: 'status', value: 'fresh' });
  const t = keyTable(pubkeys);
  const ctxAt = (last) => ({ keyFor: t.keyFor, verify: t.verify, lastCounter: (s) => (s === 1 ? last : 0n) });
  let flipsAdmitted = 0, flips = 0;
  for (let i = 0; i < fresh.length; i++) for (let bit = 0; bit < 8; bit++) {
    const m = fresh.slice(); m[i] ^= 1 << bit; flips++;
    if (decide(m, ctxAt(6n)).admit) flipsAdmitted++;
  }
  add('forge', 'every single-bit flip of a valid packet', flips + ' mutants through the gate', flipsAdmitted + ' admitted', flipsAdmitted === 0);
  // malleability: s + L (a non-canonical signature for the same message)
  const s = fresh.slice(fresh.length - 32); let sN = 0n; for (let i = 31; i >= 0; i--) sN = (sN << 8n) | BigInt(s[i]);
  const s2 = sN + L; const mall = fresh.slice();
  for (let i = 0; i < 32; i++) mall[mall.length - 32 + i] = Number((s2 >> BigInt(8 * i)) & 255n);
  add('signature', 'malleated signature (s + L)', 'the same message with a non-canonical s', decide(mall, ctxAt(6n)).stage, !decide(mall, ctxAt(6n)).admit);
  const zs = decide(Uint8Array.from([...fresh.slice(0, fresh.length - 64), ...new Uint8Array(64)]), ctxAt(6n)).stage;
  add('signature', 'all-zero signature', 'a valid header and payload, signature zeroed', zs, zs === 'signature');
  const ts = decide(fresh.slice(0, -1), ctxAt(6n)).stage;
  add('signature', 'truncated signature', 'last byte of the signature removed', ts, ts === 'size');
  const ext = (() => { const b = Array.from(fresh); b.splice(b.length - 64, 0, 0x41, 0x41); b[15] += 2; return decide(Uint8Array.from(b), ctxAt(6n)).stage; })();
  add('signature', 'length extension', 'bytes appended to the payload, length field raised to match, old signature kept', ext, ext === 'schema');
  const ext2 = (() => { const b = Array.from(fresh); b.splice(b.length - 64 + 2, 0, 0x41, 0x41); return decide(Uint8Array.from(b), ctxAt(6n)).stage; })();
  add('signature', 'bytes smuggled after the payload', 'two bytes inside the signature region, length field unchanged', ext2, ext2 === 'size');

  // ── REPLAY ────────────────────────────────────────────────────────────────────────────────────────────────
  const sp = stageOf(await post(N0, legit[0]));
  add('replay', 'a spent packet, sent again', 'the first legitimate packet', sp, sp === 'counter');
  const sp2 = stageOf(await post(N0, legit[0]));
  add('replay', '…and again', 'the same spent packet a second time', sp2, sp2 === 'recognised');
  const race = await Promise.all(Array.from({ length: 50 }, () => post(N0, fresh)));
  add('replay', 'the replay race: one fresh packet sent 50 times at once', '50 concurrent POSTs', race.filter((r) => r.body && r.body.accepted).length + ' accepted', race.filter((r) => r.body && r.body.accepted).length === 1);
  for (const n of nodes.slice(1)) await post(n.url, fresh);
  const skip = c1.next({ op: OPS.ADD, key: 'balance', delta: 1 }); const next = c1.next({ op: OPS.ADD, key: 'balance', delta: 1 });
  const ooo = stageOf(await post(N0, next));
  add('replay', 'out of order: counter +2 before +1', 'a legitimate packet that skips ahead', ooo, ooo === 'counter');
  const okSkip = stageOf(await post(N0, skip)), okNext = stageOf(await post(N0, next));
  add('replay', '…then the gap filled', '+1 then +2 again', okSkip + ' then ' + okNext, okSkip === 'ACCEPTED' && okNext === 'ACCEPTED');
  for (const n of nodes.slice(1)) { await post(n.url, skip); await post(n.url, next); }
  const cz = decide(signRaw(rawPacket({ sender: 1, counter: 0n, payload: [1, 1, 0x61, 1, 0x61] }), S1), ctxAt(0n)).stage;
  add('replay', 'counter zero', 'counter 0, signed by the legitimate key', cz, cz === 'counter');
  const top = (1n << 64n) - 1n;
  const cr = decide(signRaw(rawPacket({ sender: 1, counter: top, payload: [1, 1, 0x61, 1, 0x61] }), S1), ctxAt(9n)).stage;
  add('replay', 'counter rollover', 'counter 2^64−1, legitimately signed, out of sequence', cr, cr === 'counter');
  const wrap = decide(signRaw(rawPacket({ sender: 1, counter: 0n, payload: [1, 1, 0x61, 1, 0x61] }), S1), ctxAt(top)).stage;
  add('replay', 'counter wrap-around', 'after counter 2^64−1, try counter 0', wrap, wrap === 'counter');

  // ── SCHEMA ESCAPE (even the legitimate key cannot push these through) ──────────────────────────────────────
  const legitRaw = (payload, extra = {}) => signRaw(rawPacket({ sender: 1, counter: 10n, payload, ...extra }), S1);
  const str = (s) => Array.from(s, (c) => c.charCodeAt(0));
  const escapes = [
    ['key __proto__', [1, 9, ...str('__proto__'), 1, 0x78]],
    ['key with an upper-case letter', [1, 4, ...str('Name'), 1, 0x78]],
    ['key of 33 bytes', [1, 33, ...str('a'.repeat(33)), 1, 0x78]],
    ['empty key', [1, 0, 1, 0x78]],
    ['value with a control byte', [1, 1, 0x61, 2, 0x41, 0x7f]],
    ['value with a NUL', [1, 1, 0x61, 2, 0x41, 0x00]],
    ['value length that lies', [1, 1, 0x61, 9, 0x41]],
    ['an unknown op', [4, 1, 0x61]],
    ['a delta over the limit', [3, 1, 0x61, 0x00, 0x0f, 0x42, 0x41]],
    ['trailing bytes after a DEL', [2, 1, 0x61, 0x00]],
    ['a non-ASCII key byte', [1, 2, 0x61, 0xc3, 1, 0x78]],
  ];
  for (const [name, payload] of escapes) { const st = decide(legitRaw(payload), ctxAt(9n)).stage; add('schema', name, 'signed by the LEGITIMATE key', st, st === 'schema' || st === 'size'); }
  const lie = signRaw(rawPacket({ sender: 1, counter: 10n, payload: [1, 1, 0x61, 1, 0x61], declaredLength: 4 }), S1);
  add('schema', 'a length field that lies', 'payload 5 bytes, header says 4', decide(lie, ctxAt(9n)).stage, !decide(lie, ctxAt(9n)).admit);

  // ── PARSER REACH (ordering, partial reads, encoding) ──────────────────────────────────────────────────────
  const hx = stageOf(await post(N0, new TextEncoder().encode(toHex(legit[1]))));
  add('parser', 'the packet as hex text', 'a real packet, hex-encoded', hx, hx === 'magic');
  const n0 = new URL(N0);
  const chunked = await rawHttp(N0, 'POST /packet HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n');
  add('parser', 'a chunked body', 'Transfer-Encoding: chunked', chunked.split('\r\n')[0], /400/.test(chunked));
  const noLen = await rawHttp(N0, 'POST /packet HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
  add('parser', 'no Content-Length', 'an empty POST', noLen.split('\r\n')[0], /400/.test(noLen));
  const big = await rawHttp(N0, 'POST /packet HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n');
  add('parser', 'a Content-Length over the limit', '100000', big.split('\r\n')[0], /400/.test(big));
  const longer = await rawHttp(N0, 'POST /packet HTTP/1.1\r\nHost: x\r\nContent-Length: 90\r\n\r\n' + 'A'.repeat(200));
  add('parser', 'a body longer than its Content-Length', '90 declared, 200 sent', /accepted":true/.test(longer) ? 'ACCEPTED' : 'not accepted', !/accepted":true/.test(longer));
  const slow = await rawHttp(N0, '', { chunks: ['POST /packet HTTP/1.1\r\nHost: x\r\nContent-Length: 120\r\n\r\n', 'AAAA'], slowMs: 50, closeAfterMs: 4500 });
  add('parser', 'a slow body (send 4 of 120 bytes, then stall)', 'a slowloris on the body', /accepted":true/.test(slow) ? 'ACCEPTED' : 'closed without admitting', !/accepted":true/.test(slow));

  // ── DOS ───────────────────────────────────────────────────────────────────────────────────────────────────
  // 1,000 requests pipelined down one socket — as fast as the node will read them
  const one = 'POST /packet HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n\x01\x02\x03';
  const pipe = await rawHttp(N0, one.repeat(999) + one.replace('Host: x', 'Host: x\r\nConnection: close'), { closeAfterMs: 30000 });
  const limited = (pipe.match(/HTTP\/1\.1 429/g) || []).length > 0 && !/accepted":true/.test(pipe);
  await new Promise((r) => setTimeout(r, 2500));
  const afterFlood = c1.next({ op: OPS.SET, key: 'status', value: 'after flood' });
  const af = stageOf(await post(N0, afterFlood));
  for (const n of nodes.slice(1)) await post(n.url, afterFlood);
  add('dos', 'a flood of 1,000 requests', 'pipelined down one socket from one address', limited ? 'rate-limited (429s), nothing admitted' : 'not limited', limited);
  add('dos', '…and the gate is not locked afterwards', 'a fresh legitimate packet once the bucket refills', af, af === 'ACCEPTED');
  const garbage = await rawHttp(N0, 'GARBAGE\r\n\r\n');
  const health = await (await fetch(N0 + '/health')).json();
  add('dos', 'garbage on the socket', 'a request line that is not HTTP', health.ok ? 'node still up' : 'node down', health.ok === true);

  // ── IMMUNE: the mycelium, and no false immunity ─────────────────────────────────────────────────────────────
  const novel = fresh.slice(); novel[40] ^= 0x10;                  // a forgery no node has seen
  await post(nodes[0].url, novel);
  await new Promise((r) => setTimeout(r, 800));                   // one share interval, and then some
  const on1 = stageOf(await post(nodes[1].url, novel)), on2 = stageOf(await post(nodes[2].url, novel));
  add('immune', 'attack node 0 once — do nodes 1 and 2 already know it?', 'a new forgery sent ONLY to node 0', 'node 1: ' + on1 + ', node 2: ' + on2, on1 === 'recognised' && on2 === 'recognised');
  // autoimmunity: a pinned peer shares a packet that is VALID on the receiver — it must not be adopted
  const validNext = c1.next({ op: OPS.SET, key: 'name', value: 'bob' });
  const body = (antigens, key) => { const from = hex(key); const sig = toHex(edSign(null, Buffer.from('BREAK-IT/share/v1|' + from + '|' + JSON.stringify(antigens)), key)); return JSON.stringify({ v: 1, from, antigens, sig }); };
  const share = async (url, b) => (await fetch(url + '/immune/share', { method: 'POST', headers: { 'content-type': 'application/json' }, body: b })).json();
  const auto = await share(nodes[1].url, body([toHex(validNext)], nodeKeys[0]));
  add('immune', 'a peer shares a packet that is VALID here (an attempt at autoimmunity)', 'node 0 signs, node 1 re-runs', 'adopted ' + auto.adopted, auto.adopted === 0);
  const accepted = stageOf(await post(nodes[1].url, validNext));
  add('immune', '…so the valid packet still goes through', 'send it to node 1', accepted, accepted === 'ACCEPTED');
  for (const i of [0, 2]) await post(nodes[i].url, validNext);
  const stranger = await share(nodes[1].url, body([toHex(novel)], ATTACKER));
  add('immune', 'a share from a node that is not pinned', 'the attacker key signs a share', 'adopted ' + stranger.adopted + ' — ' + stranger.reason, stranger.adopted === 0);
  const honest = JSON.parse(body([toHex(forged)], nodeKeys[0])); honest.antigens = [toHex(validNext)];
  const tampered = await share(nodes[1].url, JSON.stringify(honest));
  add('immune', "a pinned peer's share, antigens swapped in transit", 'node 0 signs one list, the attacker swaps it', 'adopted ' + tampered.adopted + ' — ' + tampered.reason, tampered.adopted === 0);

  // ── SENTINEL: a legitimate key, abused ────────────────────────────────────────────────────────────────────
  const c2 = makeClient({ privateKey: S2, sender: 2 });
  let drainStage = null, drainAt = 0;
  for (let i = 0; i < 60; i++) { const r = stageOf(await post(N0, c2.next({ op: OPS.ADD, key: 'vault', delta: -1000000 }))); if (r !== 'ACCEPTED') { drainStage = r; drainAt = i; break; } }
  add('sentinel', 'a valid key draining the store', '60 × ADD −1,000,000 with a genuine key', drainStage ? drainStage + ' at packet ' + (drainAt + 1) : 'never stopped', drainStage === 'behavior');
  const c2b = makeClient({ privateKey: S2, sender: 2, startCounter: c2.counter - 1n });   // the refused packet's counter was never spent
  const harmless = c2b.next({ op: OPS.SET, key: 'x', value: 'y' });
  const after = stageOf(await post(N0, harmless));
  add('sentinel', '…and that key stays blocked', 'a harmless packet from the same key, at the right counter', after, after === 'behavior');

  // ── THE REBOUND LAW: a distrusted source pays compute; we pay ~nothing; we emit nothing back ─────────────────
  const shaStr = (str) => createHash('sha256').update(str).digest('hex');
  // a well-behaved client, sharing an address with an attacker, simply pays once and gets through
  const paidPost = async (url, pkt) => { let r = await post(url, pkt); if (r.status === 402 && r.body && r.body.challenge) r = await post(url, pkt, { 'x-rebound': solve(r.body.challenge, r.body.bits, shaStr) }); return r; };
  // forge until the gate stops verifying us and starts charging — each forgery is a signature refusal that climbs
  // the ladder, until past BLOCK the node answers 402 instead of doing the verify. The packet that gets charged is
  // the one we then pay for. Robust to however many refusals the earlier sections already charged this source.
  let demand = null, demandPkt = null;
  for (let i = 0; i < 160; i++) {
    const p = signRaw(message({ sender: 1, counter: 100n + BigInt(i), op: OPS.SET, key: 'bait', value: 'g' + i }), ATTACKER);
    const r = await post(N0, p);
    if (r.status === 402) { demand = r; demandPkt = p; break; }
  }
  const owes = demand && demand.body && demand.body.rebound === true && demand.body.bits === BITS.BLOCK && typeof demand.body.challenge === 'string';
  add('rebound', 'a source past BLOCK is asked to pay before any signature work', 'forge until the node charges instead of verifying', owes ? 'HTTP 402 — owes ' + demand.body.bits + ' bits, no verify run' : 'never charged (' + (demand ? demand.status : 'no 402') + ')', owes);
  // pay it: solve the server's own challenge, resend the SAME packet with the token — now it reaches the gate, which still refuses it
  const token = owes ? solve(demand.body.challenge, demand.body.bits, shaStr) : null;
  const paid = token ? await post(N0, demandPkt, { 'x-rebound': token }) : { status: 0, body: null };
  add('rebound', 'paying the price buys a look — the gate still refuses the forgery', 'the same forgery, with a valid token', paid.body && paid.body.rebound ? 'still owes' : stageOf(paid), paid.body && paid.body.stage === 'signature');
  // a token is bound to its packet+epoch: reuse it on a DIFFERENT forgery and the price is unpaid
  const other = signRaw(message({ sender: 1, counter: 50n, op: OPS.SET, key: 'bait', value: 'elsewhere' }), ATTACKER);
  const reuse = token ? await post(N0, other, { 'x-rebound': token }) : { status: 0, body: null };
  add('rebound', 'a token bought for one packet does not pay for another', "token for forgery g, used on a different forgery", reuse.status === 402 ? 'HTTP 402 — still owes' : stageOf(reuse), reuse.status === 402);
  // the raw asymmetry, measured directly on the kernel: producing a token vs checking one
  let solveHashes = 0; const counting = (str) => { solveHashes++; return shaStr(str); };
  const probe = 'BREAK-IT/rebound/v1|7|measure|' + 'a'.repeat(64);
  const n16 = solve(probe, 16, counting);
  let verifyHashes = 0; const vcount = (str) => { verifyHashes++; return shaStr(str); };
  verifyWork(probe, n16, 16, vcount);
  const law = obeys({ attackerWork: solveHashes, defenderWork: verifyHashes });
  add('rebound', 'the law holds: no amplification, attacker ≥ defender', 'measure one 16-bit interaction against obeys()', law.ok ? 'obeyed — attacker ' + solveHashes + ' hashes, defender ' + verifyHashes : 'BROKE: ' + law.broke.join('; '), law.ok && solveHashes > 1000 && verifyHashes === 1);
  add('rebound', 'the ratchet: attacking never gets cheaper as refusals climb', 'difficultyFor monotone over 0..ISOLATE+10, and strictly up across rungs', ratchetHolds() && difficultyFor(50) === 0 && difficultyFor(100) === BITS.BLOCK && difficultyFor(500) === BITS.ISOLATE ? '0 → ' + BITS.BLOCK + ' → ' + BITS.ISOLATE + ' bits, monotone' : 'NOT monotone', ratchetHolds() && difficultyFor(50) < difficultyFor(100) && difficultyFor(100) < difficultyFor(500));
  // the elastic membrane: free while unstretched, releasing the source's own energy back once its attacks pass the limit
  const el = elasticHolds();
  add('rebound', 'the elastic law: stretch stores, the limit releases it back at the source', 'released() over 0..ISOLATE+10 — free under BLOCK, rising past it, never unwinding', el.ok ? 'free (×1) under BLOCK → ×' + released(100) + ' at BLOCK → ×' + released(500) + ' at ISOLATE, monotone' : 'BROKE: ' + el.broke.join('; '), el.ok && released(50) === 1 && released(100) > 1 && released(500) > released(100));

  // ── STATE: the ledger itself ──────────────────────────────────────────────────────────────────────────────
  for (const n of nodes) await n.close();
  const ledger0 = join(dir, 'n0', 'ledger.jsonl'), original = readFileSync(ledger0, 'utf8');
  let tries = 0;
  const tryStart = async (path) => { try { const n = await startNode({ port: 0, ledgerPath: path, journalPath: join(dir, 'j-' + (tries++)), pubkeys, nodeKey: nodeKeys[0] }); await n.close(); return 'started'; } catch { return 'refused to start'; } };
  const variant = (name, text) => { const p = join(dir, 'ledger-' + name + '.jsonl'); writeFileSync(p, text); return p; };
  const lines = original.split('\n').filter(Boolean);
  const expect = async (group, name, tried, path, want) => { const r = await tryStart(path); add(group, name, tried, r, r === want); };
  await expect('state', 'one byte of the ledger changed', 'a character of entry 2 edited', variant('flip', original.replace(/"seq":2,"prev":"(.)/, (m, c) => m.slice(0, -1) + (c === 'a' ? 'b' : 'a'))), 'refused to start');
  await expect('state', 'an entry deleted', 'entry 3 removed', variant('del', lines.filter((_, i) => i !== 3).join('\n') + '\n'), 'refused to start');
  await expect('state', 'an entry duplicated', 'entry 1 repeated', variant('dup', [lines[0], lines[1], lines[1], ...lines.slice(2)].join('\n') + '\n'), 'refused to start');
  await expect('state', 'two entries swapped', 'entries 2 and 3 reordered', variant('swap', [lines[0], lines[1], lines[3], lines[2], ...lines.slice(4)].join('\n') + '\n'), 'refused to start');
  const tornPath = variant('torn', original + lines[0].slice(0, 30));
  await expect('state', 'a torn final write (a crash mid-append)', 'half a line appended — never acknowledged', tornPath, 'started');
  add('state', '…and the torn half is gone, the rest intact', 'read the file back', readFileSync(tornPath, 'utf8') === original ? 'trimmed to the last whole entry' : 'NOT trimmed cleanly', readFileSync(tornPath, 'utf8') === original);
  // a ledger that is a VALID chain but holds a forged packet: the chain checks out, the gate re-run does not
  let prev = GENESIS; const fake = [];
  for (const [i, p] of [legit[0], forged].entries()) { const e = entryFor(prev, i, toHex(p), sha256hex); fake.push(JSON.stringify(e)); prev = e.hash; }
  await expect('state', 'a well-chained ledger holding a forged packet', 'chain hashes recomputed honestly around a forgery', variant('forged-chain', fake.join('\n') + '\n'), 'refused to start');
  // the real node 0, back up from its own ledger and journal
  const back = await startNode({ port: 0, ledgerPath: ledger0, journalPath: join(dir, 'n0', 'journal.jsonl'), lootPath: join(dir, 'n0', 'loot.jsonl'), pubkeys, nodeKey: nodeKeys[0] });
  await expect('state', 'a second writer on a live ledger', 'start another node on the same file', ledger0, 'refused to start');
  const kept = stageOf(await paidPost(back.url, harmless));
  add('state', 'restart the node — is the drained key still blocked?', 'the same harmless packet (price paid), after a restart', kept, kept === 'behavior');
  const known = stageOf(await post(back.url, forged));
  add('state', 'restart the node — does it still know the attacks?', 'the first forgery, after a restart', known, known === 'recognised');
  const stillOwes = await post(back.url, signRaw(message({ sender: 1, counter: 8n, op: OPS.SET, key: 'bait', value: 'post-restart' }), ATTACKER));
  add('state', 'restart the node — is the price still owed?', 'a fresh forgery from the ground-down source, after a restart', stillOwes.status === 402 ? 'HTTP 402 — the ladder was rebuilt from the journal' : stageOf(stillOwes), stillOwes.status === 402);
  const referee = await (await fetch(back.url + '/referee')).json();
  await back.close();
  const j0 = join(dir, 'n0', 'journal.jsonl'), jtext = readFileSync(j0, 'utf8');
  writeFileSync(j0, jtext.replace('"novel":true', '"novel":false'));
  const jt = await startNode({ port: 0, ledgerPath: ledger0, journalPath: j0, pubkeys, nodeKey: nodeKeys[0] });
  const jh = await (await fetch(jt.url + '/health')).json();
  await jt.close();
  add('state', 'the attack journal edited', 'one record\'s "novel" flag flipped', jh.journal === 0 && jh.ledger === lines.length ? 'journal moved aside, ledger untouched (' + jh.ledger + ' entries)' : 'journal trusted', jh.journal === 0 && jh.ledger === lines.length);

  // ── THE REFEREE ───────────────────────────────────────────────────────────────────────────────────────────
  add('referee', 'did anything reach the app it should not have?', 'every admitted message checked against the gate, the ledger and an independent grammar; the whole state re-folded from the ledger', referee.breached ? 'BREACHED' : 'clean — ' + referee.checked + ' messages checked, state = ledger replay: ' + referee.foldMatches, !referee.breached && referee.foldMatches === true);

  rmSync(dir, { recursive: true, force: true });
  // the expected outcome of every "refused" case is fixed by the stage, so the receipt is deterministic
  const held = cases.every((c) => c.held);
  return { kind: 'break-it-redteam', v: 1, rule: 'reach the app with anything malicious and you win — the referee decides', cases: cases.length, held, results: cases };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url).replace(/\\/g, '/') === process.argv[1].replace(/\\/g, '/');
if (isMain) {
  const r = await run();
  const text = canonicalJson(r) + '\n';
  if (process.argv.includes('--check')) {
    const committed = existsSync(OUT) ? readFileSync(OUT, 'utf8').replace(/\r\n/g, '\n') : '';
    if (committed !== text) { console.error('the red-team receipt does NOT reproduce'); process.exit(1); }
    console.log('REPRODUCED — ' + r.cases + ' cases, all held: ' + r.held); process.exit(r.held ? 0 : 1);
  }
  mkdirSync(dirname(OUT), { recursive: true }); writeFileSync(OUT, text);
  for (const c of r.results) console.log((c.held ? 'HELD  ' : 'BROKE ') + c.group.padEnd(9) + c.name.slice(0, 70).padEnd(72) + ' → ' + c.outcome);
  console.log('\n' + (r.held ? 'every vector held' : 'A VECTOR BROKE') + ' — ' + r.cases + ' cases → receipts/redteam.json');
  process.exit(r.held ? 0 : 1);
}
