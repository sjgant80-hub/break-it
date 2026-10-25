#!/usr/bin/env node
// pilot/check.mjs — the pilot's receipt, re-checked without trusting it (CI runs this on every push):
//   · each claims file still hashes to what the receipt says was sealed, and the feed to its recorded hash
//   · the ledger head and the books are re-derived from the feed alone, with no node, and must equal the receipt's
//   · the judge, re-run on the receipt's own facts, must give exactly the receipt's verdicts
//   · a real node, metered the same way, ingests the first 3,000 records: its ledger head must equal the offline
//     derivation of those 3,000, its books must equal the feed's, and it must make no outbound attempt once listening
// Exit 0 only if all of it holds. The full run itself is `node pilot/measure.mjs`.
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadChain } from '../src/ledger.mjs';
import { ROOT, sha, loadFeed, startMetered, stopMetered, post, getJson, closeAgent, genuine, packetFor, deriveHead, booksHash, booksOf } from './lib.mjs';
import { judge, BIND_LOOKUP } from './judge.mjs';

const PREFIX = 3000;
const receipt = JSON.parse(readFileSync(join(ROOT, 'receipts/pilot.json'), 'utf8'));
const fails = [];
const check = (ok, what) => { console.log((ok ? '  ✓ ' : '  ✗ ') + what); if (!ok) fails.push(what); };

const claims = { claims: [] };
for (const s of receipt.sealed) {
  const text = readFileSync(join(ROOT, s.path), 'utf8');
  check(sha(text) === s.claimsSha256, s.path + ' is the file sealed at ' + s.commit.slice(0, 7));
  claims.claims.push(...JSON.parse(text).claims);
}
const feed = loadFeed();
check(feed.sha256 === receipt.feed.sha256 && feed.records.length === receipt.feed.records, 'the feed is the one the pilot ran (' + feed.records.length + ' records)');

const head = deriveHead(feed.records);
check(head === receipt.deterministic.derivedHead && head === receipt.deterministic.ledgerHead, 'the ledger head, re-derived from the feed alone, equals the node’s (' + head.slice(0, 16) + '…)');
const want = booksOf(feed.records);
check(booksHash(want) === receipt.deterministic.feedBooksSha256 && booksHash(want) === receipt.deterministic.booksSha256, 'the books, re-derived from the feed alone, equal the node’s');

const again = judge(claims, receipt.facts);
check(JSON.stringify(again.verdicts) === JSON.stringify(receipt.verdicts) && again.held === receipt.held, 'the judge, re-run on the receipt’s facts, gives the receipt’s verdicts (' + again.held + ' held, ' + again.failed + ' failed)');

// a real node on the first PREFIX records
const canary = (await startMetered(tmpdir(), { canary: true })).first.canary;
check(canary.tcp >= 1 && canary.udp >= 1 && canary.dns >= 1 && canary.fetch >= 1, 'the egress meter sees (canary: tcp, udp, dns and fetch each counted)');
const dir = mkdtempSync(join(tmpdir(), 'break-it-check-'));
const { child, first } = await startMetered(dir);
const client = genuine(), part = feed.records.slice(0, PREFIX);
let admitted = 0;
for (const rec of part) {
  const p = packetFor(client, rec);
  let r = await post(first.url, p);
  while (r.status === 429) { await new Promise((s) => setTimeout(s, 20)); r = await post(first.url, p); }
  if (r.status === 200) admitted++;
}
const state = (await getJson(first.url, '/state')).state;
closeAgent();
const m = await stopMetered(child);
const chain = loadChain(join(dir, 'ledger.jsonl'));
rmSync(dir, { recursive: true, force: true });
check(admitted === PREFIX, 'a real node admitted all ' + PREFIX + ' records (' + admitted + ')');
check(chain.ok && chain.head === deriveHead(part), 'its ledger head equals the offline derivation of those ' + PREFIX);
check(booksHash(state) === booksHash(booksOf(part)), 'its books equal the feed’s');
check(m.egress.afterListening === 0 && m.egress.seen.every((x) => x === BIND_LOOKUP), 'it made no outbound attempt once listening (' + (m.egress.seen.join('; ') || 'none at all') + ')');
check(m.egress.listening.length > 0 && m.egress.listening.every((a) => a.startsWith('127.0.0.1:')), 'it listened on 127.0.0.1 only');

console.log(fails.length ? '\nPILOT CHECK FAILED — ' + fails.length + ' of the checks above' : '\nPILOT CHECK CLEAN — the receipt stands');
process.exit(fails.length ? 1 : 0);
