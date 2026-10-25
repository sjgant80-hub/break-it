#!/usr/bin/env node
// pilot/measure.mjs — the Liveware Pilot, measured. One real node (startNode, as `node run.mjs` runs it) in a process
// of its own with the egress meter loaded first; the partner feed (180,000 signed payment records) sent to it one by
// one over HTTP; six known attack shapes from the attack kit injected mid-feed, each sent twice; then the node's own
// books, referee, journal and ledger read back, the ledger re-derived offline from the feed alone, and the red-team
// battery re-run. pilot/judge.mjs holds each sealed claim (pilot/claims.json) against what was measured.
//
//   node pilot/measure.mjs              the whole feed; writes receipts/pilot.json
//   node pilot/measure.mjs --limit N    the first N records, for a look (prints the verdicts, writes nothing)
//
// It refuses to run if pilot/claims.json or pilot/claims-2.json differs from the commit that sealed it.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { tmpdir, cpus, platform, release } from 'node:os';
import { join } from 'node:path';
import { loadChain } from '../src/ledger.mjs';
import { encodeUnsigned, OPS, HEADER } from '../src/wire.mjs';
import { randomKey, rawPacket, signRaw } from '../attack-kit/lib.mjs';
import { ROOT, sha, loadFeed, startMetered, stopMetered, post, getJson, closeAgent, genuine, packetFor, deriveHead, booksHash, booksOf, SENDER } from './lib.mjs';
import { judge, explained } from './judge.mjs';

const arg = (k) => { const i = process.argv.indexOf(k); return i >= 0 ? Number(process.argv[i + 1]) : null; };
const LIMIT = arg('--limit');
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8' });
const say = (m) => process.stderr.write(m + '\n');

// ── the seals: each claims file as it was committed (the first before any of this code existed)
function sealed(path) {
  const text = readFileSync(join(ROOT, path), 'utf8');
  const commit = git('log', '-1', '--format=%H', '--', path).trim();
  if (!commit || git('show', commit + ':' + path) !== text) throw new Error(path + ' differs from the commit that sealed it — refusing to measure');
  let codeAtSeal = true;
  try { git('show', commit + ':pilot/measure.mjs'); } catch { codeAtSeal = false; }
  return { path, commit, claimsSha256: sha(text), measuringCodeCommittedAtSeal: codeAtSeal, claims: JSON.parse(text).claims };
}
const seals = [sealed('pilot/claims.json'), sealed('pilot/claims-2.json')];
const claims = { claims: seals.flatMap((s) => s.claims) };
const sealCommit = seals[0].commit;
const code = { commit: git('rev-parse', 'HEAD').trim(), uncommittedChanges: git('status', '--porcelain', '--', 'src', 'pilot', 'attack-kit').trim() !== '' };

const feed = loadFeed();
const records = LIMIT ? feed.records.slice(0, LIMIT) : feed.records;
say('feed ' + feed.sha256.slice(0, 16) + '… — ' + records.length + ' records; claims sealed at ' + sealCommit.slice(0, 7));

// ── the meter must be able to see before its zero means anything
const canary = (await startMetered(tmpdir(), { canary: true })).first.canary;
const canarySeen = canary.tcp >= 1 && canary.udp >= 1 && canary.dns >= 1 && canary.fetch >= 1;
say('canary: tcp ' + canary.tcp + ', udp ' + canary.udp + ', dns ' + canary.dns + ', fetch ' + canary.fetch + (canarySeen ? ' — the meter sees' : ' — THE METER IS BLIND'));

const dir = mkdtempSync(join(tmpdir(), 'break-it-pilot-'));
const { child, first } = await startMetered(dir);
const url = first.url;
say('node ' + url);

// the six injections, built from the attack kit against the live feed (the last genuine packet, the next counter)
const INJECT = ['replay', 'flip', 'unpinned', 'nodomain', 'truncated', 'out-of-range'];
const be = (v, n) => Array.from({ length: n }, (_, i) => (v >>> (8 * (n - 1 - i))) & 0xff);
function attack(kind, last, next) {
  const u = () => encodeUnsigned({ sender: 1, counter: next, op: OPS.REC, account: 1, period: 63, amount: 1 });
  if (kind === 'replay') return last.slice();
  if (kind === 'flip') { const b = last.slice(); b[HEADER + 10] ^= 1; return b; }
  if (kind === 'unpinned') return signRaw(u(), randomKey());
  if (kind === 'nodomain') return signRaw(u(), SENDER, { domain: '' });
  if (kind === 'truncated') return last.slice(0, last.length - 10);
  return signRaw(rawPacket({ sender: 1, counter: next, payload: [OPS.REC, ...be(1, 4), ...be(1200, 2), ...be(1, 4)] }), SENDER);
}

const client = genuine();
const answers = [], injections = [];
let admitted = 0, genuineRefused = 0, retries = 0, last = null;
const every = Math.floor(records.length / (INJECT.length + 1));
const t0 = process.hrtime.bigint();
for (let i = 0; i < records.length; i++) {
  if (every > 0 && i > 0 && i % every === 0 && injections.length < INJECT.length) {
    const kind = INJECT[injections.length], bytes = attack(kind, last, client.counter);
    const a = await post(url, bytes), b = await post(url, bytes);
    answers.push(a.body, b.body);
    injections.push({ kind, at: i, first: { status: a.status, stage: a.body && a.body.stage }, second: { status: b.status, stage: b.body && b.body.stage } });
  }
  const p = packetFor(client, records[i]);
  let r = await post(url, p);
  while (r.status === 429) { retries++; answers.push(r.body); await new Promise((s) => setTimeout(s, 20)); r = await post(url, p); }
  if (r.status === 200 && r.body && r.body.accepted) admitted++; else { genuineRefused++; answers.push(r.body); }
  last = p;
  if ((i + 1) % 10000 === 0) say('  ' + (i + 1) + ' / ' + records.length);
}
const seconds = Number(process.hrtime.bigint() - t0) / 1e9;

// ── read the node back
const state = (await getJson(url, '/state')).state;
const referee = await getJson(url, '/referee');
const journal = [];
for (let since = 0; ; ) { const j = await getJson(url, '/journal?since=' + since + '&limit=500'); journal.push(...j.records); if (!j.records.length || journal.length >= j.length) break; since = journal.length; }
closeAgent();
const metered = await stopMetered(child);
const chain = loadChain(join(dir, 'ledger.jsonl'));
rmSync(dir, { recursive: true, force: true });

const want = booksOf(records), keys = Object.keys(want);
const mismatches = keys.filter((k) => state[k] !== want[k]).length + Object.keys(state).filter((k) => !(k in want)).length;
say('reading back done; re-deriving the ledger offline…');
const derivedHead = deriveHead(records);

say('re-running the red-team battery…');
const rt = spawnSync(process.execPath, ['attack-kit/redteam.mjs', '--check'], { cwd: ROOT, encoding: 'utf8' });
const battery = JSON.parse(readFileSync(join(ROOT, 'receipts/redteam.json'), 'utf8'));

const facts = {
  admitted, ledgerEntries: chain.ok ? chain.entries.length : -1, genuineRefused, retries,
  books: { equal: mismatches === 0, mismatches, keys: keys.length, accounts: new Set(records.map((r) => r.account)).size },
  seconds: Math.round(seconds * 10) / 10, perSecond: Math.round((admitted / seconds) * 10) / 10,
  egress: metered.egress, canarySeen, listening: metered.egress.listening,
  injections, referee: { breached: referee.breached, foldMatches: referee.foldMatches, checked: referee.checked },
  redteam: { exit: rt.status, cases: battery.cases, held: battery.held },
  explained: { answers: answers.length, unexplained: answers.filter((a) => !explained(a)).length, journal: journal.length, journalUnexplained: journal.filter((r) => !explained(r)).length },
  chain: { ok: chain.ok, head: chain.ok ? chain.head : null }, derivedHead,
};
const verdict = judge(claims, facts);
for (const v of verdict.verdicts) say((v.held ? '  HELD   ' : '  FAILED ') + v.id + ' — ' + v.measured);
say(verdict.held + ' held, ' + verdict.failed + ' failed');

if (LIMIT) { say('(a --limit run: nothing written)'); process.exit(0); }
const receipt = {
  kind: 'break-it.pilot.receipt', v: 1,
  sealed: seals.map(({ claims: _, ...s }) => s), code,
  ran: { at: new Date().toISOString(), cpu: cpus()[0].model.trim(), cores: cpus().length, os: platform() + ' ' + release(), node: process.version },
  feed: { sha256: feed.sha256, records: records.length, accounts: feed.accounts },
  deterministic: { ledgerHead: facts.chain.head, derivedHead, ledgerEntries: facts.ledgerEntries, booksSha256: booksHash(state), feedBooksSha256: booksHash(want) },
  facts: { ...facts, egress: { ...metered.egress }, nodeStats: metered.stats, antibodies: metered.antibodies, canary },
  verdicts: verdict.verdicts, held: verdict.held, failed: verdict.failed,
  rerun: 'node pilot/measure.mjs (the whole pilot, about as long as it took here) · node pilot/check.mjs (CI: the ledger and books re-derived from the feed alone, and a real node re-run on the first 3,000 records)',
};
writeFileSync(join(ROOT, 'receipts/pilot.json'), JSON.stringify(receipt, null, 1) + '\n');
say('wrote receipts/pilot.json');
process.exit(0);
