#!/usr/bin/env node
// herd/measure.mjs — the herd measurement: the seal checked, the two runs made (the shipped gate; the planted flaw),
// the facts judged against the sealed claims, the receipt written.
//   node herd/measure.mjs            → receipts/herd.json
//   node herd/measure.mjs --check    → re-run; refuse unless every verdict and every fact but the timings is the receipt's
//   HERD_SMOKE=1 node herd/measure.mjs → plumbing only: a few of each, prints the facts' shape, judges nothing, writes nothing
// It refuses to run if herd/claims.json differs from the commit that sealed it.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { judge } from './judge.mjs';

const ROOT = new URL('../', import.meta.url);
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8' });
const sha = (s) => createHash('sha256').update(s).digest('hex');
const SMOKE = process.env.HERD_SMOKE === '1';

const path = 'herd/claims.json', text = readFileSync(new URL(path, ROOT), 'utf8');
const commit = git('log', '-1', '--format=%H', '--', path).trim();
if (!commit || git('show', commit + ':' + path) !== text) { console.log(path + ' differs from the commit that sealed it — refusing to measure'); process.exit(1); }
let codeAtSeal = true;
try { git('show', commit + ':herd/run.mjs'); } catch { codeAtSeal = false; }

const run = (args) => {
  const out = execFileSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', env: { ...process.env }, maxBuffer: 1 << 24, timeout: 3600000 });
  return JSON.parse(out.trim().split('\n').pop());
};
const t0 = Date.now();
const facts = { ...run(['herd/run.mjs', 'real']), ...run(['--import', './herd/flaw.mjs', 'herd/run.mjs', 'flawed']) };

if (SMOKE) {
  const keys = (o, d = 0) => (o && typeof o === 'object' && !Array.isArray(o) && d < 2 ? '{' + Object.keys(o).map((k) => k + keys(o[k], d + 1)).join(' ') + '}' : '');
  console.log('SMOKE RAN END TO END · ' + Math.round((Date.now() - t0) / 1000) + ' s · ' + keys(facts));
  process.exit(0);
}
const claims = JSON.parse(text), j = judge(claims, facts);
const { timing, ...steady } = facts;
const receipt = { kind: 'break-it.herd.receipt', v: 1, sealed: { path, commit, claimsSha256: sha(text), measuringCodeCommittedAtSeal: codeAtSeal }, facts, steadySha256: sha(JSON.stringify(steady)), held: j.held, failed: j.failed, verdicts: j.verdicts };

if (process.argv.includes('--check')) {
  const was = JSON.parse(readFileSync(new URL('receipts/herd.json', ROOT), 'utf8'));
  const same = was.steadySha256 === receipt.steadySha256 && JSON.stringify(was.verdicts) === JSON.stringify(receipt.verdicts);
  console.log(same ? 'HERD REPRODUCED · ' + j.held + ' held, ' + j.failed + ' failed, as the receipt says (timings aside)' : 'HERD DRIFT · the re-run differs from the receipt');
  process.exit(same ? 0 : 1);
}
writeFileSync(new URL('receipts/herd.json', ROOT), JSON.stringify(receipt, null, 1) + '\n');
for (const v of j.verdicts) console.log((v.held ? 'HELD   ' : 'FAILED ') + v.id + ' · ' + v.measured);
console.log('wrote receipts/herd.json · ' + j.held + ' held, ' + j.failed + ' failed · ' + Math.round((Date.now() - t0) / 1000) + ' s');
