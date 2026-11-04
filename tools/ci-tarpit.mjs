#!/usr/bin/env node
// tools/ci-tarpit.mjs — what GitHub's machine printed for the tarpit's p-4 and p-5, kept in the repository.
//
//   node tools/ci-tarpit.mjs <runId> [<runId> …]     add those gate runs to receipts/tarpit-ci.json (needs `gh`, signed in)
//   node tools/ci-tarpit.mjs --check                 re-read the receipt: every verdict word matches its own line
//
// p-4 and p-5 turn on how fast the attacker's machine pays the proof-of-work, so CI re-runs them and PRINTS its own
// verdict without requiring it to match the committed receipt (tarpit/measure.mjs --check). Those printed lines live only
// in each run's log, and GitHub deletes logs after a while. This copies them word for word, with the run, its commit and
// its date, so the page can show every recorded run, the ones that held and the ones that failed alike. Nothing here
// measures anything; it keeps what CI said.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'receipts', 'tarpit-ci.json');
const REPO = 'sjgant80-hub/break-it';
const LINE = /^\s*(p-[45]) on this machine \(not required to match\): (held|failed) · (.+)$/;
const SUMMARY = /^TARPIT REPRODUCED · .+$/;

/** the p-4 / p-5 lines and the summary out of one run's log text (timestamps stripped), or null if the run printed none */
export function linesOf(log) {
  const out = {};
  for (const raw of String(log).split(/\r?\n/)) {
    const text = raw.replace(/^.*?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?/, '');
    const m = text.match(LINE);
    if (m) out[m[1]] = { verdict: m[2], line: text.trim() };
    else if (SUMMARY.test(text.trim())) out.summary = text.trim();
  }
  return out['p-4'] && out['p-5'] ? out : null;
}

const gh = (args) => {
  const r = spawnSync('gh', args, { encoding: 'utf8', maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error('gh ' + args.join(' ') + ': ' + (r.stderr || '').trim());
  return r.stdout;
};

const blank = () => ({ kind: 'break-it.tarpit-ci', v: 1,
  about: 'What GitHub\u2019s machine printed for p-4 and p-5 on each gate run recorded here, copied word for word from the run\u2019s log (node tools/ci-tarpit.mjs <runId>). CI prints these two without requiring them to match receipts/tarpit.json, because they turn on how fast the attacker\u2019s machine pays the proof-of-work. The committed receipt keeps the laptop\u2019s verdicts.',
  runs: [] });

const args = process.argv.slice(2);
const receipt = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : blank();

if (args.includes('--check')) {
  let bad = 0;
  for (const r of receipt.runs) for (const id of ['p-4', 'p-5']) {
    const m = String(r[id] && r[id].line).match(LINE);
    if (!m || m[1] !== id || m[2] !== r[id].verdict) { bad++; console.error('run ' + r.run + ' ' + id + ': the verdict does not match its line'); }
  }
  console.log(bad ? 'NOT CONSISTENT' : 'CONSISTENT · ' + receipt.runs.length + ' CI runs, every verdict word read from its own line');
  process.exit(bad ? 1 : 0);
}

for (const id of args) {
  if (!/^\d+$/.test(id)) { console.error('a run id is a number: ' + id); process.exit(2); }
  const meta = JSON.parse(gh(['run', 'view', id, '-R', REPO, '--json', 'headSha,createdAt,conclusion,url,workflowName']));
  if (meta.workflowName !== 'gate') { console.error('run ' + id + ' is not a gate run'); process.exit(2); }
  const got = linesOf(gh(['run', 'view', id, '-R', REPO, '--log']));
  if (!got) { console.error('run ' + id + ' printed no p-4 / p-5 lines (before af830fe, or the step did not run)'); process.exit(1); }
  const row = { run: Number(id), url: meta.url, sha: meta.headSha, at: meta.createdAt, conclusion: meta.conclusion, 'p-4': got['p-4'], 'p-5': got['p-5'], summary: got.summary || null };
  receipt.runs = receipt.runs.filter((r) => r.run !== row.run).concat(row).sort((a, b) => a.at.localeCompare(b.at));
  console.log('run ' + id + ' (' + meta.headSha.slice(0, 7) + '): p-4 ' + got['p-4'].verdict + ' · p-5 ' + got['p-5'].verdict);
}
if (args.length) writeFileSync(OUT, JSON.stringify(receipt, null, 1) + String.fromCharCode(10));
