// every number typed into the live page, tied to where it comes from. The page fills most of its figures from the
// receipts at load time; the few written into the HTML (the FAQ and its schema, the explainers, the white paper) are
// checked here against the kernel constant, the receipt or the sourced price they state. Change a kernel or a receipt and
// the page must change with it, or this fails. Read as text; no browser needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { REBOUND_LADDER, BITS } from '../src/rebound.mjs';
import { TARPIT } from '../src/tarpit.mjs';
import { HEADER, SIG, MAX_PACKET, REC_N, MAX_ACCOUNT, MAX_PERIOD, MAX_AMOUNT } from '../src/wire.mjs';
import { POST_CAP, WINDOW } from '../src/sentinel.mjs';
import { costCase } from '../src/cost.mjs';

const read = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const HTML = read('index.html'), LLMS = read('llms.txt'), SERVER = read('src/server.mjs'), CHECK = read('pilot/check.mjs');
const flat = (s) => s.replace(/>\s*</g, '> <').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/\s+/g, ' ');   // tags that touch are words apart
const PAGE = flat(HTML), TEXT = LLMS.replace(/\s+/g, ' ');
const n0 = (n) => Number(n).toLocaleString('en-GB');
const WORD = { 4: 'four', 5: 'five', 6: 'six', 20: 'twenty' };
const has = (s, where = PAGE) => assert.ok(where.includes(s), 'the page says: ' + s);
const json = (p) => JSON.parse(read(p));
const PILOT = json('receipts/pilot.json'), RED = json('receipts/redteam.json'), HERD = json('receipts/herd.json'), TP = json('receipts/tarpit.json');
const SOURCES = json('costs/sources.json'), BASIS = json('costs/basis.json');

test('the rebound: the price a look, and where it starts', () => {
  const lo = n0(2 ** BITS.BLOCK), hi = n0(2 ** BITS.ISOLATE), B = REBOUND_LADDER.BLOCK, I = REBOUND_LADDER.ISOLATE;
  has('(' + lo + ' hashes a look past ' + B + ' refusals, ' + hi + ' past ' + I + ')');
  has('refused ' + B + ' times owes a proof-of-work token per packet (' + BITS.BLOCK + ' leading zero bits, about ' + lo + ' hashes), ' + I + ' times ' + BITS.ISOLATE + ' bits (about ' + hi + ')');
  for (const s of ['Under ' + B + ' refusals a source pays nothing', 'A source past ' + B + ' gate refusals', 'From ' + B + ' refusals an address must pay', 'the rebound starts only after ' + B + ' refusals']) has(s);
  has('past ' + B + ' refusals a source pays proof-of-work per look (about ' + lo + ' hashes; ' + hi + ' past ' + I + ')', TEXT);
});

test('the tarpit: who is confirmed, how long, how many', () => {
  assert.equal(TARPIT.CONFIRM, REBOUND_LADDER.ISOLATE, 'confirmed = the top rung of the rebound');
  const C = TARPIT.CONFIRM, CAP = TARPIT.CAP, secs = WORD[TARPIT.HOLD_MS / 1000];
  assert.equal(TARPIT.DRIP_MS, 1000, 'one space a second');
  for (const s of ['once the gate has refused it ' + C + ' times', 'At most ' + CAP + ' answers are held at once', 'An address the gate has turned away ' + C + ' times is confirmed',
    'from ' + C + ' the tarpit also holds its refusals', 'each address must be refused ' + C + ' times', 'the node keeps at most ' + CAP + ' connections open',
    'only from a source the gate has refused ' + C + ' times, and at most ' + CAP + ' at once', 'one space a second for ' + secs + ' seconds', 'sends one space a second for ' + secs + ' seconds']) has(s);
  for (const s of ['refused ' + C + ' times before,', 'at most ' + CAP + ' at once', 'held ' + secs + ' seconds']) assert.ok(HTML.includes(s), 'the diagram says: ' + s);
  const p2 = TP.facts.p2;
  assert.deepEqual([p2.sent, p2.admitted, p2.held], [100, 100, 0]);
  has('Measured in p-2: ' + p2.sent + ' genuine records sent from the attacker’s own address were all admitted and none was held');
});

test('the wire: the record, the header, the signature, the packet', () => {
  const lastYear = 2000 + Math.floor(MAX_PERIOD / 12), lastMonth = MAX_PERIOD % 12;
  assert.equal(lastMonth, 11, 'the last month is a December');
  has('A REC record is ' + REC_N + ' bytes: an account (1–' + n0(MAX_ACCOUNT) + '), a month (January 2000 to December ' + lastYear + ') and an amount (0–' + n0(MAX_AMOUNT) + ')');
  has('an account (1 to ' + n0(MAX_ACCOUNT) + '), a month (January 2000 to December ' + lastYear + ') and an amount (0 to ' + n0(MAX_AMOUNT) + ')', TEXT);
  for (const s of ['a ' + HEADER + '-byte header', 'a ' + SIG + '-byte Ed25519 signature', 'A ' + SIG + '-byte proof', 'anything over ' + MAX_PACKET + ' bytes']) has(s);
  has('it accepts period ' + (MAX_PERIOD + 1) + ', a month past its limit');
});

test('the HTTP layer: the limits a request meets before the gate', () => {
  const lim = SERVER.match(/LIMITS = Object\.freeze\(\{ rate: (\d+), burst: (\d+),/), opt = SERVER.match(/requestTimeout: (\d+), headersTimeout: (\d+), keepAliveTimeout: \d+, maxHeaderSize: (\d+)/);
  assert.ok(lim && opt, 'the limits are where the test reads them');
  const [, rate, burst] = lim, [, req, hdr, max] = opt;
  has('more than ' + rate + ' requests a second from one address (bursts to ' + burst + ')');
  has('“One address is limited to ' + rate + ' records a second.” By design, with bursts to ' + burst);
  has('capped at ' + Number(max) / 1024 + ' KB, with a ' + Number(hdr) / 1000 + '-second header and ' + Number(req) / 1000 + '-second request timeout');
});

test('the sentinel: the inflation cap', () => {
  has('posting over ' + n0(POST_CAP) + ' in ' + WINDOW + ' records');
  has('inflation over ' + n0(POST_CAP) + ' in ' + WINDOW + ' records', TEXT);
});

test('the pilot: every figure typed on the page is the receipt’s', () => {
  const f = PILOT.facts;
  assert.equal(f.admitted, PILOT.feed.records);
  has(n0(f.admitted) + ' real payment records through one node');
  has('ingested all ' + n0(f.admitted) + ' payment records of the UCI Default of Credit Card Clients dataset (DOI 10.24432/C55S3H) in ' + n0(f.seconds) + ' seconds, ' + f.perSecond + ' a second on a laptop');
  has('Its books equalled the feed on all ' + n0(f.books.keys) + ' keys, ' + WORD[f.injections.length] + ' attack shapes injected mid-feed');
  has(PILOT.held + ' of the ' + PILOT.verdicts.length + ' claims sealed in git before the run held');
  has('equal to the feed on every one of ' + n0(f.books.keys) + ' keys, while ' + WORD[f.injections.length] + ' attacks were refused');
  has('One laptop at the pilot’s ' + f.perSecond + ' records a second carries about ' + (Math.round((f.perSecond * 86400) / 100000) / 10) + ' million records a day');
  has('The ' + f.perSecond + ' records a second is what the node did');
  has('in ' + n0(f.seconds) + ' seconds (' + f.perSecond + ' a second', TEXT);
  assert.ok(new RegExp('const PREFIX = 3000;').test(CHECK));
  has('a real node re-run on the first 3,000 records');
  assert.equal(f.egress.afterListening, 0);
  has('Egress: 0 outbound attempts once the node was listening', TEXT);
});

test('the red-team battery: the case count and the stolen-key case', () => {
  assert.equal(RED.cases, Object.keys(RED.results).length);
  assert.equal(RED.held, true);
  for (const s of ['the battery of ' + RED.cases + ' attacks re-runs in CI', 'a ' + RED.cases + '-case attack battery']) has(s);
  const theft = Object.values(RED.results).find((r) => /stolen, posting credit without end/.test(r.name));
  const at = theft && (theft.outcome.match(/behavior at record (\d+)/) || [])[1];
  assert.ok(at, 'the battery has the stolen-key case');
  has('without end at record ' + at + ' (red-team case)');
  has('a stolen feed key posting credit without end is blocked at record ' + at);
});

test('the herd: how many nodes, and who closed the hole', () => {
  const n = HERD.facts.h1.sent;
  assert.equal(HERD.facts.h3.peers.length, n - 1);
  assert.equal(HERD.facts.h3.breaches, 1);
  has('the first of ' + WORD[n] + ' nodes it reached; the other ' + WORD[n - 1] + ' checked the proof themselves');
  has(WORD[n][0].toUpperCase() + WORD[n].slice(1) + ' nodes, as node run.mjs starts them, each pinning the other ' + WORD[n - 1]);
  has('under ' + WORD[n] + ' real nodes');
});

test('the cost case: the FAQ’s worked example is the kernel’s, on the committed prices', () => {
  const p = SOURCES.prices;
  const r = costCase({ requests: 10000000, acls: 1, rules: 19, api: 'rest', rate: Math.floor(PILOT.facts.perSecond), watts: p.laptopMaxWatts, hours: 730, fx10k: p.fx10k,
    machinePence: 0, lifeMonths: 36, staffHours: 0, staffRatePence: p.nlwPence, staffShare: 100 }, p);
  assert.equal(r.ok, true);
  const usd = (c) => '$' + (c / 100).toFixed(2), gbp = (x) => '£' + (x / 100).toFixed(2);
  has('one web ACL, 19 rules and 10 million requests a month, WAF is ' + usd(r.managed.wafCents) + ' and a REST API Gateway adds ' + usd(r.managed.gatewayCents)
    + ', while one node drawing the laptop chip\'s ' + p.laptopMaxWatts + ' W maximum all month costs ' + gbp(r.node.electricityPence));
  assert.equal(r.node.nodes, 1);
  has('USD ' + p.breachUsd / 1e6 + ' million on average worldwide');
  for (const [id, v] of [['c-watts', p.laptopMaxWatts], ['c-fx', p.fx10k / 10000], ['c-staffr', p.nlwPence / 100], ['c-rules', 19], ['c-hours', 730]]) {
    const m = HTML.match(new RegExp('id="' + id + '"[^>]*value="([^"]+)"'));
    assert.ok(m && Number(m[1]) === v, '#' + id + ' starts at ' + v);
  }
  has('the chip’s full ' + p.laptopMaxWatts + ' W every hour of the month');
});

test('the estate’s sourced basis is vendored byte for byte, and the two figures the page shows come from it', () => {
  const pin = json('costs/basis.SOURCE.json');
  assert.equal(createHash('sha256').update(readFileSync(new URL('../costs/basis.json', import.meta.url))).digest('hex'), pin.sha256);
  for (const k of Object.keys(pin.reads)) { assert.ok(Number.isFinite(BASIS[k].value), k); assert.match(BASIS[k].source, /^https:\/\//, k); }
  assert.ok(!/24\.51|19\.67/.test(HTML), 'the basis figures are not typed into the page');
  // the words the page puts round them must stay true of the figures themselves
  assert.ok(Math.round(BASIS.electricityPencePerKwh.value * 100) < SOURCES.prices.unitRateCentiPence, 'the page says the business price was lower than the household cap the case uses');
  has('at the household price cap (the average UK business price was lower');
  assert.ok(Math.round(BASIS.wageMedianHourly.value * 100) > SOURCES.prices.nlwPence, 'the page calls the staff rate it starts from the floor, below the median');
  has('the National Living Wage floor');
  assert.ok(read('page/app.mjs').includes("fetch('costs/basis.json')"), 'the page reads them from the basis');
});
