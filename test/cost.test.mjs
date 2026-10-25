import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pricesFrom, banded, nodesFor, costCase, RANGES, API } from '../src/cost.mjs';

const FILE = JSON.parse(readFileSync(new URL('../costs/sources.json', import.meta.url), 'utf8'));
const P = FILE.prices;
const BASE = Object.freeze({ requests: 10000000, acls: 1, rules: 19, api: 'none', rate: 100, watts: 55, hours: 730, fx10k: 13363,
  machinePence: 0, lifeMonths: 36, staffHours: 0, staffRatePence: 0, staffShare: 0 });
const run = (over) => costCase({ ...BASE, ...over }, P);

test('the committed source file passes its own check, and every source names a primary page and a date', () => {
  const r = pricesFrom(FILE);
  assert.equal(r.ok, true);
  assert.equal(r.prices, P);
  for (const s of FILE.sources) { assert.match(s.url, /^https:\/\//); assert.equal(s.read, '2026-10-25'); assert.ok(s.what.length > 20); }
  assert.deepEqual(FILE.sources.map((s) => s.id), ['aws-waf', 'aws-apigw', 'ofgem-cap', 'intel-i7-1255u', 'boe-fx', 'ibm-breach']);
});

test('pricesFrom refuses a file with any price missing, zero, fractional or off the cap', () => {
  assert.deepEqual(pricesFrom(null), { ok: false, why: 'no prices' });
  assert.deepEqual(pricesFrom({ prices: 'x' }), { ok: false, why: 'no prices' });
  for (const k of ['wafAclCents', 'wafRuleCents', 'wafPerMillionCents', 'maxRequests', 'unitRateCentiPence', 'fx10k', 'laptopBaseWatts', 'laptopMaxWatts', 'breachUsd']) {
    for (const bad of [0, -1, 1.5, '5', undefined]) {
      const r = pricesFrom({ prices: { ...P, [k]: bad } });
      assert.equal(r.ok, false, k + '=' + bad);
      assert.equal(r.why, k + ' is not a positive integer');
    }
    assert.equal(pricesFrom({ prices: { ...P, [k]: P[k] } }).ok, true);
  }
  assert.equal(pricesFrom({ prices: { ...P, maxRequests: P.maxRequests - 1 } }).why, 'maxRequests is not the calculator’s cap');
});

test('a tier table must cover exactly 0 to the cap, each tier two positive integers', () => {
  const cap = P.maxRequests;
  for (const [field, name] of [['restBands', 'restBands'], ['httpBands', 'httpBands']]) {
    const why = name + ' do not cover 0 to maxRequests';
    for (const bad of [null, 7, [], 'x', [[cap - 1, 100]], [[cap + 1, 100]], [[cap, 0]], [[cap, 1.5]], [[0, 100], [cap, 100]], [[cap]], [[cap, 100, 1]], [5]]) {
      assert.equal(pricesFrom({ prices: { ...P, [field]: bad } }).why, why, JSON.stringify(bad));
    }
    assert.equal(pricesFrom({ prices: { ...P, [field]: [[cap, 1]] } }).ok, true);
    assert.equal(pricesFrom({ prices: { ...P, [field]: [[1, 1], [cap - 1, 1]] } }).ok, true);
  }
});

test('banded: the price page’s own worked examples, to the cent', () => {
  // REST, US East: 333M at $3.50 + 667M at $2.80 + 14B at $2.38 = $36,353.10
  assert.equal(banded(15000000000, P.restBands) / 1e6, 3635310);
  // HTTP: 300M at $1.00 + 132M at $0.90 = $418.80
  assert.equal(banded(432000000, P.httpBands) / 1e6, 41880);
  // HTTP: 9.72M at $1.00 = $9.72
  assert.equal(banded(9720000, P.httpBands) / 1e6, 972);
});

test('banded: each tier boundary, exactly', () => {
  assert.equal(banded(0, P.restBands), 0);
  assert.equal(banded(1, P.restBands), 350);
  assert.equal(banded(333000000, P.restBands), 333000000 * 350);
  assert.equal(banded(333000001, P.restBands), 333000000 * 350 + 280);
  assert.equal(banded(1000000000, P.restBands), 333000000 * 350 + 667000000 * 280);
  assert.equal(banded(1000000001, P.restBands), 333000000 * 350 + 667000000 * 280 + 238);
  assert.equal(banded(300000001, P.httpBands), 300000000 * 100 + 90);
  assert.equal(banded(15000000001, P.restBands), null);
  assert.equal(banded(5, [[3, 10]]), null);
  assert.equal(banded(3, [[3, 10]]), 30);
});

test('banded is total: junk is null', () => {
  for (const [n, b] of [[-1, P.restBands], [1.5, P.restBands], ['5', P.restBands], [null, P.restBands], [5, null], [5, 'x'], [5, [7]], [5, [null]]]) {
    assert.equal(banded(n, b), null, JSON.stringify([n, b]));
  }
});

test('nodesFor: a node a month carries rate × hours × 3600 records, and never fewer than one node', () => {
  const cap = 100 * 730 * 3600;
  assert.equal(nodesFor(0, 100, 730), 1);
  assert.equal(nodesFor(cap, 100, 730), 1);
  assert.equal(nodesFor(cap + 1, 100, 730), 2);
  assert.equal(nodesFor(cap * 3, 100, 730), 3);
  assert.equal(nodesFor(1, 1, 1), 1);
  for (const [n, r, h] of [[-1, 100, 730], [1.5, 100, 730], [5, 0, 730], [5, -1, 730], [5, 1.5, 730], [5, 100, 0], [5, 100, 2.5], [null, 1, 1]]) {
    assert.equal(nodesFor(n, r, h), null, JSON.stringify([n, r, h]));
  }
});

test('AWS WAF Case A, as the page works it: one web ACL, 19 rules, 10 million requests = $30.00', () => {
  const r = run({});
  assert.equal(r.ok, true);
  assert.deepEqual(r.managed, { wafCents: 3000, gatewayCents: 0, totalCents: 3000, totalPence: Math.round(3000 * 10000 / 13363) });
  assert.equal(r.managed.totalPence, 2245);
});

test('the gateway adds its tiered line; none adds nothing', () => {
  assert.equal(run({ api: 'rest' }).managed.gatewayCents, 3500);
  assert.equal(run({ api: 'http' }).managed.gatewayCents, 1000);
  assert.equal(run({ api: 'rest' }).managed.totalCents, 6500);
  assert.equal(run({ api: 'rest' }).managed.totalPence, 4864);
  assert.equal(run({ api: 'none' }).managed.gatewayCents, 0);
});

test('no web ACL means no WAF line at all; a rule without an ACL is refused', () => {
  const r = run({ acls: 0, rules: 0, api: 'http' });
  assert.equal(r.managed.wafCents, 0);
  assert.equal(r.managed.totalCents, 1000);
  assert.deepEqual(run({ acls: 0, rules: 1 }), { ok: false, why: 'a rule lives in a web ACL: rules need at least one' });
  assert.equal(run({ acls: 1, rules: 0 }).managed.wafCents, 500 + 600);
  assert.equal(run({ acls: 2, rules: 3, requests: 1000000 }).managed.wafCents, 1000 + 300 + 60);
});

test('the node’s electricity: nodes × watts × hours at the Ofgem cap, rounded once', () => {
  const r = run({});
  assert.equal(r.node.nodes, 1);
  assert.equal(r.node.electricityPence, Math.round(55 * 730 * 2632 / 100000));
  assert.equal(r.node.electricityPence, 1057);
  assert.equal(r.node.machinePence, 0);
  assert.equal(r.node.totalPence, 1057);
  const two = run({ requests: 100 * 730 * 3600 + 1 });
  assert.equal(two.node.nodes, 2);
  assert.equal(two.node.electricityPence, Math.round(2 * 55 * 730 * 2632 / 100000));
  assert.equal(run({ watts: 15 }).node.electricityPence, Math.round(15 * 730 * 2632 / 100000));
});

test('a machine the buyer has to buy is spread over its life, per node', () => {
  assert.equal(run({ machinePence: 120000, lifeMonths: 36 }).node.machinePence, 3333);
  assert.equal(run({ machinePence: 120000, lifeMonths: 36 }).node.totalPence, 1057 + 3333);
  assert.equal(run({ machinePence: 120000, lifeMonths: 36, requests: 100 * 730 * 3600 + 1 }).node.machinePence, 6667);
});

test('staff time is the buyer’s three figures: hours × rate × the share removed', () => {
  assert.equal(run({ staffHours: 10, staffRatePence: 5000, staffShare: 50 }).staffPence, 25000);
  assert.equal(run({ staffHours: 10, staffRatePence: 5000, staffShare: 0 }).staffPence, 0);
  assert.equal(run({ staffHours: 3, staffRatePence: 1001, staffShare: 33 }).staffPence, Math.round(3 * 1001 * 33 / 100));
});

test('the bottom line is managed − node + staff, a month and a year, and may be negative', () => {
  const r = run({ api: 'rest', staffHours: 10, staffRatePence: 5000, staffShare: 50 });
  assert.equal(r.monthlyPence, 4864 - 1057 + 25000);
  assert.equal(r.yearlyPence, (4864 - 1057 + 25000) * 12);
  const low = run({ requests: 0, acls: 0, rules: 0, api: 'none' });
  assert.equal(low.monthlyPence, -1057);
  assert.equal(low.yearlyPence, -1057 * 12);
});

test('every input: its range edges are accepted, one past them refused with a reason', () => {
  for (const [k, [lo, hi]] of Object.entries(RANGES)) {
    const extra = k === 'acls' ? { rules: 0 } : {};
    const fits = (v) => run({ ...extra, [k]: v });
    const why = k + ' must be a whole number from ' + lo + ' to ' + hi;
    assert.equal(fits(hi).ok, true, k + ' at ' + hi);
    assert.equal(fits(lo).ok, true, k + ' at ' + lo);
    assert.deepEqual(fits(lo - 1), { ok: false, why }, k + ' below');
    assert.deepEqual(fits(hi + 1), { ok: false, why }, k + ' above');
    assert.deepEqual(fits(lo + 0.5), { ok: false, why }, k + ' fractional');
    assert.deepEqual(fits(String(lo)), { ok: false, why }, k + ' as text');
  }
  assert.equal(run({ requests: 15000000000, rate: 1000000 }).ok, true);
});

test('api must be one of the three; junk inputs and junk prices are reasons, never throws', () => {
  assert.deepEqual(API, ['rest', 'http', 'none']);
  for (const a of ['REST', '', null, 1]) assert.deepEqual(run({ api: a }), { ok: false, why: 'api is rest, http or none' });
  for (const junk of [null, undefined, 5, 'x']) assert.deepEqual(costCase(junk, P), { ok: false, why: 'no inputs' });
  assert.deepEqual(costCase(BASE, null), { ok: false, why: 'prices: no prices' });
  assert.equal(costCase(BASE, { ...P, fx10k: 0 }).why, 'prices: fx10k is not a positive integer');
});

test('more nodes than the cap is refused: the sums stay exact integers', () => {
  const r = run({ requests: 15000000000, rate: 1, hours: 1 });
  assert.deepEqual(r, { ok: false, why: 'that volume needs more than 100000 nodes at this rate: check the rate' });
  const edge = 100000 * 3600;
  assert.equal(run({ requests: edge, rate: 1, hours: 1 }).node.nodes, 100000);
  assert.equal(run({ requests: edge + 1, rate: 1, hours: 1 }).ok, false);
});

test('every number the case returns is a safe integer, at the largest inputs', () => {
  const r = run({ requests: 15000000000, acls: 100, rules: 1000, api: 'rest', rate: 1000000, watts: 2000, hours: 744, fx10k: 1000,
    machinePence: 1000000000, lifeMonths: 1, staffHours: 10000, staffRatePence: 100000, staffShare: 100 });
  assert.equal(r.ok, true);
  const walk = (o) => Object.values(o).forEach((v) => (typeof v === 'object' ? walk(v) : assert.ok(Number.isSafeInteger(v), String(v))));
  const { ok, ...nums } = r;
  assert.equal(ok, true);
  walk(nums);
});
