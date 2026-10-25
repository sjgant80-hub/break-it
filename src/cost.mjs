// ════════════════════════════════════════════════════════════════
// cost.mjs — the CFO's line. What the managed-cloud path in front of an ingest feed costs a month, set against what
// break-it nodes cost to run, from the buyer's OWN volumes and the dated public list prices in costs/sources.json.
// Pure, total, integers only (US cents, pence, hundredths of a penny): junk in is a reason out, never a throw or NaN.
//
//   pricesFrom(json)          → { ok, prices } | { ok:false, why }     the committed source file, checked field by field
//   banded(requests, bands)   → millionths of a cent for a tiered per-million price, or null past the last band
//   nodesFor(requests, rate, hours) → how many nodes carry that volume at a measured rate (records a second each)
//   costCase(inputs, prices)  → { ok, managed, node, staffPence, monthlyPence, yearlyPence } | { ok:false, why }
//
// The managed path is AWS WAF (web ACLs + rules + per-request) plus, if the buyer runs one, API Gateway (REST or HTTP).
// The node path is electricity at the Ofgem cap for as many nodes as the measured rate needs, plus the buyer's own
// machine cost spread over its life (0 when it runs on hardware they already own). Staff time the journal's automatic
// classification removes is the buyer's own three figures. A negative monthlyPence is reported as it is: the case
// can come out against the node, and the page says so.
// ════════════════════════════════════════════════════════════════

export const API = Object.freeze(['rest', 'http', 'none']);
export const RANGES = Object.freeze({
  requests: [0, 15000000000], acls: [0, 100], rules: [0, 1000], rate: [1, 1000000], watts: [1, 2000], hours: [1, 744],
  fx10k: [1000, 100000], machinePence: [0, 1000000000], lifeMonths: [1, 120], staffHours: [0, 10000], staffRatePence: [0, 100000], staffShare: [0, 100],
});
const MILLION = 1000000;
export const MAX_NODES = 100000;                                 // past this the rate is wrong, and the sums would leave exact integers
const isInt = (n) => Number.isSafeInteger(n);
const within = (n, [lo, hi]) => isInt(n) && n >= lo && n <= hi;
const posInt = (n) => isInt(n) && n > 0;

function bandsOk(b, total) {
  if (!Array.isArray(b) || b.length < 1) return false;
  let sum = 0;
  for (const x of b) {
    if (!Array.isArray(x) || x.length !== 2 || !posInt(x[0]) || !posInt(x[1])) return false;
    sum += x[0];
  }
  return sum === total;
}

/** The committed costs/sources.json, checked: every price a positive integer, every tier table covering the cap. */
export function pricesFrom(json) {
  const p = json && typeof json === 'object' ? json.prices : null;
  if (!p || typeof p !== 'object') return { ok: false, why: 'no prices' };
  for (const k of ['wafAclCents', 'wafRuleCents', 'wafPerMillionCents', 'maxRequests', 'unitRateCentiPence', 'fx10k', 'laptopBaseWatts', 'laptopMaxWatts', 'breachUsd']) {
    if (!posInt(p[k])) return { ok: false, why: k + ' is not a positive integer' };
  }
  if (p.maxRequests !== RANGES.requests[1]) return { ok: false, why: 'maxRequests is not the calculator’s cap' };
  if (!bandsOk(p.restBands, p.maxRequests)) return { ok: false, why: 'restBands do not cover 0 to maxRequests' };
  if (!bandsOk(p.httpBands, p.maxRequests)) return { ok: false, why: 'httpBands do not cover 0 to maxRequests' };
  return { ok: true, prices: p };
}

/** A tiered per-million price over `requests`, in millionths of a cent (exact). null if it runs past the last band. */
export function banded(requests, bands) {
  if (!isInt(requests) || requests < 0 || !Array.isArray(bands)) return null;
  let left = requests, sum = 0;
  for (const b of bands) {
    if (!Array.isArray(b)) return null;
    const take = Math.min(left, b[0]);
    sum += take * b[1];
    left -= take;
  }
  return left === 0 ? sum : null;
}

/** Nodes needed to carry `requests` a month when each sustains `rate` records a second for `hours` hours. At least 1. */
export function nodesFor(requests, rate, hours) {
  if (!isInt(requests) || requests < 0 || !posInt(rate) || !posInt(hours)) return null;
  return Math.max(1, Math.ceil(requests / (rate * hours * 3600)));
}

/** The case, a month at a time, from the buyer's inputs and the checked prices. */
export function costCase(inputs, prices) {
  const i = inputs && typeof inputs === 'object' ? inputs : null;
  if (!i) return { ok: false, why: 'no inputs' };
  const checked = pricesFrom({ prices });
  if (!checked.ok) return { ok: false, why: 'prices: ' + checked.why };
  for (const k of Object.keys(RANGES)) {
    if (!within(i[k], RANGES[k])) return { ok: false, why: k + ' must be a whole number from ' + RANGES[k][0] + ' to ' + RANGES[k][1] };
  }
  if (!API.includes(i.api)) return { ok: false, why: 'api is rest, http or none' };
  if (i.acls === 0 && i.rules > 0) return { ok: false, why: 'a rule lives in a web ACL: rules need at least one' };

  const p = prices;
  const wafMicro = i.acls === 0 ? 0 : i.acls * p.wafAclCents * MILLION + i.rules * p.wafRuleCents * MILLION + i.requests * p.wafPerMillionCents;
  const gwMicro = i.api === 'none' ? 0 : banded(i.requests, i.api === 'rest' ? p.restBands : p.httpBands);
  const wafCents = Math.round(wafMicro / MILLION), gatewayCents = Math.round(gwMicro / MILLION);
  const totalCents = wafCents + gatewayCents;
  const managed = { wafCents, gatewayCents, totalCents, totalPence: Math.round((totalCents * 10000) / i.fx10k) };

  const nodes = nodesFor(i.requests, i.rate, i.hours);
  if (nodes > MAX_NODES) return { ok: false, why: 'that volume needs more than ' + MAX_NODES + ' nodes at this rate: check the rate' };
  const electricityPence = Math.round((nodes * i.watts * i.hours * p.unitRateCentiPence) / 100000);
  const machinePence = Math.round((nodes * i.machinePence) / i.lifeMonths);
  const node = { nodes, electricityPence, machinePence, totalPence: electricityPence + machinePence };

  const staffPence = Math.round((i.staffHours * i.staffRatePence * i.staffShare) / 100);
  const monthlyPence = managed.totalPence - node.totalPence + staffPence;
  return { ok: true, managed, node, staffPence, monthlyPence, yearlyPence: monthlyPence * 12 };
}
