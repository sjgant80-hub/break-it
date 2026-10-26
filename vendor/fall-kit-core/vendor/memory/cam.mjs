// cam.mjs — GOLDEN-ANGLE CAM · content-addressable memory by locality-on-a-sphere.
//
// Keys are directions on the unit sphere; similar keys point the same way. The index is a Fibonacci-sphere
// LATTICE of M cells spaced by the GOLDEN ANGLE (§1 · θ=137.5°=π(3−√5), the maximally-irrational angle).
// That spacing is the whole point: every cell covers ≈ EQUAL AREA, so buckets stay BALANCED for data spread
// over the sphere — unlike a naive lat/long grid, which piles points up at the poles (equirectangular
// distortion). Balanced buckets → retrieval touches only a few cells → SUB-LINEAR scan.
//
// HONEST SCOPE: this is NOT O(1), and NOT exact semantic search. It is approximate-nearest-neighbour by
// directional bucketing; the golden angle buys BALANCE (even load), which buys sub-linear candidate sets
// (~O(√N) with M≈√N cells). The gate measures the real recall + fraction-scanned and never claims O(1).
// Pure, zero-dep, Node + browser.

export const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));   // ≈ 2.39996 rad = 137.5077°

const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
export function unit(v) { const n = Math.hypot(v[0], v[1], v[2]) || 1; return [v[0] / n, v[1] / n, v[2] / n]; }

// M cell-centres, golden-angle Fibonacci spiral on the sphere → ≈ equal-area, no clustering.
export function fibLattice(M) {
  const cells = [];
  for (let i = 0; i < M; i++) {
    const y = 1 - 2 * (i + 0.5) / M, r = Math.sqrt(Math.max(0, 1 - y * y)), phi = i * GOLDEN_ANGLE;
    cells.push([r * Math.cos(phi), y, r * Math.sin(phi)]);
  }
  return cells;
}

// the P cells whose centres are nearest the query direction (largest dot product)
function nearestCells(cells, v, P) {
  const scored = cells.map((c, i) => [dot(c, v), i]);
  scored.sort((a, b) => b[0] - a[0]);
  return scored.slice(0, P).map(s => s[1]);
}

export function cam({ cells = 4096 } = {}) {
  const M = typeof cells === 'number' ? cells : cells.length;
  const lattice = typeof cells === 'number' ? fibLattice(cells) : cells;
  const buckets = new Map();          // cellIdx -> [{ id, v, meta }]
  const items = new Map();            // id -> { id, v, meta, cell }

  function insert(id, vec, meta = {}) {
    const v = unit(vec), cell = nearestCells(lattice, v, 1)[0];
    const rec = { id: String(id), v, meta, cell };
    items.set(rec.id, rec);
    if (!buckets.has(cell)) buckets.set(cell, []);
    buckets.get(cell).push(rec);
    return rec;
  }

  // query: gather candidates from the `probe` nearest cells, rank by cosine, return top-k + how much we scanned
  function query(vec, { k = 5, probe = 8 } = {}) {
    const v = unit(vec), cellIdxs = nearestCells(lattice, v, probe);
    let candidates = [];
    for (const c of cellIdxs) for (const rec of (buckets.get(c) || [])) candidates.push(rec);
    const ranked = candidates.map(r => ({ id: r.id, v: r.v, meta: r.meta, cos: dot(r.v, v) })).sort((a, b) => b.cos - a.cos).slice(0, k);
    return { results: ranked, scanned: candidates.length, of: items.size };
  }

  // brute-force exact top-k (for measuring recall against)
  function exact(vec, k = 5) {
    const v = unit(vec);
    return [...items.values()].map(r => ({ id: r.id, cos: dot(r.v, v) })).sort((a, b) => b.cos - a.cos).slice(0, k).map(x => x.id);
  }

  function loads() { return [...buckets.values()].map(b => b.length); }
  const stats = () => ({ M, N: items.size, filledCells: buckets.size });
  return { insert, query, exact, loads, stats, lattice, get items() { return items; } };
}

// a naive lat/long grid index of ~M cells — the BASELINE the golden angle beats on balance (poles clump).
export function latLonCell(v, M) {
  const nLon = Math.max(1, Math.round(Math.sqrt(M))), nLat = Math.max(1, Math.round(M / nLon));
  const u = unit(v);
  const lat = Math.acos(Math.min(1, Math.max(-1, u[1])));          // 0..π
  const lon = Math.atan2(u[2], u[0]) + Math.PI;                    // 0..2π
  const li = Math.min(nLat - 1, Math.floor(lat / Math.PI * nLat));
  const oi = Math.min(nLon - 1, Math.floor(lon / (2 * Math.PI) * nLon));
  return li * nLon + oi;
}

// coefficient of variation (std/mean) of an array — 0 = perfectly balanced, higher = more clumped
export function cv(arr) {
  if (!arr.length) return 0;
  const mean = arr.reduce((s, x) => s + x, 0) / arr.length;
  const varr = arr.reduce((s, x) => s + (x - mean) ** 2, 0) / arr.length;
  return mean ? Math.sqrt(varr) / mean : 0;
}

export default { GOLDEN_ANGLE, unit, fibLattice, cam, latLonCell, cv };
