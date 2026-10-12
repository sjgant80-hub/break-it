// ledger.mjs — the append-only ledger on disk: one JSON line per admitted packet, hash-chained (chain.mjs), written
// and fsync'd BEFORE the app acts. One writer at a time (an exclusive lock file); a second server on the same ledger
// refuses to start. At start-up every line is read back and the whole chain checked — a single altered byte refuses
// the start (the server then re-runs every packet through the gate, so the ledger can only ever hold packets the
// gate would admit). A torn final line — a crash mid-write, never acknowledged — is the one thing trimmed.
// The attack journal (journal.mjs) uses the same chain, in its own file.
import { openSync, closeSync, writeSync, fsyncSync, readFileSync, existsSync, mkdirSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { GENESIS, entryFor, verifyChain } from './chain.mjs';

export const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
const hex = (u8) => Buffer.from(u8).toString('hex');

const HELD = new Set();                                         // locks THIS process holds (a pid alone cannot tell two opens apart)
function takeLock(lockPath) {
  if (HELD.has(lockPath)) return false;
  try {
    const fd = openSync(lockPath, 'wx');
    writeSync(fd, String(process.pid)); closeSync(fd);
    HELD.add(lockPath);
    return true;
  } catch {
    // a lock left by a process that is gone is stale; a live holder keeps it (our own pid here, not in HELD, is a
    // dead process whose pid we happen to have been given)
    let pid = NaN;
    try { pid = Number(readFileSync(lockPath, 'utf8')); } catch { return false; }
    let alive = true;
    try { process.kill(pid, 0); } catch { alive = false; }
    if (alive && pid !== process.pid) return false;
    try { unlinkSync(lockPath); } catch { return false; }
    return takeLock(lockPath);
  }
}
const dropLock = (lockPath) => { HELD.delete(lockPath); try { unlinkSync(lockPath); } catch { /* ignore */ } };

/** Read and check a chain file. → { ok, entries, head, trimmed } or { ok:false, reason }. */
export function loadChain(path) {
  if (!existsSync(path)) return { ok: true, entries: [], head: GENESIS, trimmed: false };
  let text = readFileSync(path, 'utf8');
  let trimmed = false;
  if (text.length && !text.endsWith('\n')) {                  // a torn final write: never acknowledged, so dropped
    const cut = text.lastIndexOf('\n') + 1;
    truncateSync(path, Buffer.byteLength(text.slice(0, cut)));
    text = text.slice(0, cut); trimmed = true;
  }
  const lines = text.split('\n').filter((l) => l.length);
  const entries = [];
  for (let i = 0; i < lines.length; i++) {
    try { entries.push(JSON.parse(lines[i])); } catch { return { ok: false, reason: 'line ' + i + ' is not JSON' }; }
  }
  const v = verifyChain(entries, sha256hex);
  return v.ok ? { ok: true, entries, head: v.head, trimmed } : { ok: false, reason: v.reason };
}

/** Open a chain file for appending, under an exclusive lock. */
export function openChain(path) {
  mkdirSync(dirname(path), { recursive: true });
  const lockPath = resolve(path) + '.lock';
  if (!takeLock(lockPath)) return { ok: false, reason: 'another process holds ' + lockPath + ' — one writer at a time' };
  const loaded = loadChain(path);
  if (!loaded.ok) { dropLock(lockPath); return { ok: false, reason: 'the chain at ' + path + ' does not verify: ' + loaded.reason }; }
  if (!existsSync(path)) writeFileSync(path, '');
  const fd = openSync(path, 'a');
  let head = loaded.head, seq = loaded.entries.length;
  return {
    ok: true, entries: loaded.entries, trimmed: loaded.trimmed,
    get head() { return head; }, get length() { return seq; },
    /** Append one packet: written and fsync'd before this returns. */
    append(packet) {
      const e = entryFor(head, seq, hex(packet), sha256hex);
      if (!e) throw new Error('refusing to append a malformed entry');
      writeSync(fd, JSON.stringify(e) + '\n');
      fsyncSync(fd);
      head = e.hash; seq += 1;
      return e;
    },
    close() { try { closeSync(fd); } catch { /* ignore */ } dropLock(lockPath); },
  };
}
