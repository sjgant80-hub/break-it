// journal.mjs — the attack journal: every refusal, written down, tamper-evident, bounded. It is what the immune
// system feeds on (immune.mjs) and where vaccines come from (tools/vaccinate.mjs).
//
// One JSON line per record, hash-chained like the ledger but in its own file and its own domain, so an attacker can
// neither edit their history out nor pass a journal line off as a ledger entry. Attacker bytes are stored as hex —
// never decoded, never parsed, never rendered as HTML. Bounded three ways: at most RAW_CAP bytes of any one attack
// are kept; a source the immune system has at BLOCK/ISOLATE is recorded as a count, not in full (except a NOVEL
// attack, which is always kept whole — it is a vaccine); and past FILE_CAP only novel attacks are written at all.
// A novel record is fsync'd before the node answers; repeats are written but ride the OS cache, so a flood of known
// attacks cannot turn into a flood of disk syncs. A crash mid-write leaves a torn last line, which is trimmed.
import { openSync, closeSync, writeSync, fsyncSync, readFileSync, existsSync, mkdirSync, writeFileSync, unlinkSync, truncateSync } from 'node:fs';
import { dirname } from 'node:path';
import { sha256hex } from './ledger.mjs';

export const RAW_CAP = 1024, FILE_CAP = 256 * 1024 * 1024, TAIL = 5000;
const GENESIS = '0'.repeat(64);
const FIELDS = ['seq', 'prev', 'at', 'source', 'stage', 'reason', 'family', 'print', 'novel', 'detail', 'size', 'bytes', 'context'];

const canonical = (r) => JSON.stringify(FIELDS.map((k) => [k, r[k] === undefined ? null : r[k]]));
const hashOf = (r) => sha256hex('BREAK-IT/journal/v1|' + canonical(r));

/** Check a journal file's chain. → { ok, records, head } | { ok:false, reason } */
export function loadJournal(path) {
  if (!existsSync(path)) return { ok: true, records: [], head: GENESIS, trimmed: false, bytes: 0 };
  let text = readFileSync(path, 'utf8');
  let trimmed = false;
  if (text.length && !text.endsWith('\n')) { text = text.slice(0, text.lastIndexOf('\n') + 1); trimmed = true; }   // a torn final write
  const lines = text.split('\n').filter((l) => l.length);
  const records = [];
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let r;
    try { r = JSON.parse(lines[i]); } catch { return { ok: false, reason: 'journal line ' + i + ' is not JSON' }; }
    const { hash, ...rest } = r;
    if (rest.seq !== i || rest.prev !== prev || hashOf(rest) !== hash) return { ok: false, reason: 'journal line ' + i + ' has been altered or reordered' };
    records.push(r); prev = hash;
  }
  return { ok: true, records, head: prev, trimmed, bytes: Buffer.byteLength(text) };
}

/** Open the journal for appending. A journal that does not verify is moved aside (never trusted, never lost). */
export function openJournal(path) {
  mkdirSync(dirname(path), { recursive: true });
  let loaded = loadJournal(path);
  if (!loaded.ok) {
    const aside = path + '.broken-' + process.pid + '-' + Date.now();
    writeFileSync(aside, readFileSync(path)); unlinkSync(path);
    loaded = { ok: true, records: [], head: GENESIS, movedAside: aside };
  }
  if (!existsSync(path)) writeFileSync(path, '');
  if (loaded.trimmed) truncateSync(path, loaded.bytes);
  const fd = openSync(path, 'a');
  let size = loaded.bytes || 0;
  let head = loaded.head, seq = loaded.records.length;
  const tail = loaded.records.slice(-TAIL);
  return {
    records: loaded.records, movedAside: loaded.movedAside || null,
    /** The most recent records (at most TAIL kept in memory), from seq `since`. */
    tail(since, limit) { return tail.filter((r) => r.seq >= since).slice(0, limit); },
    get length() { return seq; },
    /** Write one refusal. bytes: the raw attack (hex, capped). context: what a vaccine needs to replay it. */
    record({ at, source, stage, reason, family, print, novel, detail, bytes, context }) {
      if (size > FILE_CAP && novel !== true) return null;
      const raw = bytes instanceof Uint8Array ? bytes : new Uint8Array(0);
      const r = {
        seq, prev: head, at: String(at), source: String(source).slice(0, 64), stage: String(stage), reason: String(reason).slice(0, 200),
        family: String(family), print: String(print).slice(0, 128), novel: novel === true, detail: detail === 'count' ? 'count' : 'full',
        size: raw.length, bytes: detail === 'count' ? '' : Buffer.from(raw.subarray(0, RAW_CAP)).toString('hex'),
        context: context && typeof context === 'object' ? context : null,
      };
      const line = { ...r, hash: hashOf(r) };
      const text = JSON.stringify(line) + '\n';
      writeSync(fd, text); size += Buffer.byteLength(text);
      if (line.novel) fsyncSync(fd);                             // a vaccine is forced to disk; the rest ride the OS cache
      head = line.hash; seq += 1;
      tail.push(line); if (tail.length > TAIL) tail.shift();
      return line;
    },
    close() { try { closeSync(fd); } catch { /* ignore */ } },
  };
}
