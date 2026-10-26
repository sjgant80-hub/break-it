// ════════════════════════════════════════════════════════════════
// core/relay.mjs — a relay of the mesh: it carries bytes to the node a frame names, and holds them a while for a node
// that is away. Organ 6 of the shared foundation (Phase 3, pass 1: claims R1–R3 in core/phase3/claims.json).
//
// Transport, not trust. A relay reads one thing, the recipient's id on the frame, and never a body: every body is a
// LIGHT packet the sending node signed, and the receiving node's own door decides on it. So a relay that drops,
// reorders, repeats or lies costs delivery, never safety. It keeps no app state: who is connected, and a bounded
// queue of frames for nodes that are not. Kill one, and its nodes carry on through another.
//
//   frameOf(kind, id, bytes)   → bytes   'LRY1' · kind (1 hello, 2 send, 3 deliver) · 32-byte node id · u32 n · n bytes
//   createReader()             → { push(chunk) → { ok, frames } | { ok: false, why } }   a TCP stream, cut into frames
//   createRelay(opts)          → { open(conn), close(conn), take(conn, frame, now) → [{ conn, bytes }], stats() }
//        opts = { maxQueue (frames held per absent node, default 256), ttlMs (default 10 minutes), repeat (1, or 2 to
//        deliver every held frame twice: a faulty relay, for the measurement of the node's door) }
//
// Pure: no sockets, no clock of its own (the caller passes now), no crypto, no codec. Junk is refused, never thrown.
// Powered by the Konomi architecture, created by Thomas Frumkin.
// ════════════════════════════════════════════════════════════════

export const MAGIC = Object.freeze([0x4c, 0x52, 0x59, 0x31]);   // 'LRY1'
export const KIND = Object.freeze({ HELLO: 1, SEND: 2, DELIVER: 3 });
export const HEAD = 41, MAX_FRAME = 1 << 20;
const isBytes = (x) => x instanceof Uint8Array;
const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

/** One frame. id is the 32-byte key of the node it is for (or, for hello, the node saying hello). → Uint8Array | null */
export function frameOf(kind, id, bytes) {
  if (kind !== KIND.HELLO && kind !== KIND.SEND && kind !== KIND.DELIVER) return null;
  const body = bytes === undefined ? new Uint8Array(0) : bytes;
  if (!isBytes(id) || id.length !== 32 || !isBytes(body) || body.length > MAX_FRAME) return null;
  const out = new Uint8Array(HEAD + body.length);
  out.set(MAGIC, 0); out[4] = kind; out.set(id, 5);
  new DataView(out.buffer).setUint32(37, body.length);
  out.set(body, HEAD);
  return out;
}

/** A stream of chunks, cut into whole frames. A stream that is not frames is refused, and stays refused. */
export function createReader() {
  let buf = new Uint8Array(0), broken = null;
  return {
    push(chunk) {
      if (broken !== null) return { ok: false, why: broken };
      if (!isBytes(chunk)) { broken = 'not bytes'; return { ok: false, why: broken }; }
      const next = new Uint8Array(buf.length + chunk.length);
      next.set(buf, 0); next.set(chunk, buf.length);
      buf = next;
      const frames = [];
      while (buf.length >= HEAD) {
        if (!MAGIC.every((m, i) => buf[i] === m)) { broken = 'not a relay frame'; return { ok: false, why: broken }; }
        const kind = buf[4], n = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(37);
        if (kind !== KIND.HELLO && kind !== KIND.SEND && kind !== KIND.DELIVER) { broken = 'kind ' + kind + ' is not a relay frame'; return { ok: false, why: broken }; }
        if (n > MAX_FRAME) { broken = 'a frame of ' + n + ' bytes is too long'; return { ok: false, why: broken }; }
        if (buf.length < HEAD + n) break;
        frames.push({ kind, id: buf.slice(5, 37), bytes: buf.slice(HEAD, HEAD + n) });
        buf = buf.slice(HEAD + n);
      }
      return { ok: true, frames };
    },
  };
}

/** A relay: who is here, and what waits for who is not. */
export function createRelay(opts) {
  const o = opts !== null && typeof opts === 'object' ? opts : {};
  const maxQueue = Number.isSafeInteger(o.maxQueue) && o.maxQueue > 0 ? o.maxQueue : 256;
  const ttlMs = Number.isSafeInteger(o.ttlMs) && o.ttlMs > 0 ? o.ttlMs : 600000;
  const repeat = o.repeat === 2 ? 2 : 1;
  const conns = new Map(), online = new Map(), queues = new Map();
  const s = { frames: 0, delivered: 0, queued: 0, lateDelivered: 0, expired: 0, dropped: 0, refused: 0 };
  const deliver = (conn, bytes) => ({ conn, bytes: frameOf(KIND.DELIVER, conns.get(conn).idRaw, bytes) });
  return {
    open(conn) { if (!conns.has(conn)) conns.set(conn, { id: null, idRaw: null }); },
    close(conn) {
      const c = conns.get(conn);
      if (c && c.id !== null && online.get(c.id) === conn) online.delete(c.id);
      conns.delete(conn);
    },
    take(conn, f, now) {
      const c = conns.get(conn);
      if (!c || f === null || typeof f !== 'object' || !isBytes(f.id) || f.id.length !== 32 || !isBytes(f.bytes) || !Number.isSafeInteger(now)) { s.refused++; return []; }
      s.frames++;
      const id = hex(f.id);
      if (f.kind === KIND.HELLO) {
        if (c.id !== null && online.get(c.id) === conn) online.delete(c.id);
        c.id = id; c.idRaw = f.id; online.set(id, conn);
        const q = queues.get(id) || [];
        queues.delete(id);
        const out = [];
        for (const item of q) {
          if (now - item.at > ttlMs) { s.expired++; continue; }
          for (let k = 0; k < repeat; k++) { out.push(deliver(conn, item.bytes)); s.lateDelivered++; }
        }
        return out;
      }
      if (f.kind === KIND.SEND) {
        const to = online.get(id);
        if (to !== undefined) { s.delivered++; return [deliver(to, f.bytes)]; }
        const q = queues.get(id) || [];
        q.push({ bytes: f.bytes, at: now });
        if (q.length > maxQueue) { q.shift(); s.dropped++; }
        queues.set(id, q);
        s.queued++;
        return [];
      }
      s.refused++;   // a node does not send DELIVER to a relay
      return [];
    },
    stats() { return { ...s, online: online.size, waiting: [...queues.values()].reduce((a, q) => a + q.length, 0) }; },
  };
}
