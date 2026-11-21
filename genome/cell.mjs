// cell.mjs — BREAK IT's three answers for the birth check (seed.json, genome/).
//
// judge  a claimed gate decision for one raw packet is verified when BREAK IT's own gate, decide() from src/gate.mjs,
//        run with the pinned key table (src/keys.mjs keyTable) and the senders' last counters, stops the packet at
//        the same stage or admits it. Unverified when it does not. Refused when the input is out of lane or the claim
//        is not one of the gate's stages. The birth check's bad case is what the gate exists to stop: a packet signed
//        by the pinned sender, then changed by one byte, claimed admitted.
// lane   one packet as raw bytes in lower-case hex, a non-empty pinned key table that keyTable() accepts, and the
//        senders' last admitted counters (optional; whole numbers, as text or numbers). An already-parsed record is
//        out of lane and goes to Kar: the gate vouches for bytes before parsing, never for a record that skipped it.
import { decide, STAGES } from '../src/gate.mjs';
import { keyTable } from '../src/keys.mjs';

const HEX = /^(?:[0-9a-f]{2})+$/;
const COUNTER = /^[0-9]+$/;
const isObj = (o) => o !== null && typeof o === 'object' && !Array.isArray(o);

// table(pinned) → the kernel's own pinned key table, or null when keyTable() refuses the keys
const table = (pinned) => { try { return keyTable(pinned); } catch { return null; } };

// stage(input) → where the gate stops the packet, or 'admitted'
export function stage(input) {
  const t = keyTable(input.pinned), last = input.last ?? {};
  return decide(new Uint8Array(Buffer.from(input.packet, 'hex')),
    { keyFor: t.keyFor, verify: t.verify, lastCounter: (s) => BigInt(last[s] ?? 0) }).stage;
}

export async function judge(input) {
  if (!(await inLane(input)) || !STAGES.includes(input.claim)) return 'refused';
  return stage(input) === input.claim ? 'verified' : 'unverified';
}

export async function inLane(input) {
  return typeof input?.packet === 'string' && HEX.test(input.packet)
    && isObj(input.pinned) && Object.keys(input.pinned).length > 0 && table(input.pinned) !== null
    && (input.last === undefined || (isObj(input.last) && Object.values(input.last).every((v) => COUNTER.test(String(v)))));
}

// health: the gate's receipts (pilot, herd, tarpit) are re-checked in CI, but from inside the repository it cannot see
// who runs a node or when one last refused a real attack, so it says so
export async function health() {
  return { used: null, dependedOn: null, lastEarned: null };
}
