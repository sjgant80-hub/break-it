// ════════════════════════════════════════════════════════════════
// node/breakit-node.mjs — break-it as a cell of the one body: the ingest gateway, offering its gate on the estate's
// shared foundation (vendor/fall-kit-core, copied verbatim from fall-kit/core and pinned).
//
// Its skill is `screen`: hand it the bytes of a BRK1 packet (as hex) and break-it's own gate (src/gate.mjs) decides,
// against break-it's committed pinned key table (config/pubkeys.json), whether it is a well-formed BRK1 packet signed
// by a pinned sender — and at which stage it fails if not. The screen is STATELESS: it checks size, magic, schema,
// sender and signature, and takes the packet's own counter as the next one, because a screen holds no counter store
// (the live gateway does; see src/server.mjs). The answer carries a receipt the asker can re-hash. The node is also the
// estate's immune hub: what its door refuses becomes an antibody it can share.
// ════════════════════════════════════════════════════════════════
import { createNode } from '../vendor/fall-kit-core/node.mjs';
import { verifyBytes, hex } from '../vendor/fall-kit-core/identity.mjs';
import { sha256 } from '../vendor/fall-kit-core/vendor/light/sha256.mjs';
import { decide } from '../src/gate.mjs';
import { rawCheck, headerOf, signedBytes } from '../src/wire.mjs';

export const NAME = 'break-it';
const HEX = /^(?:[0-9a-f]{2})+$/;
const shaHex = (bytes) => hex(sha256(bytes));
const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));

/** The screen, as a pure-ish function of the pinned table: bytes → break-it's gate verdict (after an async verify). */
export async function screen(pins, bytes) {
  const raw = rawCheck(bytes);
  let sigOk = false, counter = 1n;
  if (raw.ok) {
    const h = headerOf(bytes, raw.n);
    counter = h.counter;
    const key = pins[String(h.sender)];
    if (typeof key === 'string') sigOk = await verifyBytes(key, signedBytes(bytes, raw.n), h.sig);
  }
  return decide(bytes, {
    keyFor: (s) => (typeof pins[String(s)] === 'string' ? fromHex(pins[String(s)]) : null),
    verify: () => sigOk,
    lastCounter: () => counter - 1n,
  });
}

/** { identity, genesis, clock, budget, pins (break-it's config/pubkeys.json: sender → hex key) }. */
export async function breakitNode({ identity, genesis, clock, budget, pins = {} } = {}) {
  const keyset = shaHex(new TextEncoder().encode(JSON.stringify(Object.keys(pins).sort().map((k) => [k, pins[k]]))));
  const skills = {
    screen: async (input) => {
      const h = input && typeof input.hex === 'string' && HEX.test(input.hex) && input.hex.length <= 8192 ? input.hex : null;
      if (h === null) return { verdict: 'ABSTAIN', why: 'screen takes the bytes of one packet as hex' };
      const bytes = fromHex(h);
      const v = await screen(pins, bytes);
      const core = { model: 'break-it/gate', stateless: true, input: shaHex(bytes), admit: v.admit === true, stage: v.stage, keyset };
      return { verdict: 'VERIFIED', admit: core.admit, stage: core.stage, receipt: { ...core, receiptHash: shaHex(new TextEncoder().encode(JSON.stringify(core))) } };
    },
  };
  const node = await createNode({ name: NAME, identity, skills, genesis, clock, budget });
  return { node, keyset };
}
