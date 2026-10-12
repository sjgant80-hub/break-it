# BREAK IT

### ▶ Live arena: **https://sjgant80-hub.github.io/break-it/**

A white-box **verify-before-parse gate** with a living immune system and a cost law.
Everything is in front of you — the gate, a naive app behind it, the ledger, and a full
attack kit. **Reach the app with anything malicious and you win.** A referee decides, in
code written independently of the gate, and the win drops a signed, re-runnable trophy.

The live page runs the **exact same kernel** the tests and CI run — the gate you attack
in the browser is the gate that is gated below. Nothing is a mock.

---

## The rule

A tiny app sits behind the gate. It is naive on purpose: it trusts every message it is
handed and does no checking of its own. The only thing between the network and that app
is the gate. You win if the **referee** ever sees one of these:

- the app acted on a message the gate never admitted (bypass), or
- the gate admitted a packet an **independent** grammar validator rejects (a schema escape), or
- the app's action did not match its ledger entry, or
- the app's whole state stopped being a replay of the ledger (state corruption).

If you cause any of those, the node mints you a **signed trophy** bound to the exact
packet you sent — anyone can re-run it against the published gate and watch the referee
condition fire. The trophy proves its own story.

## Run it

```bash
node run.mjs            # one node on 127.0.0.1:8787 + a legit client sending real, signed traffic
node run.mjs --mesh 3   # three nodes, each pinned to the others — attack one, watch the others go immune
```

Then point the attack kit at it:

```bash
node attack-kit/forge.mjs   --op set --key name --value hi --send    # forge (random key)
node attack-kit/replay.mjs  --from-captured 0 --times 50 --parallel 50  # the replay race
node attack-kit/fuzz.mjs    --n 20000                                 # mutation fuzzer
node attack-kit/redteam.mjs                                          # our own battery, every vector
```

Watch what it learns: `GET /referee /immune /loot /journal /state /pubkeys`.

## What is defending

A packet's path, each stage refusing more than the last, nothing decoded until every
raw-byte check has passed:

```
HTTP limits → known-attack recognition (on sight) → THE REBOUND LAW (cost) → THE GATE (verify before parse)
            → SENTINEL (behaviour) → LEDGER (fsync'd) → the naive APP → the REFEREE (did anything get through?)
```

- **The gate** — `size → magic → schema → sender → signature → counter`, in order, on the
  raw bytes. Ed25519 over a domain-separated header+payload; one algorithm, no algorithm
  field; an exact per-sender counter (`last + 1`, inside the signed bytes — no window, no
  gaps, no rollover, and a malleated signature cannot make a replay fresh). It parses
  **only** after all of that, and the parsed message is frozen and tagged admitted.
  **Canonical wire format:** for every byte string the gate accepts, `encode(parse(b)) === b`
  — there is exactly one encoding of any message, so a packet cannot be read two ways.

- **The living immune system** — every refusal becomes memory: an attack **family**, a
  structural **fingerprint**, and — for refusals that can never become valid (bad bytes,
  a forged signature, a replay) — an **exact antibody** that is recognised on sight. New
  attacks near a known one are recognised by **shape**. Negative selection: an antibody is
  minted (and adopted from a peer) only after the node **re-runs the attack through its own
  gate** and the gate refuses it — so there is no false immunity. On a mesh, a new attack
  is signed and pushed to every peer, each of which re-runs it on its own gate before
  adopting it: a zero-day lands **once**, then the herd is immune. Every attack is written
  to a hash-chained journal — the feed the immune system eats from, and the source of CI
  **vaccines**.

- **The rebound law** — the gate is an elastic membrane. An attack *stretches* it (each
  refusal stored as tension); past its elastic limit the membrane *releases that stored
  energy back onto the source* as proof-of-work it must spend to be looked at. We verify a
  token in **one hash**; producing one costs **~2^bits**, and the price rises with every
  refusal while our cost stays flat. A legitimate client is never refused, so it owes
  nothing. **Nothing is ever emitted back onto the network** — the rebound is the
  attacker's own spent work becoming the price of its next attempt, not traffic aimed at
  anyone. A flood doesn't exhaust the defender; it only winds the spring tighter against
  the flooder.

- **Sentinel** — a behaviour guard on *verified* traffic, per sender: a stolen or scripted
  key is still a key, so Sentinel bounds its blast radius (drain, destruction, and a
  one-class deviation from the sender's own baseline) on the GEP ladder. It only ever
  refuses *more* than the gate.

- **The ledger** — append-only, hash-chained, `fsync`'d before the app acts, one writer at
  a time. On start every packet is re-run through the gate, so the ledger can only ever
  hold packets the gate would admit; a single altered byte refuses the start.

## Proof it holds (and how you'd know if it didn't)

- **`node attack-kit/redteam.mjs`** — our own battery across every vector in the brief
  (forge / replay-race / malleability / truncation / extension / length-extension /
  schema-escape / parser-reach / DoS / ledger tamper-delete-reorder / torn-tail /
  double-open / mesh-poisoning / Sentinel abuse / the rebound law). It writes
  `receipts/redteam.json`, and **`--check` regenerates it and demands it be byte-identical**.
  CI runs `--check`.
- **`node witness-all.mjs`** — the mutation + fuzz gate over every decision kernel. It
  flips one operator at a time and fails unless a test catches it; a surviving mutant is a
  line no test actually tests. CI runs it. Any reviewed-equivalent survivor is listed, with
  a written reason, in `witness.baseline.json`.
- **`node --test test/`** — the unit + hostile-input (never-throw) suites.

CI green on GitHub's runner is the un-forgeable proof of the code; the **live arena** is
the un-forgeable proof it's usable. Found something? Write it up in
[`FINDINGS.md`](FINDINGS.md) — vector, repro, severity.

## Layout

```
src/        wire · gate · immune · antibody · rebound · sentinel · chain · ledger · journal · referee · loot · app · keys · server · client
attack-kit/ forge · replay · fuzz · redteam  (+ lib)   — none of it trusted by the node
test/       one suite per kernel + a shared hostile-input battery
receipts/   redteam.json  — the re-runnable receipt CI must reproduce
run.mjs     one command stands it up
```

Private keys live in `secrets/` (git-ignored, never served). MIT licensed; see
[`NOTICE`](NOTICE) for credits (Gary W. Floyd's GEP ladder; the estate's trust rail;
Konomi / Thomas Frumkin).
