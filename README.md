# BREAK IT · the Liveware ingest gateway

### ▶ Live: **https://sjgant80-hub.github.io/break-it/**

A secure ingest gateway for the records you take in from partners and devices. It proves
**who sent each record, in what order, in exactly what shape**, on the raw bytes, **before any
software parses it**. Every refusal becomes an antibody, a repeat attacker pays proof-of-work
for every new look, an independent referee watches the naive app behind it, and the whole
thing runs on a machine you own and sends nothing out. White-box: **reach the app with
anything malicious and you win.**

The live page runs the repository's own gated kernels in your browser: the real feed (180,000
payment records), the real gate, immune system, sentinel, app and referee. Nothing is a mock.

## The Liveware Pilot: sealed first, measured second, failures kept

One real node (`startNode`, as `node run.mjs` runs it) as the ingest gateway for a partner's
payment feed: the 180,000 records of the UCI *Default of Credit Card Clients* dataset
(DOI 10.24432/C55S3H, CC BY 4.0), with six known attack shapes injected mid-feed. The claims
were committed (`pilot/claims.json` @ c75c903) before the measuring code existed;
`pilot/measure.mjs` refuses to run if a claims file differs from its seal.

| role | claim | measured | |
|---|---|---|---|
| COO | every record admitted, none refused or lost | 180,000 admitted, 180,000 in the ledger, 0 refused | HELD |
| COO | the books equal the feed exactly | equal on all 210,000 keys, 30,000 accounts | HELD |
| COO | ≥ 100 records/s, each signature-checked and fsync'd first | 194.6 records/s (925 s), Intel i7-1255U laptop | HELD |
| CISO | 0 outbound attempts of any kind (as sealed, DNS included) | 1: Node's own `dns.lookup('127.0.0.1')` for its bind address | **FAILED, kept** |
| CISO | listens on 127.0.0.1 only | 127.0.0.1 | HELD |
| CISO | 0 outbound attempts once listening (addendum, sealed before the full run) | 0 | HELD |
| Security | six attack shapes refused at the gate, then dropped on sight | replay → counter; flip, unpinned key, no domain → signature; truncated → size; out-of-range → schema; all six then recognised | HELD |
| Security | the referee finds 0 breaches; its fold matches | 0 breaches, 180,000 checked, fold matches | HELD |
| Security | the red-team battery reproduces its receipt | 79 cases, all held | HELD |
| Regulator | every refusal explained; the ledger re-derivable offline | 12/12 answers and 12/12 journal records explained; the chain verifies; head = the offline derivation | HELD |

Receipt: [`receipts/pilot.json`](receipts/pilot.json), including the attempts that went wrong
on the way. CI runs `node pilot/check.mjs`: the ledger head and the books re-derived from the
feed alone, the judge re-run on the receipt's facts, and a metered real node re-run on the
first 3,000 records. The CFO's case is arithmetic on dated list prices and your own volumes
(`src/cost.mjs`, gated; prices in [`costs/sources.json`](costs/sources.json)), run on the page.

```bash
node pilot/measure.mjs     # the whole pilot on your own machine: your rate, your egress meter, your books
node pilot/check.mjs       # what CI checks
node tools/serve.mjs       # the live page locally, http://127.0.0.1:8892
```

Supplied by [AI Native Solutions](https://www.ai-nativesolutions.com). MIT, no licence fee.
Powered by the Konomi architecture, created by Thomas Frumkin.

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

- **The tarpit** (off unless the operator switches it on) — the rung above the rebound, for a
  **confirmed** attacker only: a source the gate has already refused 500 times. Its refusals
  that no genuine key can cause (wrong size, form or grammar, an unknown sender, a bad
  signature, a known attack) are held open twenty seconds, one ASCII space a second, then sent
  exactly as before (JSON ignores leading spaces). An admission, a work challenge, a counter a
  retry could cause: answered at once, from any address, so a genuine client never waits.
  At most 64 held at once; when full, answered at once; a source that leaves ends its hold.
  Nothing else is sent and nothing reaches into anyone's systems; every refusal is still
  journalled and harvested. Measured against sealed claims: `node tarpit/measure.mjs`
  (receipt `receipts/tarpit.json`).

- **Sentinel** — a behaviour guard on *verified* traffic, per sender: a stolen or scripted
  key is still a key, so Sentinel bounds its blast radius (drain, destruction, and a
  one-class deviation from the sender's own baseline) on the GEP ladder. It only ever
  refuses *more* than the gate.

- **The ledger** — append-only, hash-chained, `fsync`'d before the app acts, one writer at
  a time. On start every packet is re-run through the gate, so the ledger can only ever
  hold packets the gate would admit; a single altered byte refuses the start.

- **The mesh speaks LIGHT** — when a node learns a new exact antibody it tells its pinned
  peers, and that message is now a signed **LIGHT** packet (the estate's one codec,
  `vendor/light`, created in the Konomi frame), not JSON. The receiver's LIGHT door checks
  size, the pinned sender and the signature on the raw bytes *before a byte of the body is
  decoded*, then re-runs every antigen through its own gate, exactly as before. A share from
  an unpinned key, or a genuine share with one byte changed in transit, is refused at the
  signature with its body never read; a 64-antigen batch is ~2.5× smaller than the JSON it
  replaced (`node tools/light-share.mjs` → `receipts/light-share.json`). `vendor/light`
  is read-only, its SHA-256 pinned in `SOURCE.json` and checked by the tests.

## Proof it holds (and how you'd know if it didn't)

- **`node attack-kit/redteam.mjs`** — our own battery across every vector in the brief
  (79 cases: forge / replay-race / malleability / truncation / extension / length-extension /
  schema-escape / parser-reach / DoS / ledger tamper-delete-reorder / torn-tail /
  double-open / mesh-poisoning / Sentinel abuse / the rebound law). It writes
  `receipts/redteam.json`, and **`--check` regenerates it and demands it be byte-identical**.
  CI runs `--check`.
- **`node witness-all.mjs`** — the mutation + fuzz gate over every decision kernel. It
  flips one operator at a time and fails unless a test catches it; a surviving mutant is a
  line no test actually tests. CI runs it. Any reviewed-equivalent survivor is listed, with
  a written reason, in `witness.baseline.json`.
- **`node --test test/*.test.mjs`** — the unit + hostile-input (never-throw) suites, the pilot judge's tests, and the live page's own gate (self-only CSP, every control wired, the FAQ equal to its schema, the credits).

CI green on GitHub's runner is the un-forgeable proof of the code; the **live arena** is
the un-forgeable proof it's usable. Found something? Write it up in
[`FINDINGS.md`](FINDINGS.md) — vector, repro, severity.

## Layout

```
src/        wire · gate · immune · antibody · rebound · sentinel · chain · ledger · journal · referee · loot · app · keys · server · client · feed · cost · share (LIGHT mesh)
vendor/light/  the estate's one codec (read-only, SHA-pinned) — nodes share antibodies as signed LIGHT packets
node/       break-it as a node of the estate's shared foundation (vendor/fall-kit-core, pinned): its gate offered as the screen skill
pilot/      claims (sealed) · measure · check · judge · the egress meter · the metered node
page/       the live page: app.mjs (the kernels, in the browser) · style.css
feeds/      the UCI feed + SOURCES.json        costs/  the dated list prices the cost case reads
attack-kit/ forge · replay · fuzz · redteam  (+ lib)   — none of it trusted by the node
test/       one suite per kernel + a shared hostile-input battery
receipts/   redteam.json · pilot.json · witness.json — the re-runnable receipts CI checks
run.mjs     one command stands it up
```

Private keys live in `secrets/` (git-ignored, never served). MIT licensed; see
[`NOTICE`](NOTICE) for credits (Gary W. Floyd's GEP ladder; the estate's trust rail;
Konomi / Thomas Frumkin).
