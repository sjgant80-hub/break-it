# The prospective-client walkthrough (2026-10-25)

Five buyer personas opened the rebuilt page cold, read every section and number, and pressed every
control. Each gap they found is listed with what changed on the page. The click-through ran in a
real browser against the page served locally (`node tools/serve.mjs`): every button, the feed at
all three paces, the console with genuine, replayed, flipped and junk bytes, the theme toggle, the
cost inputs including refused ones, and the layout at 375 px wide with no horizontal scroll.

| persona | what they asked or hit | what changed |
|---|---|---|
| CFO | At the default volume the case says £38 a month. Why would I switch for that? | The cost case now shows the same kernel at 10 million, 100 million, 1 billion and 5 billion requests a month, with your other figures, so the slope is visible: the managed bill grows per million, the node path only per machine. |
| CFO | What does the managed line leave out, and does the node line flatter itself? | Stated under the calculator: the managed line leaves out the compute behind the gateway that would check signatures, data transfer, logging and support; the node line uses the chip's full 55 W all month at the household cap, above the business average. |
| CISO | The node listens only on 127.0.0.1. How does a partner reach it? | Security section and risks: whatever already carries the feed (your TLS endpoint, VPN or file drop) runs on the same machine and hands each record to the node; the node has no port on the network. |
| CISO | Something must read the request before the gate. What? | Stated: Node's HTTP layer reads the request line and headers (8 KB cap, 2 s header and 3 s request timeouts, Content-Length required, no chunked bodies); the record itself is read by nothing until the gate passes it. |
| CISO | Is the record encrypted? | Stated: signed, not hidden; confidentiality on the wire is the TLS in front. |
| CISO | ciso-1 says FAILED. | Explained on the page: Node's own listen() resolves the bind literal 127.0.0.1 through dns.lookup; the sealed claim counts it and stays failed; ciso-3 (sealed before the full run) holds: nothing once listening. |
| COO | 194.6 a second means what for a day's work? | The COO card: about 16.8 million records a day on one laptop. |
| COO | A partner sends a record wrongly. Do they get punished? | Risks: refused with its stage and reason, resent with the next counter; the rebound starts only after 100 refusals. |
| Owner-manager | Ed25519, counter, fsync, proof-of-work, ledger: I do not know these words. | "Words used on this page" under Start here: each term in one or two plain sentences. |
| Procurement | Who supplies it, on what terms, and how do we leave? | Already on the page: AI Native Solutions; MIT with no licence fee; support, service levels, warranty and liability agreed per deployment; the ledger and journal are plain files. |

Found by the click-through itself (fixed before the walkthrough):

| what | why | fix |
|---|---|---|
| The out-of-range attack did nothing on the page | `withSignature()` runs the raw check and refuses to wrap bytes the grammar forbids; the pilot used the attack kit's `signRaw`, which does not | the page signs that one shape raw, as the attack kit does |
| A `frame-ancestors` console error | the directive is ignored in a meta CSP | removed from the meta policy |
| A favicon 404 | none shipped | `page/icon.svg` |

# The second walkthrough (2026-11-04): after the herd and the tarpit

Four buyers (CFO, CTO/CISO, COO, procurement) read the page cold, served locally from the commit
being pushed (`node tools/serve.mjs`), section by section, with every control pressed: the feed,
the six shapes run twice each (all six refused, then dropped on sight), the console with an
out-of-range record (refused at schema, then on sight) and junk bytes (refused at size), the cost
case at 1 billion requests and with a refused input, and the theme toggle. No console errors; no
horizontal scroll; every in-page link has its target. Each gap, and what changed:

| persona | what they asked or hit | what changed |
|---|---|---|
| CTO/CISO | "What if the gate has a hole?" still said a breach becomes an antibody pushed to every peer. Since the herd was measured we know that alone cannot stop it: an antibody never refuses bytes a peer's own gate admits. | The risk now gives the herd's answer: the breach packet is its own proof, each peer re-checks it on its own gate and grammar and closes its door, so the flaw lands once in the mesh, not once per node; and what it cannot catch (a flaw in both validators at once). The README's immune paragraph said the same old thing and is corrected, with a section for the herd. |
| CTO/CISO | Has anyone outside tested it? | A straight answer in the risks: not yet. Everything is re-runnable by anyone; no outside team has reported; nothing has been filed in FINDINGS.md (no issue or pull request has ever been opened on the repository). |
| CTO/CISO | The tarpit's "on a faster machine the cap was reached" quoted one CI run. | Every recorded CI run is listed word for word from its log (`receipts/tarpit-ci.json`), the one where p-5 failed on GitHub's machine as well as the one where it held; a test refuses the page text singling one out. |
| CFO | The page says the business electricity price "was lower" and the staff rate starts at "the floor". Lower than what, and says who? | Both figures come from the estate's sourced basis (`costs/basis.json`, vendored byte for byte) and are shown beside the inputs with their sources; a test fails if either word stops being true of the figures. |
| COO | How would we see what a node is doing? | Security operations: each node answers /health, /journal, /immune and /referee on its own machine, as JSON. |
| COO | Is the herd on? Is the tarpit on? | Roll-out: the herd's patch is on unless a node is started with `herdPatch: false`; the tarpit is off until `tarpit: true`. |
| Procurement | Is there third-party material, and under what licence? | The procurement card names it (the pilot's dataset, CC BY 4.0; the GEP ladder, Open Defensive Prior Art); NOTICE now lists every vendored part (LIGHT, the shared foundation, the witness engine, the cost basis), each pinned by SHA-256, all MIT. NOTICE had said the build ships no codec, which stopped being true when the mesh moved to LIGHT. |
| Procurement | How do we contact the supplier? | Ownership: contact AI Native Solutions through its site. |
| Procurement | FINDINGS.md says 66 cases. | 79, as the battery's receipt says, with the ingest cases and the herd's and tarpit's limits added. |
