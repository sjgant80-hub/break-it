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
