# FINDINGS

Found a way through? Log it here and open an issue/PR. The bar is the **referee**: a
finding counts if it makes `GET /referee` report `breached: true`, or shows the app acting
on something the gate did not admit, or desyncs the ledger from the app state.

## Report template

```
### <short title>
- Vector:      forge | replay | tamper | schema-escape | parser-reach | dos | state | determinism | other
- Severity:    critical (referee breach) | high (gate bypass, no breach yet) | medium | low
- Repro:       the exact command(s), or the packet hex
- Expected:    what should have happened
- Observed:    what happened (paste the /referee or /immune output)
- Node/commit: `git rev-parse HEAD`
```

## In-house red team (reproduced every run by `attack-kit/redteam.mjs --check`)

Every vector in the brief, run against real nodes, each asserting the outcome it should
produce. Current result: **66 cases, all held** (see `receipts/redteam.json`).

| Vector | What was tried | Outcome |
|---|---|---|
| forge | a perfect packet signed by an unpinned key | refused at `signature`, then recognised on sight |
| forge | an unknown sender id | refused at `sender` |
| forge | the legit key, signed without the domain prefix | refused at `signature` |
| forge | algorithm/version confusion (version byte 2) | refused at `magic` |
| forge | every single-bit flip of a valid packet | 0 of them admitted |
| signature | nonce reuse (Ed25519 is deterministic) | identical signatures — nothing to reuse |
| signature | malleability (s + L), all-zero sig, truncated sig | refused at `signature` / `size` |
| signature | length extension; bytes smuggled into the sig region | refused at `schema` / `size` |
| replay | a spent packet resent; the same one again | refused at `counter`, then recognised |
| replay | 50 concurrent copies of one fresh packet (the race) | exactly 1 admitted |
| replay | out of order, counter 0, rollover, wrap-around | all refused at `counter` |
| schema | `__proto__` key, upper-case key, 33-byte key, empty key | refused at `schema` |
| schema | control/NUL value byte, lying length, unknown op, over-limit delta, non-ASCII | refused at `schema` / `size` |
| parser | packet as hex text; chunked body; no / oversized / lying Content-Length; slow body | refused before admission |
| dos | 1,000 requests pipelined down one socket | rate-limited (429), nothing admitted; gate not locked afterwards |
| dos | garbage on the socket | node stays up |
| immune | attack node 0 once (mesh) | nodes 1 and 2 recognise it on sight without having seen it |
| immune | a peer shares a packet that is valid here (autoimmunity attempt) | not adopted; the valid packet still goes through |
| immune | a share from an unpinned peer; antigens swapped in transit | not adopted (signature) |
| rebound | a source past BLOCK | charged proof-of-work (402) before any signature work |
| rebound | pay the price | the forgery reaches the gate and is still refused; the law holds (attacker ≫ defender, ratchet never slips) |
| sentinel | a valid key draining the store | blocked (`behavior`), and stays blocked |
| state | ledger byte-flip / delete / duplicate / swap / forged-but-well-chained | node refuses to start |
| state | torn final write | trimmed to the last whole entry, node starts |
| state | second writer on a live ledger | refused |
| state | restart | the drained key stays blocked and the attacks stay known (rebuilt from the journal) |
| state | the attack journal edited | journal moved aside, the ledger untouched |
| referee | did anything reach the app it should not have? | clean — every admitted message checked; state == ledger replay |

## Residual / honest limits

- **The app is naive by design.** It is the thing you are trying to reach; its own lack of
  checking is not a finding — reaching it past the gate is.
- **Shared-address cost.** The rebound law is keyed by source address. A legitimate client
  behind the same address as a flooder inherits the raised price and must pay the
  proof-of-work once (cheap for a low-volume client). This is a deliberate trade, not a
  bug: the alternative — turning that source away — would let an attacker lock out a
  neighbour, which the design refuses to do.
- **`MAX_BITS` cap.** The proof-of-work difficulty is capped so a malicious or buggy peer
  cannot ask for an unbounded amount of work.
- **Mesh trust.** Peers are pinned by public key; a peer can only ever get another node to
  *re-run* an antigen on its own gate, never to adopt on its say-so. A compromised peer
  cannot inject a false antibody (it would have to produce bytes that this node's own gate
  refuses at a permanent stage — i.e. a genuine attack).

No referee breach has been produced. If you produce one, you've earned the rune — log it
above.
