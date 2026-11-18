---
"@oip/conformance": minor
---

The suite judges identity (M2).

- The adapter gains `lineage` and `didDocument`, and the five positive checks M2 owes run through it: logs verify and addresses derive from their geneses, 2-of-3 pre-rotation, lineage, signatures counting for their authors, and DID documents.
- `NOT_JUDGED`: an adapter may answer it for a case it does not judge yet. The case is reported as pending, never as passed. The reference adapter answers it for every record whose proofs name an authority, until delegation is built.
- The reference adapter verifies logs and judges records signed by a mind's own keys with `@oip/identity`.
- `vectors.json` gains the cases of OEP-0002: 22 must-accept cases, 102 negative cases and 52 controls in all.
- A positive check that finds a wrong answer fails, whatever else the adapter left unjudged.
- The differential campaign for identity compares logs of key-controlled minds, of collectives and of collectives within collectives; records signed by a mind's own keys, pinned to a branch and under a collective's threshold; lineages; and the DID documents both implementations resolve. `Verdict.value` is `unknown`: the Python checker also answers the questions `didDocument`, `lineage` and `intake`.
- The adapter gains `logIntake`: how far a copy of a log verifies, and whether the event after that is invalid or undecided (Layer 1, 4.9). The differential tests compare it with the checker's answer, which is written from the text of 4.9, and compare the two on sets of copies: with junk after them, with proofs lost, and with the proofs of one event split between two.
