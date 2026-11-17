---
"@oip/conformance": minor
---

The suite judges identity (M2).

- The adapter gains `lineage` and `didDocument`, and the five positive checks M2 owes run through it: logs verify and addresses derive from their geneses, 2-of-3 pre-rotation, lineage, signatures counting for their authors, and DID documents.
- `NOT_JUDGED`: an adapter may answer it for a case it does not judge yet. The case is reported as pending, never as passed. The reference adapter answers it for every record whose proofs name an authority, until delegation is built.
- The reference adapter verifies logs and judges records signed by a mind's own keys with `@oip/identity`.
- `vectors.json` gains the cases of OEP-0002: 20 must-accept cases, 86 negative cases and 36 controls in all.
