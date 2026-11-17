---
"@oip/identity": minor
---

First version: who a mind is, and which of its keys may sign (Layer 1, Sections 2 to 9; core Section 9).

- `verifyLog` and `LogBook`: verify an identity log event by event into the state after each, with each event's evaluation time taken from evidence. A book holds the logs a verifier has, verifies members' logs to the depth Layer 1, 4.7 allows, and resolves duplicity by the earlier evidence, never by length.
- `EvidenceView`, `FirstSeen`, `proofTime`, `eventTime`: evidence of time, and the two formulas of core 9.3 and 9.5. Nothing counts without evidence, and no function verifies without a view.
- `judgeRecord`, `operationalProofTime`, `operationalProofs`, `ownSignedTime`, `collectiveSignedTime`: key validity (Layer 1, 6.1) and signing by a mind's own authority, for a collective by its threshold at each time (Layer 1, 9.5).
- `didDocument`: DID documents, current and at a `versionId`. `lineage`: whether a parent acknowledges a child.
- `draftGenesis`, `draftUpdate`, `draftFork`, `draftRetire`, `signEvent`, `signEventSync`: write and sign the four events.
- A proof pinned to a `Retire` counts for nothing, for a mind's own records and for a member's proofs on a collective's events (OEP-0002).
- When a member's proof on a collective's event does not count, the rejection says why.
