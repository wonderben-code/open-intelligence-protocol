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
- `witnessLog` and `witnessRecord`: record a verifier's own first sight of a log's events or a record's proofs, of those that verify and of no other. Evidence for an event is evidence of the event with valid proofs (core 9.5), and a content ID does not cover proofs.
- A book keeps its own copy of what it holds, never replaces a log by an earlier state of itself (`drop` first), keeps each branch with the time it is known up to, and forgets a verdict only when a log it rests on changes (`forget` for a change of evidence). A branch takes part in resolving duplicity with the events it has that verify.
- `understood`, for `verifyLog`, `LogBook` and `judgeRecord`: the extensions the caller implements. An event or a record that lists another in `critical` is refused (core 8.3). By default none is implemented.
- A duplicitous collective signs nothing from its first conflicting event on, and a record is signed by a collective from the moment a change of membership completes its threshold (Layer 1, 7.3, 9.5; OEP-0002).
- Verified logs and judged records are frozen.
