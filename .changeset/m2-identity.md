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
- A book keeps its own copy of what it holds, and keeps what it has been shown (Layer 1, 4.9): every event of every copy of a mind's log, in a tree from the genesis, with every proof of each. `hold` judges nothing and discards nothing, so no copy undoes another and the order they come in does not matter (`drop` to go back). `log` judges when it is asked: an invalid event is no event; one the verifier cannot judge stops the log; where several verify at one position, the earlier evidence decides (Layer 1, 7.3), and what follows an event that lost is not judged. A verdict is forgotten only when a log it rests on changes (`forget` for a change of evidence).
- Only a well-formed copy of an event adds its proofs to it (Layer 1, 7.1): a copy whose `proof` is not what core 5.1 requires, or that is too large with it, adds nothing and takes nothing away, and keeps its place. Proofs are held for an event by its content ID, wherever in a copy it stands. A value in a copy has a place if, apart from its `proof`, it is a JSON object within core Section 1, of at most 1 MiB; nothing after a value that has none is held in that copy.
- A book has no limit on the copies it holds of one mind's log. For one event it holds the proofs that one record carries (256, and 1 MiB with the event), and refuses the mind when well-formed copies show more.
- `understood`, for `verifyLog`, `LogBook` and `judgeRecord`: the extensions the caller implements. An event or a record that lists another in `critical` is refused (core 8.3). By default none is implemented.
- A duplicitous collective signs nothing from its first conflicting event on, and a record is signed by a collective from the moment a change of membership completes its threshold (Layer 1, 7.3, 9.5; OEP-0002).
- An event that fails is invalid or undecided (Layer 1, 4.9; OEP-0002). `witnessLog` says which (`undecided`) for a copy judged alone. A log that arrives is taken in with `LogBook.witness`, which holds the copy as it came and records first sight of every event that verifies with the proofs of every copy held. It looks at the copy's mind and at every mind held whose log rests on it, so an event of a collective that waited on a member's log is seen when that log arrives. `LogBook.witnessHeld` does the same for everything held, after a change that was no copy taken in.
- Verified logs, judged records and every answer a book keeps are frozen.
