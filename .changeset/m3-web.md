---
"@oip/web": minor
---

First version: the Mind Web (Layer 2).

- `signedTime`, `countsFor`, `actsFor`: whether a record counts for a mind, and from when, by its own key or threshold, through a delegation chain, or for a collective through a charter role (Layer 2, 7.1, 5.2). By every route, a proof evaluated more than 300 seconds after the record's `expires` does not count.
- `charterInForce`, `roleProofTime`, `roleTime`: the charter in force at a time, and whether a member's proof counts for its collective through a role of it (Layer 2, 6.2, 7.1 item 4).
- `commitmentAccepted` (Layer 2, 7.3), and status (Layer 2, Section 8): `intentStatus`, `offerStatus`, `commitmentStatus`, `charterStatus`, and `status` by the type of the record. A status is computed from the records the verifier holds and a time the caller gives; nothing reads a clock.
- `WebRecords`, `WebRecordSet`, `WebContext`: the records a verifier holds, found by what they refer to: what supersedes a record, the Commitments that resolve it and the Receipts about it.
- `evidenceMatches`, `evidenceIsChecked`: whether bytes a verifier fetched are the bytes an evidence item names by its digest (Layer 2, Section 9).
- A member's proof counts for its collective through a charter role only if the collective's log is known up to the evidence for the proof (core 9.4), and only before a duplicitous collective's first conflicting event (Layer 1, 7.3; OEP-0003). A removed member no longer signs for a collective against a stale copy of its log.
