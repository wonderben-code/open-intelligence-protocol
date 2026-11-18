---
"@oip/web": minor
---

First version: the Mind Web (Layer 2).

- `signedTime`, `countsFor`, `actsFor`: whether a record counts for a mind, and from when, by its own key or threshold, through a delegation chain, or for a collective through a charter role (Layer 2, 7.1, 5.2). By every route, a proof evaluated more than 300 seconds after the record's `expires` does not count.
- `charterInForce`, `roleProofTime`, `roleTime`: the charter in force at a time, and whether a member's proof counts for its collective through a role of it (Layer 2, 6.2, 7.1 item 4).
