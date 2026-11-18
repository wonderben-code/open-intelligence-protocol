# ADR-0009: Signing for a party: two packages, one view of records, and no search

**Status:** Accepted, 18 November 2026 (M3).

## Context

Layer 2, Section 7 gives four routes by which a record counts for a mind: its own key, a delegation chain, a collective's threshold, and a charter role. Layer 1, Section 11 defines the chain. The first and third routes are `@oip/identity`'s (M2). M3 adds the other two, and the status functions of Layer 2, Section 8, which ask the question of many records at once.

Three things had to be decided: where the code goes, how it reaches the records a verifier holds, and how much it is allowed to look for.

## Decision

**Two packages, split where the specifications split.** `@oip/delegation` is Layer 1, Section 11: commands, policies, chains, revocations and `/oip/send`. `@oip/web` is Layer 2: charters and roles, the four routes together, acceptance and status. Both are pure. A host that only relays packets needs `sentFor` and nothing of Layer 2.

**A verdict is a time.** `delegatedTime`, `roleTime` and `signedTime` answer with the earliest evaluation time at which the record counts, or `undefined`. Every rule about time is then a comparison of times that come from evidence (ADR-0003), and "counts" is "has a time". The functions that explain a refusal (`delegatedProofTime`, `roleProofTime`) return a result with the clause and the entry of `authority` at fault.

**A chain is checked as listed, and never searched for.** Layer 1, 11.6 forbids a verifier to look for another order or subset. The code has no operation that could: it reads the entries of one proof's `authority` in order, and each fails or passes as it stands. A proof therefore acts for its signer and for at most one other mind, and what a delegate signs for a principal is what the delegate chose to list.

**Records are reached through a view, as logs are.** `RecordView` (and `WebRecords`, which adds what Section 8 asks for) is the interface: a record by its content ID, the revocations of a delegation, the charters of a collective, what supersedes a record, the Commitments that resolve it, the Receipts about it. `RecordSet` and `WebRecordSet` hold records in memory; an indexer (M5) implements the same interface over its store. Nothing in either package enumerates "all records".

**What a set is shown, it keeps.** The same record given twice, with other proofs, is one record with every proof that verified. This is the rule of ADR-0008 for logs, for the same reason: a copy must never undo what another showed. For a `Revocation` the failure would be open: a second copy without its author's proof would un-revoke a delegation.

**The role route is as strict as the threshold route.** A member signs for its collective through a role only if the collective's log is known up to the evidence for the proof, and only before a duplicitous collective's first conflicting event (OEP-0003). The first version asked only whether the signer was a member in the copy of the log at hand, so a removed member kept its role for as long as a verifier kept an old copy.

**`disputed` needs no second set of rules.** Layer 2, 8.3 asks whether a Commitment would be accepted were compromise declarations disregarded. `disregardingCompromise(view)` in `@oip/identity` gives a view of the same logs without the declarations, and the ordinary rules are asked of it. No function that counts a signature has a flag.

**A policy is read whole before any of it is used.** Differential testing against the Python checker found that the evaluator, given a policy that had not been validated, never looked at the statement of a quantifier over an empty array. Validation now comes first inside `evaluatePolicy` itself, whoever calls it.

**After two reviews: what a chain needs to know of its authors, and a bound that counts.** Two independent reviews of the milestone found that a delegated proof was judged against whatever copy of the delegator's log the verifier happened to hold, that a retired or duplicitous delegator's grants went on counting, that a compromise declaration gave back a delegation its author had revoked, and that one member could bring back a charter the threshold had replaced. Each is now a rule of the specification (OEP-0003, items 18 to 20 and 23), and each is checked where the route is judged, so no caller has to remember it. The policy evaluator counted statements and not work: it now counts one for each value a statement is tried on and the bytes of both forms where it compares by canonical form, stops at 262,144, and does no more work than it counts (item 17). The same count is in the Python checker, so the two agree on which policies hold.

## Consequences

- A verifier that keeps its own first sight takes a record in with `witnessProofs`, which also records the proofs of the delegations and charters carried inline. Their signatures need evidence of their own (Layer 1, 11.4, item 1), and without it a proof that carries its chain never counts.
- Status is only as complete as the records behind the view. A verifier that does not hold the Receipt that says `fulfilled` answers `accepted`. The READMEs say so.
- The cost of `signedTime` is that of the routes: each proof on the record, and for a chain up to eight delegations, each with its author's log. A status function calls it for each related record. Nothing is cached between calls; an indexer that needs to can cache by content ID and proof digests, since a verdict changes only when a log, a record or the evidence does.
- The work of one policy for one record is at most 262,144 (Layer 1, 11.3): about a tenth of a second for a verifier at the limit. A record may carry many proofs, each with a chain of its own, so a host that takes records from strangers still bounds what it will judge for one sender.
- A status function judges a Commitment with the proofs of every copy the view holds, and checks what the view says refers to a record against the record that is said to. A view is still trusted to be complete: a Receipt it does not hand over is not heard.
