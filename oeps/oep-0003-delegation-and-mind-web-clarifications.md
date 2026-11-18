---
oep: 3
title: Delegation and Mind Web clarifications found while building the reference implementation
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 2 # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: 2026-11-18
requires: [1, 2]
replaces: []
discussion: # the pull request of milestone M3
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0003: Delegation and Mind Web clarifications found while building the reference implementation

## Summary

Writing `@oip/delegation` and `@oip/web`, the packages of the reference implementation that judge delegation chains, charter roles and the status of Layer 2 records, showed sixteen places where Layer 1, Section 11, and Layer 2 (revision 2026-11-17, with OEP-0001 and OEP-0002) allow two readings, set no rule, or leave a rule without a test. This proposal settles each. Fourteen choose the reading both implementations already had, or make an informal term exact. Two close gaps that protect someone: a member that a collective has removed could go on signing for it through a charter role against a stale copy of the collective's log, and a member of a duplicitous collective could sign for it through a role although nobody can under its threshold.

No record format changes, except that an Offer's `quantity` is at least 1.

## Motivation

Whether a record counts for a mind decides who is bound by a Commitment. Two verifiers that hold the same records and the same evidence must give the same answer, and each item below is a case where they might not, or where the answer protects less than the text beside it says.

1. **Which commands are reserved?** 11.2 reserves "every other command beginning `/oip`". Read by its letters, that reserves `/oipx/pay`, an extension's command. Both implementations read it by segment.
2. **How deep is "8 deep"?** 11.3 says statements nest at most 8 deep and does not say where counting starts. Both implementations count a statement of the policy as depth 0, so nine levels fit. No vector stood at the boundary.
3. **Is a policy well formed whatever record it is asked of?** A quantifier tries its statement on each element of an array. On an empty array it tries it on nothing. The reference implementation's evaluator, asked of a policy that had not been validated, therefore never looked at that statement, and a statement there that was none went unnoticed: the policy held. The Python checker validates a policy whole before it evaluates any of it. Differential testing found the difference in twenty thousand generated policies. Records are validated before their policies are used, so no chain was affected; the text should still say which is right.
4. **An ordering on what is no decimal had no vector.** Six vectors were meant to show that `<` on a value that is no decimal is an error. Each is rejected earlier, as a malformed record, because the value stands where an amount must. The rule itself was tested by unit tests alone.
5. **Who may revoke a delegation?** 11.5 says a `Revocation` has an `author`, "the author of the revoked delegation", and does not say what a revocation by anyone else does.
6. **What is a proof whose chain does not hold?** 11.6 says a proof acts, through its `authority`, for at most one mind besides its signer. It does not say whether a proof whose `authority` fails still counts for its signer, what a verifier does with a delegation it is given by reference and does not hold, whether a delegation given inline is judged with the proofs of a copy the verifier holds, or whether a principal's own proof can count for it "through" a chain.
7. **The collective's log, for a role.** core 9.4 requires the log of a collective "under whose threshold the proof is counted", held as served no earlier than the evidence for the proof. Layer 2, 7.1, item 4 counts a member's proof for the collective through a charter role, if the signer is a member of the collective's state at the proof's time. Nothing required the collective's log to be known up to then. A verifier with a copy of the log from before a member was removed counted that member's signatures for the collective for as long as it kept the copy. The reference implementation did.
8. **A duplicitous collective's roles.** Layer 1, 7.3 (as OEP-0002 amended it) says that from its first conflicting event on, a duplicitous collective's members are not known, and nothing is signed under its threshold. Item 4 of 7.1 asks whether the signer is a member at the proof's time, and both implementations answered from the last state the branches share. So a member could bind a duplicitous collective through a role where no number of members could bind it under its threshold.
9. **A superseding record with a `status` that is not its type's.** Section 2 says `status` is "the new status". An Offer that supersedes another with `status` `satisfied` has a status that Section 8 does not give Offers. Is the Offer it names withdrawn, edited, or untouched?
10. **Copies of one record.** 5.3 says that every copy of a Commitment with the same content ID is the same Commitment, and that a verifier SHOULD merge their proofs. The reason given holds for every record.
11. **May an Offer's `quantity` be zero, or negative?** 4.2 says "integer". 8.2 makes an Offer `exhausted` when at least that many accepted Commitments take it up, so an Offer with a quantity of zero is exhausted before anyone can accept it.
12. **Which members of an inline object are required?** The tables have a column for it. Objects described inline, as `{ "max": <amount>, "currency": … }`, do not, and the text marks some members REQUIRED and is silent on others. Two implementations could disagree about whether a budget needs a currency, or a role a purpose.
13. **Is a status computed with a tolerance?** 8.1 to 8.3 say `expired` "if `expires` has passed" and `overdue` if the deadline "has passed". core 9.1 gives clocks 300 seconds. Does a status allow them too, and is an Intent expired at the instant `expires` names? And does the time of computation limit which signatures are counted?
14. **Which Receipts are superseded?** 8.3 excludes "Receipts superseded by a later Receipt of the same author". "Later" by what: `created`, evidence, or nothing but the reference? And must the superseding Receipt itself be one that is heard?
15. **Whose compromise declarations?** 8.3, item 1 calls a Commitment `disputed` "if it would be accepted were compromise declarations disregarded, because a party has withdrawn its signature by declaring its key compromised". A party's signature may also rest on another mind's key: its delegate's, or a member's of a collective that is a party.
16. **Two negative cases had no control.** `delegation-outside-the-proof` and `role-without-charter` are rejected by an implementation with no delegation and no charters at all.

## Specification

**Layer 1, 11.2.** Current: "Every other command beginning `/oip`, including `/oip` and `/oip/sign` themselves, is reserved". Proposed:

> Every other command whose first segment is `oip`, `/oip` and `/oip/sign` themselves among them, is reserved: a delegation using one is invalid in this revision, so there are no blanket grants. A command whose first segment only begins with those letters, such as `/oipx/pay`, is an extension's.

**Layer 1, 11.3.** Current: "Statements nest at most 8 deep." Proposed:

> Statements nest at most 8 deep: a statement of the policy is at depth 0, a statement inside another is one deeper than it, and none is deeper than 8. Whether a policy is well formed does not depend on the record it is asked of: every part of it is a statement, the statement of a quantifier among them, which is tried on nothing where the array is empty.

**Layer 1, 11.5**, add after "and is signed by the author's own authority.":

> A revocation by any other mind revokes nothing.

**Layer 1, 11.6**, add after "Verifiers check the list as given and MUST NOT search for another order or subset.":

> A delegation given inline is judged with the proofs it carries there; one given by reference is the record the verifier holds, and a proof that names a delegation the verifier does not hold does not count for `P`. A proof whose list is not a valid chain counts for no mind through it, and is its signer's own proof all the same (Layer 2, Section 7.1, item 1): what a proof says of acting for another takes nothing from what it is for its signer. A proof by `P` itself counts for `P` by its own key, and never through a chain.

**core 9.4**, in "Holding the evidence". Current: "the log of a collective under whose threshold the proof is counted (Layer 1, Section 9.5), held as served no earlier than `τ(p)`". Proposed:

> the log of a collective under whose threshold the proof is counted (Layer 1, Section 9.5), or for which it is counted through a charter role (Layer 2, Section 7.1), held as served no earlier than `τ(p)`

**Layer 2, 7.1**, item 4, add at its end:

> As for a threshold, the verifier holds `P`'s log as served no earlier than the evidence for `p` (core 9.4), for a copy older than that may lack the event that removed `M`; and if `P` is duplicitous, `t(p)` is before its first conflicting event, from which on its members are not known (Layer 1, Section 7.3).

**Layer 2, Section 2.** The row for `status`. Current: "Only in a superseding record; the new status (Section 8)". Proposed:

> Only in a superseding record; the new status (Section 8): `withdrawn` or `satisfied` on an Intent, `withdrawn` on an Offer. A superseding record with any other `status` is neither a withdrawal nor an edit (4.3), and changes nothing

Add after "never in the record.":

> Proofs are added to a record without changing its content ID (core 3.1), so every copy of a record with the same content ID is the same record, and a verifier SHOULD judge it with the proofs of every copy it holds (5.3).

**Layer 2, 4.1, 4.2, 5.1 and 6.2**: which members are required.

- 4.1, `budget`: `max` is REQUIRED and `currency` optional.
- 4.2, `price`: `amount` and `currency` are both REQUIRED. `quantity` is "an integer of at least 1: how many times the Offer can be taken up".
- 5.1, `price`: all four members are REQUIRED.
- 6.2, `roles`: `purpose` and `powers` are optional, and a role without powers grants nothing. In a power, `command` is REQUIRED and `policy` defaults to `[]`. In an entry of `assignments`, `mind` and `role` are both REQUIRED.
- Section 2, `links`: `rel` and `ref` are both REQUIRED.

**Layer 2, Section 8**, add after its first sentence:

> The time of computation is compared with `expires` and with a deadline exactly: a status is a statement at a time, and the tolerance of core 9.1 is for judging signatures. `expires` or a deadline "has passed" at any later time, and not at the instant it names. Whether a record counts for a mind is asked of the records and the evidence the verifier holds, and not of the time of computation.

**Layer 2, 8.3.** Current: "excluding Receipts superseded by a later Receipt of the same author and Receipts with outcome `revoked`." Proposed:

> excluding Receipts with outcome `revoked` and Receipts superseded by another Receipt of the same author: one in which `supersedes` names it, whose author is a party and which counts for its author. A Receipt that names another author's Receipt in `supersedes` supersedes nothing.

Item 1. Current: "were compromise declarations (Layer 1, Section 6.2) disregarded, because a party has withdrawn its signature by declaring its key compromised". Proposed:

> were compromise declarations (Layer 1, Section 6.2) disregarded, every mind's and not the parties' alone, because a signature it rests on was withdrawn by a declaration that a key was compromised

## Rationale and alternatives

**Items 1 and 2** write down what both implementations do. Reserving by letters would take a name from every extension that happens to start with them. Counting the outermost statement as depth 1 would allow eight levels where both implementations allow nine; nothing rests on the difference, so the text follows the code, and two vectors now stand at the boundary.

**Item 3.** A policy is data that a delegator writes once and that many records are judged by. Whether it is a policy must not depend on which record it meets first: a delegation that is valid for a record with one party and invalid for a record with none would be two delegations. The Python checker was right, and the reference implementation now reads a policy whole before it asks any of it of a record.

**Item 5.** Any other rule lets a delegate, or a stranger, end a delegation that is not theirs. That a revocation is its author's alone was always the intent; `revocation-by-another-mind` now tests it.

**Item 6.** A proof is first of all its signer's signature. If a failed `authority` took that away, a delegate could not sign for itself and for its principal in one proof and have the first survive a mistake in the second, and a verifier would need the chain to judge the delegate's own signature. The opposite risk, that a proof meant for a principal binds only the delegate, is the delegate's to avoid, and Layer 2, 5.4 already has displays show under what policy a party was bound. An inline delegation is judged as given because the proof's signature covers its `authority`: what is inline is what the delegate chose to show, and nobody else can change it.

**Items 7 and 8** make the role route as strict as the threshold route. The reasons are those OEP-0002 gave for the threshold: a copy of a log that is older than a proof may lack the event that removed the signer, and after duplicity nobody knows who the members are. A role is a lesser authority than the threshold, and it must not outlast it.

- _Alternative for item 8: ask whether the signer is a member in every branch._ OEP-0002 rejected that for the threshold, for the reason that holds here: a verifier that sees one branch and a verifier that sees two must not disagree about a record signed before either saw the second.

**Item 9.** An unknown `status` could be read as an edit. But a `status` is a claim about the record named, and a verifier that does not know the claim should not act on half of it. Reading it as nothing means a status from a later revision does not withdraw or replace anything for verifiers of this one.

**Item 11.** A quantity of zero or less has no meaning as an offer, and made a record that is exhausted from the start. The other members the text calls "integer" (`Location.seq`, `maxHops`, a query's `limit`) belong to Layer 1 and are left to the milestone that implements them.

**Item 12** states what the JSON Schemas already require, member by member. A general convention for the inline notation was considered and not adopted: the text marks members both ways today (`summary` is called REQUIRED and `deliveryBy` optional in one sentence), and no single default matches every object.

**Item 13.** A status is shown to people, at a time they can read off a clock. A tolerance would make "expired" start 300 seconds after the time the record names, for no gain: nothing is signed or bound by a status. The last sentence answers the other half of the question. A verifier does not hide a signature it holds because the time it was asked about is earlier: what it holds is what it knows.

**Item 14.** `created` is the author's claim and evidence differs between verifiers, so neither can decide which Receipt is "later" for everyone. The reference in `supersedes` can: it is in the content, and the content ID covers it. A superseding Receipt that would not itself be heard (an outsider's, or one whose signature does not count) cannot silence one that is.

**Item 15.** `disputed` tells a counterparty that the Commitment was once complete and that a declaration undid it. It makes no difference to the counterparty whose key the declaration named. Both implementations disregard every declaration.

## Backwards compatibility

A rule change, in the sense that a verifier of the unamended revision may count proofs that this proposal does not.

- **Does any record that is valid today become invalid, or the reverse?** An Offer with a `quantity` below 1 becomes malformed. A proof through a charter role stops counting where the verifier's copy of the collective's log is older than the evidence for the proof, and where the collective is duplicitous and the proof is evaluated at or after its first conflicting event. Under one reading of today's text, a superseding record with a `status` that is not its type's stops superseding. Nothing else changes for an implementation that read the text as the two implementations here did.
- **Does any golden value change?** No. `vectors.json` gains cases and loses none; every existing value is byte for byte what it was.
- **What does an implementation of the earlier revision do with a record that uses the change?** There is nothing to use: the change removes readings and adds no member, type or name.
- **What must existing minds, hosts, resolvers, indexers and gateways do, and by when?** Nothing. No Offer in the vectors, the papers or the examples has a quantity below 1.

## Security and privacy considerations

- **Items 7 and 8 close two ways to bind a collective without its consent.** Without item 7, a member the collective has removed keeps its role for every verifier that has not refreshed the collective's log, with no bound but the verifier's patience; with it, the verifier refuses until its copy is as recent as the proof. Without item 8, one member with a role could commit a collective that its own members had made duplicitous, and choose the moment.
- **Item 3 closes a way for an invalid policy to pass**, for any caller that evaluates a policy it has not validated. No such caller exists in the reference implementation; the rule protects the next one.
- **Item 6 is not a loosening.** A proof with a broken chain never counted for the principal, and it always was a signature by the signer's key. Saying so prevents an implementation from discarding the signer's own commitment because of a mistake in `authority`.
- **Item 13 cannot be used to bind anyone.** Status binds nobody; acceptance (7.3) does, and it is judged at evaluation times, with the tolerance.
- **Privacy.** None of the items changes what is published or to whom.

## Test vectors

Added to `vectors.json` by `oip_vectors.py`, and accepted or rejected by both implementations. Each negative case fails under the rule it names and its control passes with that one thing put right.

| Case                                                   | Kind        | Section                            | Item |
| ------------------------------------------------------ | ----------- | ---------------------------------- | ---- |
| `command-whose-first-segment-begins-oip`               | `record`    | must-accept                        | 1    |
| `delegation-with-a-reserved-command`                   | `record`    | negative                           | 1    |
| `policy-nested-eight-deep`                             | `record`    | must-accept                        | 2    |
| `policy-nested-nine-deep`                              | `record`    | negative                           | 2    |
| `policy-orders-what-is-no-decimal`                     | `countsFor` | negative, with a control           | 4    |
| `revocation-by-another-mind`                           | `countsFor` | must-accept                        | 5    |
| `proof-with-a-broken-chain-counts-for-its-signer`      | `countsFor` | must-accept                        | 6    |
| `delegation-named-and-not-held`                        | `countsFor` | negative, with a control           | 6    |
| `duplicitous-collective-acts-through-a-role`           | `countsFor` | negative, with a control           | 8    |
| `offer-superseded-with-a-status-that-is-not-an-offers` | `status`    | must-accept                        | 9    |
| `offer-with-a-quantity-of-zero`                        | `record`    | negative, with a control           | 11   |
| `intent-at-its-expiry-is-open`                         | `status`    | must-accept                        | 13   |
| `commitment-at-its-deadline-is-not-overdue`            | `status`    | must-accept                        | 13   |
| `receipt-superseded-by-its-author`                     | `status`    | must-accept                        | 14   |
| `receipt-revoked-by-its-author`                        | `status`    | must-accept                        | 14   |
| `receipt-superseded-by-another-party`                  | `status`    | negative                           | 14   |
| `delegation-outside-the-proof`, `role-without-charter` | `countsFor` | controls for two earlier negatives | 16   |

Ten further negative cases, each with a control, pin the items of Layer 1, 11.4 one at a time on a two-step chain. They test rules the text already stated and that no vector held: `chain-without-its-first-delegation`, `chain-with-a-delegation-twice`, `delegation-for-another-subject`, `delegation-signed-in-its-authors-name`, `delegation-to-another-delegate`, `sub-delegation-drops-a-statement`, `sub-delegation-outlives-its-parent`, `delegation-not-yet-valid`, `delegation-made-after-the-proof` and `delegation-expired-beyond-the-tolerance`. Two of the controls stand exactly at a limit: a delegation that starts 300 seconds after the proof, and a proof 300 seconds past an expiry.

Item 7 has no vector: the vectors take every log as known in full. Item 3 is tested by a unit test and by the differential campaign, since a record with a malformed policy is rejected before its policy is evaluated. Items 10, 12 and 15 change no answer in either implementation.

The vectors now hold 31 must-accept cases, 126 negative cases and 75 controls.

## Reference implementation

`@oip/delegation` and `@oip/web` (BUILD.md, M3) and the Python checker `spec/test-vectors/oip_vectors.py` implement every item, except that the checker takes every log as complete and so has nothing to do for item 7. Differential tests compare the two on generated policies, on generated delegation chains with a record signed under each, and on generated sets of Layer 2 records whose status is asked; and, made by hand with the answer each must give, on 63 policies and on every way a chain that counts is changed, one at a time.

## Open questions

- **A bound on the work of a policy.** A quantifier tries its statement on every element of an array, and quantifiers nest, so a policy of a few statements can ask for work in proportion to the square, or a higher power, of a record of 1 MiB. The reference implementation stops at 100,000 evaluations of a statement and treats the policy as not holding; the Python checker has no bound. Two verifiers could therefore disagree about a record built to cost that much. A later revision should name the bound, or limit the arrays a quantifier may range over.
- **Supersession of other Layer 2 records.** Section 2 lets any Layer 2 record carry `supersedes`. Section 8 says what that does to an Intent, an Offer and a Receipt, and nothing for a Commitment or a charter. Both implementations take it to do nothing there.
- **The charter of a duplicitous collective.** 8.4 calls a charter `dissolved` if the collective's log is retired, and `active` otherwise. After duplicity nobody can sign for the collective, under its threshold or through a role, and its charter still reads `active`.
- **The other "integers" of Layer 1** (`Location.seq`, `maxHops`, a query's `limit`), and the members of inline objects there (an endpoint's `priority`, `Resume.lastSent`, a result's `hints`), are left to the milestone that implements them.
- **The clause each negative case breaks** (OEP-0002's last open question) is still open. Each new negative case here names its clause in its reason, in prose.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
