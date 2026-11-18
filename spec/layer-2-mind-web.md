# OIP Layer 2: the Mind Web

**Revision 2026-11-17 · Status: Draft · Licensed under CC BY 4.0**

This document specifies the linked primitives through which minds coordinate: Participant, Intent, Offer, Commitment, Receipt and Collective. It depends on [core.md](core.md) and [layer-1-mind-network.md](layer-1-mind-network.md). Rationale is in Section 6 of the [technical architecture paper](../papers/02-technical-architecture.md).

## 1. Principles

1.1. The meaning of a Layer 2 record is fixed by its signed content. Implementations MUST NOT infer obligations from anything other than signed records.

1.2. Records are immutable. A change of state is expressed by a new record that links to the old one.

1.3. The status of a record is computed by the functions in Section 8 from the set of records a verifier knows and the time of computation.

## 2. Common members

Every Layer 2 record has the core common members (core, Section 7) and MAY have:

| Member | Value |
|---|---|
| `supersedes` | A `record-ref` to an earlier record of the same `type` by the same `author`, which this record replaces |
| `status` | Only in a superseding record; the new status (Section 8): `withdrawn` or `satisfied` on an Intent, `withdrawn` on an Offer. A superseding record with any other `status` is neither a withdrawal nor an edit (4.3), and changes nothing |
| `links` | Array of `{ "rel": <string>, "ref": <record-ref or URL> }`, both REQUIRED |

Every Layer 2 record MUST carry at least one proof that counts for its `author` (Section 7). A proof made through a delegation lists the delegations in its own `authority` (core 5.2; Layer 1, Section 11.6), and a proof made under a charter role names the charter there (Section 7.1), never in the record. Proofs are added to a record without changing its content ID (core 3.1), so every copy of a record with the same content ID is the same record, and a verifier SHOULD judge it with the proofs of every copy it holds (5.3).

## 3. Participant

The Participant record is defined in Layer 1, Section 16.

## 4. Intent and Offer

4.1. **`Intent`**:

| Member | Required | Value |
|---|---|---|
| `want` | yes | Plain-language statement of the outcome sought, at most 4096 characters |
| `subject` | no | Structured description in any vocabulary |
| `constraints` | no | Object; recognised members include `deadline` (timestamp), `budget` (`{ "max": <amount>, "currency": <ISO 4217 code or asset name> }`, of which `max` is REQUIRED and `currency` optional) and `requires` (array of tags) |
| `audience` | no | `"public"` (default); an array of addresses; a collective's address; or `{ "query": <capability query> }` (Layer 1, Section 18.2) |

4.2. **`Offer`**:

| Member | Required | Value |
|---|---|---|
| `provides` | yes | Plain-language statement of what is offered, at most 4096 characters |
| `terms` | yes | Object with REQUIRED `summary` (plain language) and optional `price` (`{ "amount": <amount>, "currency": … }`, both REQUIRED), `deliveryBy` (timestamp), `quantity` (an integer of at least 1: how many times the Offer can be taken up) and `conditions` (array of strings) |
| `answers` | no | `record-ref` of an Intent |
| `capability` | no | A capability `id` from the author's Participant profile |
| `subject` | no | Structured description |
| `audience` | no | As for an Intent |

Amounts are non-negative decimal strings (core 1.3).

4.3. **Withdrawals and edits.** A withdrawal is a superseding record (Section 2) with `status` `withdrawn`; an edit is a superseding record without `status`. Both restate the required members of the record they replace (an Intent's `want`, an Offer's `provides` and `terms`).

## 5. Commitment

5.1. **`Commitment`**:

| Member | Required | Value |
|---|---|---|
| `parties` | yes | 2–64 objects `{ "mind": <address>, "role": <string>, "required": <boolean, default false> }`. Roles: `debtor` (owes performance), `creditor` (is owed it), `witness`, or a namespaced role. Each mind appears at most once. At least one party MUST be a `debtor` and at least one a `creditor`, and every debtor and creditor MUST be `required`. |
| `promise` | yes | Plain-language statement of who will do what for whom, at most 8192 characters |
| `terms` | yes | Object; recognised members include `deadline`, `deliverables`, `price`, `conditions` and `selfReport` (boolean, default false). `price` is `{ "amount": <amount>, "currency": …, "payer": <address>, "payee": <address> }`, where all four are REQUIRED and `payer` and `payee` are two different parties, so that a delegation's policy can check who pays whom |
| `resolves` | no | `record-ref`s of Intents and Offers this Commitment settles |
| `closesIntent` | no | Boolean, default false |
| `onBehalfOf` | no | A collective's address, when the debtor acts for a collective. Informational only: the collective is bound only if it is itself a party |

5.2. The `author` of a Commitment MUST be one of its parties, or a mind whose proof on it counts for a party through a delegation or a charter role (Section 7.1, items 2 and 4). A Commitment whose author is neither is never accepted.

5.3. Additional signatures are added by appending proofs. Adding proofs does not change the content ID (core 3.1); every copy of a Commitment with the same content ID is the same Commitment, and a verifier SHOULD merge the proof sets of all copies it holds.

5.4. **Parties bound through a delegate.** A party whose proof on a Commitment counts only through a delegation or a charter role (Section 7.1, items 2 and 4) is bound by the Commitment's structured `terms`. Where the plain-language `promise` states more than the `terms` (a higher price, a different payer, an extra obligation), the `terms` prevail for that party, because the delegation's policy could check only them. Displays SHOULD show such a party's commitment together with the policy under which it was made.

## 6. Receipt and Collective

6.1. **`Receipt`**:

| Member | Required | Value |
|---|---|---|
| `about` | yes | `record-ref` of the record concerned, usually a Commitment |
| `outcome` | yes | `accepted`, `progress`, `fulfilled`, `broken`, `cancelled`, `disputed`, `revoked`, or a namespaced outcome `<namespace>:<name>` |
| `statement` | no | Plain language, at most 8192 characters |
| `evidence` | no | Array of evidence items (Section 9), at most 64 |
| `rating` | no | `{ "score": <decimal string from "0" to "1"> }` |

A Receipt with outcome `revoked` MUST supersede an earlier Receipt by the same author; the superseded Receipt no longer counts.

6.2. **`Collective`** (a charter):

| Member | Required | Value |
|---|---|---|
| `author` | yes | The collective's address |
| `name` | yes | At most 128 characters |
| `purpose` | yes | Plain language |
| `roles` | no | Object mapping role names to `{ "purpose": <string>, "powers": [ { "command": <command>, "policy": <policy> } ] }`. `purpose` and `powers` are optional, and a role without powers grants nothing. In a power, `command` is REQUIRED and `policy` defaults to `[]` |
| `assignments` | no | Array of `{ "mind": <member address>, "role": <role name> }`, both REQUIRED |
| `procedures` | no | Object; decision procedures defined by extensions |

Membership and the base threshold are defined only by the collective's identity log (Layer 1, Section 9) and MUST NOT be inferred from a charter. A charter MUST be signed by the collective's own authority (Section 7.2): its member threshold (Layer 1, Section 9.5) or an operational key the collective has authorised. The charter **in force** at time `t` is the charter whose signature for the collective was completed most recently at or before `t`; if two were completed at the same time, the one with the lower content ID. A charter is completed at the earliest time at which it is signed for the collective, judged with the proofs of every copy the verifier holds (Section 2): a copy that lacks the proofs which completed a charter early does not make it a later charter. A charter that another charter of the collective names in `supersedes` is in force at no time from that other charter's completion on, whichever of the two was completed first and whoever signs the superseded one afterwards. A collective that replaces a charter SHOULD name it in `supersedes`, which is how a charter is ended for good. Role powers use the commands and policies of Layer 1, Section 11; reserved commands grant nothing, and charters SHOULD exclude a role holder as a party to the records its role signs, as delegations do (Layer 1, Section 11.3). An assignment is effective only while the assigned mind is a member.

A threshold of signatures can be completed at any time, so a member's signature on an abandoned charter or proposal remains usable, and a verifier that holds only some of a charter's proofs may take it for a charter completed later than it was. Superseding the charter closes both. A charter MAY carry `expires`, which bounds when it can be signed (core 9.6), not how long it stays in force; members SHOULD sign charters, and other records that wait for a threshold, only when they carry an `expires`.

## 7. Signing for a party

7.1. A record `r` **counts for** mind `P` (is signed by `P`) at the earliest evaluation time at which any of the following holds:
1. **Own key.** `r` carries a proof by a valid operational key of `P` (Layer 1, Section 6).
2. **Delegation.** `r`'s type is delegable (7.2), and `r` carries a proof `p` by a valid operational key of a mind `D`, whose `authority` lists exactly a chain from `P` to `D` that is valid for `r` and `p` under Layer 1, Sections 11.4 and 11.6.
3. **Collective threshold.** `P` is a collective and `r` is signed by it under Layer 1, Section 9.5: by members' proofs without `authority`, each by that member's own valid operational key, meeting the threshold of `P`'s state at that time, or, for a record that describes `P`'s current state (`Location`, `Participant`), of `P`'s latest state.
4. **Collective role.** `r`'s type is delegable, `P` is a collective, and `r` carries a proof `p` by a valid operational key of a member `M` of `P`'s state at `t(p)`, whose `authority` names exactly one charter of `P` (a `record-ref`, or the inline `Collective` record, which is the same charter as any copy the verifier holds and is judged with the proofs of them all, 6.2) that is the charter in force at `t(p)`, in which `M` is assigned to a role that has a power whose `command` covers `/oip/sign/<r.type>` and whose `policy` holds for `r`. As for a threshold, the verifier holds `P`'s log as served no earlier than the evidence for `p` (core 9.4), for a copy older than that may lack the event that removed `M`; and if `P` is duplicitous, `t(p)` is before its first conflicting event, from which on its members are not known (Layer 1, Section 7.3).

In every case, a proof whose evaluation time is more than 300 seconds after `r.expires` does not count (core 9.6). A proof thus counts for its signer's own mind and, through its `authority`, for at most one other mind, and acting for another mind is always a choice the proof states and signs. A delegate or role holder that is itself a party binds its principal to itself only if the policy it acts under allows that, so policies SHOULD exclude it (Layer 1, Section 11.3).

7.2. **Delegable types** are `Intent`, `Offer`, `Commitment` and `Receipt`. Every other signed record (including `Delegation`, `Revocation`, `Collective`, `Lineage`, identity events and current-state records) counts for its author only through items 1 and 3, the author's **own authority**. A delegate can therefore never create, widen or revoke authority in its principal's name.

7.3. A Commitment is **accepted** when it counts for its `author`, its author is a party or signs for one (5.2), and it counts for every party with `required` true.

## 8. Status

Status is computed from the records known to the verifier and the time of computation, and so can differ between verifiers and change over time. The time of computation is compared with `expires` and with a deadline exactly: a status is a statement at a time, and the tolerance of core 9.1 is for judging signatures. `expires` or a deadline "has passed" at any later time, and not at the instant it names. Whether a record counts for a mind is asked of the records and the evidence the verifier holds, and not of the time of computation. Implementations MUST implement the following functions exactly. A superseding record that carries `status` (Section 2) has that status itself. When several valid superseding records by the record's author exist, `satisfied` takes precedence over `withdrawn`, and `withdrawn` over an edit; among records of equal standing, the one with the earlier evaluation time wins, then the one with the lower content ID.

8.1. **Intent.** `withdrawn` or `satisfied` if a valid superseding Intent by the same author has that `status`; otherwise `superseded` if a valid edit (4.3) by the same author supersedes it; otherwise `satisfied` if an accepted Commitment that also counts for the Intent's author lists it in `resolves` with `closesIntent` true; otherwise `expired` if `expires` has passed; otherwise `open`. Other minds cannot close someone's Intent by committing among themselves.

8.2. **Offer.** `withdrawn` if a valid superseding Offer by the same author has that status; otherwise `superseded` if a valid edit by the same author supersedes it; otherwise `expired` if `expires` has passed; otherwise `exhausted` if `terms.quantity` is present and at least that many accepted Commitments that also count for the Offer's author list it in `resolves`; otherwise `open`.

8.3. **Commitment.** Let `R` be the set of Receipts about the Commitment whose `author` is a party and that count for their author, excluding Receipts with outcome `revoked` and Receipts superseded by another Receipt about the same Commitment, of the same author: one in which `supersedes` names it, whose author is a party and which counts for its author. A Receipt that names another author's Receipt in `supersedes` supersedes nothing.
1. If the Commitment is not accepted (7.3): `disputed` if it would be accepted were compromise declarations (Layer 1, Section 6.2) disregarded, every mind's and not the parties' alone, because a signature it rests on was withdrawn by a declaration that a key was compromised; otherwise `proposed`.
2. If one or more `cancelled` Receipts in `R` together have proofs counting for every required party: `cancelled`.
3. Let `F` be the `fulfilled` Receipts in `R`. If a Receipt in `F` counts for a creditor, or `terms.selfReport` is true and `F` is non-empty, the candidate status is `fulfilled`; otherwise, if `F` is non-empty, it is `claimed-fulfilled`; otherwise it is `accepted`.
4. If `R` contains a `broken` or `disputed` Receipt and the candidate status is `fulfilled` or `claimed-fulfilled`: `disputed`.
5. If `R` contains a `broken` Receipt and the candidate is `accepted`: `broken`.
6. If `R` contains a `disputed` Receipt and the candidate is `accepted`: `disputed`.
7. If the candidate is `accepted` and `terms.deadline` has passed: `overdue`.
8. Otherwise, the candidate.

A `broken` status is a claim attributable to the authors of the `broken` Receipts; displays SHOULD show who made it.

8.4. **Collective charter.** `dissolved` if the collective's identity log is retired; otherwise `active`.

## 9. Evidence

An evidence item is an object:

| Member | Required | Value |
|---|---|---|
| `kind` | yes | `oip`, `uri`, `hash`, `vc`, `payment`, `log`, or a namespaced kind |
| `ref` | yes | A record-ref, URL, credential reference, transaction identifier or log reference |
| `digest` | for `uri` and `hash` | `"sha256:<64 lower-case hex digits>"` of the exact bytes |
| `mediaType` | no | Media type |
| `note` | no | Plain language |
| `ext` | no | For `payment`, the rail's namespace and its native proof object |

A verifier that fetches a `uri` item MUST check its digest.

## 10. Publication

10.1. Records MAY be published in feeds (Layer 1, Section 10), exchanged privately in packets, or both. Publication does not change a record.

10.2. A party to a Commitment SHOULD list it in its own feed once it has signed, with the entry committing to the proofs it then carries, and SHOULD publish the Receipts it authors. Anchored checkpoints over those entries keep the Commitment verifiable after the delegations and keys that signed it expire or are removed (core 9.7).

10.3. Backlinks (for example, which Offers answer an Intent) are computed by indexers and clients. The protocol defines no global index.

## 11. Extensions

11.1. Payment terms appear in `ext` blocks under the payment rail's namespace (`x402`, `ap2`, `acp`, `l402`), carrying the rail's native objects. Proof of payment appears as an evidence item of kind `payment`. Layer 0, Section 8 gives the conventions.

11.2. New outcomes, roles, evidence kinds and decision procedures MUST be namespaced. Records whose correct handling depends on an extension MUST list it in `critical`.
