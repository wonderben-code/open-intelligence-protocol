# OIP Layer 2: the Mind Web

**Revision 2026-10-30 · Status: Draft · Licensed under CC BY 4.0**

This document specifies the linked primitives through which minds coordinate: Participant, Intent, Offer, Commitment, Receipt and Collective. It depends on [core.md](core.md) and [layer-1-mind-network.md](layer-1-mind-network.md). Rationale is in Section 6 of the [technical architecture paper](../papers/02-technical-architecture.md).

## 1. Principles

1.1. The meaning of a Layer 2 record is fixed by its signed content. Implementations MUST NOT infer obligations from anything other than signed records.

1.2. Records are immutable. A change of state is expressed by a new record that links to the old one.

1.3. The status of a record is computed by the functions in Section 8 from the set of records a verifier knows.

## 2. Common members

Every Layer 2 record has the core common members (core, Section 7) and MAY have:

| Member | Value |
|---|---|
| `supersedes` | A `record-ref` to an earlier record of the same `type` by the same `author`, which this record replaces |
| `status` | Only in a superseding record; the new status (Section 8) |
| `links` | Array of `{ "rel": <string>, "ref": <record-ref or URL> }` |
| `authority` | Delegations relied on (Layer 1, Section 11.6) |

Every Layer 2 record MUST carry at least one proof that counts for its `author` (Section 7).

## 3. Participant

The Participant record is defined in Layer 1, Section 16.

## 4. Intent and Offer

4.1. **`Intent`**:

| Member | Required | Value |
|---|---|---|
| `want` | yes | Plain-language statement of the outcome sought, at most 4096 characters |
| `subject` | no | Structured description in any vocabulary |
| `constraints` | no | Object; recognised members include `deadline` (timestamp), `budget` (`{ "max": <decimal>, "currency": <ISO 4217 code or asset name> }`) and `requires` (array of tags) |
| `audience` | no | `"public"` (default); an array of addresses; a collective's address; or `{ "query": <capability query> }` (Layer 1, Section 18.2) |

4.2. **`Offer`**:

| Member | Required | Value |
|---|---|---|
| `provides` | yes | Plain-language statement of what is offered, at most 4096 characters |
| `terms` | yes | Object with REQUIRED `summary` (plain language) and optional `price` (`{ "amount": <decimal>, "currency": … }`), `deliveryBy` (timestamp), `quantity` (integer) and `conditions` (array of strings) |
| `answers` | no | `record-ref` of an Intent |
| `capability` | no | A capability `id` from the author's Participant profile |
| `subject` | no | Structured description |
| `audience` | no | As for an Intent |

## 5. Commitment

5.1. **`Commitment`**:

| Member | Required | Value |
|---|---|---|
| `parties` | yes | 2–64 objects `{ "mind": <address>, "role": <string>, "required": <boolean> }`. Roles: `debtor` (owes performance), `creditor` (is owed it), `witness`, or a namespaced role. At least one party MUST be a `debtor` and at least one a `creditor`, and every debtor and creditor MUST be `required`. |
| `promise` | yes | Plain-language statement of who will do what for whom, at most 8192 characters |
| `terms` | yes | Object; recognised members include `deadline`, `deliverables`, `price`, `conditions` and `selfReport` (boolean, default false) |
| `resolves` | no | `record-ref`s of Intents and Offers this Commitment settles |
| `closesIntent` | no | Boolean, default false |
| `onBehalfOf` | no | A collective's address, when the debtor acts for a collective |

5.2. The `author` of a Commitment MUST be one of its parties or a delegate of one (Section 7).

5.3. Additional signatures are added by appending proofs. Adding proofs does not change the content ID (core 3.3); every copy of a Commitment with the same content ID is the same Commitment, and a verifier SHOULD merge the proof sets of all copies it holds.

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
| `roles` | no | Object mapping role names to `{ "purpose": <string>, "powers": [ { "command": <command>, "policy": <policy> } ] }` |
| `assignments` | no | Array of `{ "mind": <member address>, "role": <role name> }` |
| `procedures` | no | Object; decision procedures defined by extensions |

Membership and the base threshold are defined only by the collective's identity log (Layer 1, Section 9) and MUST NOT be inferred from a charter. A charter MUST be signed by the collective under the threshold rule (Layer 1, Section 9.4, first alternative). The **current charter** is the most recent valid, unsuperseded Collective record authored by the collective. An assignment is effective only while the assigned mind is a member.

## 7. Signing for a party

7.1. A proof on record `r` **counts for** mind `P` if any of the following holds:
1. The proof is by a valid operational key of `P` (Layer 1, Section 6).
2. The proof is by a valid operational key of a mind `D`, and `r.authority` contains a delegation chain from `P` to `D` that is valid for `r` under Layer 1, Section 11.4.
3. `P` is a collective, and the collective threshold rule of Layer 1, Section 9.4 is satisfied by proofs on `r`; or a member of `P` assigned to a role in `P`'s current charter has a proof that counts for itself on `r`, and that role has a power whose `command` covers `/oip/sign/<r.type>` and whose `policy` holds for `r`.

7.2. A Commitment is **accepted** when every party with `required` true has at least one proof on it that counts for that party.

## 8. Status

Status is computed from the records known to the verifier at the time of computation. Implementations MUST implement the following functions exactly.

8.1. **Intent.** `withdrawn` or `satisfied` if a valid superseding Intent by the same author has that `status`; otherwise `satisfied` if an accepted Commitment lists it in `resolves` with `closesIntent` true; otherwise `expired` if `expires` has passed; otherwise `open`.

8.2. **Offer.** `withdrawn` if a valid superseding Offer has that status; otherwise `expired` if `expires` has passed; otherwise `exhausted` if `terms.quantity` is present and at least that many accepted Commitments list it in `resolves`; otherwise `open`.

8.3. **Commitment.** Let `R` be the set of valid Receipts about the Commitment whose `author` is a party, excluding superseded and revoked Receipts.
1. If the Commitment is not accepted (7.2): `proposed`.
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

10.2. A party to a Commitment SHOULD list it in its own feed once it has signed, and SHOULD publish the Receipts it authors.

10.3. Backlinks (for example, which Offers answer an Intent) are computed by indexers and clients. The protocol defines no global index.

## 11. Extensions

11.1. Payment terms appear in `ext` blocks under the payment rail's namespace (`x402`, `ap2`, `acp`, `l402`), carrying the rail's native objects. Proof of payment appears as an evidence item of kind `payment`. Layer 0, Section 8 gives the conventions.

11.2. New outcomes, roles, evidence kinds and decision procedures MUST be namespaced. Records whose correct handling depends on an extension MUST list it in `critical`.
