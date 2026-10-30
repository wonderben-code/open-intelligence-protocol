# Fix design for the paper review (30 October 2026)

How each finding in [2026-10-30-paper-review.md](2026-10-30-paper-review.md) is fixed, so the paper, the specifications and the test vectors change together and stay consistent. Findings from the specification review will be added when it completes. Work happens on branch `review-fixes`.

## 1. Time: evidence beats claims (C5, and parts of C6, I2, I5)

The single biggest change. A signer's own `created` is a claim, never evidence.

- **Evaluation time of a proof.** `t(p) = max(p.created, τ(p))`, where `τ(p)` is the earliest time for which the verifier holds evidence that the proof existed. With no evidence, `τ(p)` is the time the verifier first obtained the proof (so for anything received live, `t(p)` is "now"). A proof whose `created` is more than 300 s after `τ(p)` is rejected.
- **Evidence** (core, new Section 9): the verifier's own first-seen record; the first-seen record of a witness the verifier chooses to trust (its resolver or indexer); an anchored checkpoint covering a feed entry that commits to the proof; an `Ack` covering a packet that carries the proof. A proof's own `created` is never evidence. Because co-signatures cover only the record's content, one proof is never evidence for another.
- **Feeds commit to proofs.** `Entry` gains `proofs`: the SHA-256 digests of the proofs on the record as published, so an anchored checkpoint gives evidence for those exact proofs.
- **Every time rule uses `t(p)`:** key removal, key compromise, retirement, delegation `notBefore` and `expires`, revocation, collective membership and charter roles.
- **Revocations** take effect from their own evaluation time, so a backdated revocation cannot void records already evidenced.
- **Identity events are the controller's own statements about its own key state**, so a removal or compromise time in an identity event is taken at the event's `created`. A controller who backdates one is repudiating its own records, which is attributable. Identity events' `created` must now be non-decreasing.
- **Consequence, stated plainly in the paper:** to keep a record verifiable after the keys that signed it change, publish it in a feed whose checkpoints are anchored (or keep witness evidence). Without evidence a verifier evaluates a proof at the time it first sees it.

## 2. Key validity (C1, I1, I5)

One definition, `validKey`, used everywhere (paper Appendix A, spec Layer 1 Section 6, code):

A proof `p` by `did:oip:X?versionId=V#K` is by a valid operational key of `X` for record type `T` if and only if: `X`'s log verifies and contains `V`; `K` is an operational key at `V`; if a later event removes `K` (or retires the mind), `t(p)` is before that event's `created`; no revocation of `K` has `compromisedSince` at or before `t(p)`; `p.proofPurpose` is the one core 5.6 requires for `T`; and, for current-state records, `K` is in the latest state.

- **Removing a key** stops it signing anything new; **marking it compromised** also withdraws what it signed from the compromise time. This replaces "a removed key remains valid for its versions" (old spec 6.3) and corrects the paper's "rotating revokes everything" (I5).
- **DID document:** operational keys listed under `authentication`, `assertionMethod`, `capabilityInvocation` and `capabilityDelegation`; when produced for a `versionId`, verification-method ids use the versioned form, so exact-id matching in generic Data Integrity verifiers works.

## 3. Thresholds and parameters (C2, I3, part of C6)

- Thresholds count **distinct** keys and **distinct** members, everywhere.
- Key controller: `keys` 1–16 distinct; `next` 0–16 distinct; `nextThreshold` an integer with `1 ≤ t ≤ |next|` and **`2t > |next|`**. Member controller: 1–256 distinct members, not the collective itself; **`1 ≤ threshold ≤ n` and `2·threshold > n`**. Majority thresholds mean any two valid conflicting events share a signer, so duplicity is always attributable.
- Every event's `type` is checked; `Merge` is reserved and a v1 verifier rejects a log containing it; nothing follows `Retire` (key- or member-controlled); `Genesis` has no `mind`, `seq` or `prev`; `recovery` is a reserved member name and v1 verifiers reject events containing it (I12).

## 4. Forks of an identity log (C6)

- Never choose between conflicting branches by length or freshness.
- **v1 resolution rule:** the branch whose event at the point of divergence has the earlier evidence (first-seen by the verifier or a trusted witness, or anchored) wins; if evidence cannot separate them, the mind is duplicitous and its records after the divergence are not accepted. Records pinned to versions before the divergence stay valid.
- Implementations destroy control keys once the event they sign is published; minds publish identity events to at least two independent witnesses.
- Custody handover is safe once the handover event is witnessed: the former custodian can only create detectable duplicity, which the rule resolves against it.
- **Routine forks without control keys (I8):** a new Layer 1 record, `Lineage`, signed by an operational key of the parent, acknowledges a child. A `Fork` event remains for lineage recorded in the identity log itself.

## 5. Delegation (C3, C4, I14)

- **Delegable record types:** `Intent`, `Offer`, `Commitment`, `Receipt` (commands `/oip/sign/<Type>`) and packets (`/oip/send`). Everything else must be signed by the author's own authority: `Delegation`, `Revocation`, `Collective`, `Lineage`, identity events and current-state records.
- `/oip`, `/oip/sign` and `/oip/publish` are reserved: no blanket grants in v1. Extension commands live under their own first segment.
- **Policies:** ordering operators are true only when both values are decimals (core 1.3) or integers; no string ordering. Equality compares decimals numerically and other values by canonical form.
- **Amounts** (`price.amount`, `budget.max`) are non-negative decimals.
- **Delegated commitments:** the structured `terms` bind a party that signed through a delegation; where the plain-language `promise` says more, `terms` prevail for that party. Policies should constrain every term that matters; the worked example now pins currency as well as amount.
- `Delegation.chain` is removed: the record's `authority` lists the whole chain, root first, which matches UCAN 1.0 (invocations carry `prf`). UCAN is described as a release candidate.

## 6. Collectives (I2)

- A member's proof counts only if it is by one of that member's own valid operational keys. A collective that is a member of another collective signs with operational keys it has authorised through `keys`; recursive threshold signing is reserved.
- **Acting as one:** a record is signed by a collective at the earliest time `T` at which the members of the collective's state at `T` holding proofs with `t(p) ≤ T` reach that state's threshold. The state at `T` is the state after the last identity event whose `created` is at or before `T`. Role powers use the charter in force at `t(p)`.
- **Limits:** at most 256 proofs per record; collective nesting depth 4 for log verification.

## 7. Layer 2 status (I9, minor)

- An Intent becomes `satisfied` only through an accepted Commitment that its author is a required party to. An Offer is `exhausted` only by accepted Commitments its author is a required party to.
- The lifecycle table, Appendix A.6 and spec 8.3 are aligned (including `claimed-fulfilled`, `disputed`, `overdue`, several `cancelled` Receipts); status depends on the evaluation time, which is stated.

## 8. Sessions, feeds and hosts (I6, I7, pre-identified fixes)

- Any verb may open a session; the first packet carries the `Session` record. The vector packet now does, with a nonce of at least 8 characters.
- Session chains are per sender and instance (packets may carry `instance`); a feed has a single writer at a time. Entries made invalid by a compromise do not count as equivocation.
- Moving away from a host that holds one of the mind's operational keys requires removing that key; until then the host can publish competing location records.

## 9. Bridges and claims (I10–I13)

- A bridged mind's genesis carries the `oip.bridge` block and a proof by an operational key of its gateway; without that proof the label is only `claimed`. Undeclared bridging cannot be detected, which the paper says.
- §7.2 adds the OIP MCP server rules (keys outside the model's context; confirmation before signing commitments and delegations) and no longer says separating content from authority stops prompt injection.
- The roadmap marks recovery, merge and new key types as rule changes, not format-only changes.
- Novelty is claimed for the combination, with prior art cited: KERI (including delegated inception), did:keri and did:peer:4, Safe and KERI multisig, Ricardian contracts, Singh's commitments, EAS, and the 2026 Proof-of-Descendancy thesis.

## 10. Test vectors

- The generator implements `validKey`, evaluation times, delegation chains, policies, revocation, compromise, collective threshold and role signing, and Layer 2 status (A.6).
- New **negative vectors**, each with the reason it must fail: duplicate control key in a threshold; forged rotation correctly signed by a key outside `next` (pre-rotation, not the signature, rejects it); `nextThreshold` 0; collective `threshold` 0; event after `Retire`; minority threshold; wrong proof purpose; delegated signature by a key not in the signer's log; delegate signing a `Delegation` for its principal; policy bypass by currency, negative amount and non-decimal strings; backdated proof by a removed key; backdated proof by a compromised key; use of an expired delegation with a backdated `created`; revoked delegation; removed collective member; outsider closing someone else's Intent.
- The reviewer's independent checker (`reviews/spec-review-workfiles/indep_check.py`) is run against the new vectors as a second implementation.
