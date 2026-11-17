# OIP specification review: revision 2026-10-30

**Reviewer:** independent implementer review, 30 October 2026.
**Scope:** `spec/README.md`, `spec/core.md`, `spec/layer-1-mind-network.md` (L1), `spec/layer-2-mind-web.md` (L2) and `spec/layer-0-bridge.md` (L0). I checked them against `spec/test-vectors/vectors.json` and `oip_vectors.py`, and used BUILD.md and Paper 2 for context only. Section numbers refer to the spec documents unless they are prefixed "paper".

## What I checked

- `python3 -I spec/test-vectors/oip_vectors.py --check` passes all 9 checks.
- **Independent check.** I wrote a second implementation from the spec text only, without importing `oip_vectors.py`. It covers JCS, content IDs, Multikey, `eddsa-jcs-2022`, log replay, key validity, the policy language, counts-for and Commitment status. Run against every record in `vectors.json`:
  - all 24 proofs verify;
  - every content ID, address, key hash, Multikey and the JCS example is reproduced;
  - all 24 verification methods match the core 6.1 grammar;
  - every proof purpose matches core 5.6.
  - Commitment status reproduces as expected: `proposed`, then `accepted`, `overdue` after the deadline, and `fulfilled` with Amina's Receipt.
- **The only vector record that fails the spec is the packet** (see C5).
- **Attack probes.** I built attack records and ran them through `oip_vectors.py`.
- No repository file other than this one was changed. The scratch scripts are outside the repository.

Severity levels:
- **Critical:** blocks a safe or conformant implementation.
- **Important:** a real attack or failure, or a point where an implementer must guess.
- **Minor:** editorial issues and small gaps.

### Findings by requested category

| Category | Findings |
|---|---|
| 1. Conflicts with vectors or `oip_vectors.py` | C2, C5, I20, I21 |
| 2. Cross-reference errors | M1 |
| 3. Ambiguities | I3–I7, I10, I12–I14, I16, I19, M3 |
| 4. Logic and security flaws | C1–C4, I1, I2, I8, I9, I11, I15, I17, I18 |
| 5. Internal inconsistencies | C4 (L1 6.2 vs 10.4), I1 (L1 3.11 vs 5.2), I2 (L1 17.1 vs 7.2), I6 (L1 11.2 vs 10.1/12.1), I11 (L1 9.4 vs L2 7.1), C5 (L1 12.1 vs 14.3), M2 |

---

## Critical

### C1. Backdating defeats revocation, expiry and key removal, and lets signers repudiate

**Where:** L1 6.1, 6.3, 9.4, 11.4 (items 5 and 7), 11.5 and 12.4; core 9.2.

**Problem.** Every one of these rules is evaluated against a `created` value that the signer writes. Core 9.2 itself says `created` is self-asserted. This allows four attacks:

- **Thief.** Someone holding a stolen operational key pins an old `versionId` and sets the proof's `created` before `compromisedSince`. The proof is then valid under 6.1. This works for Commitments, Delegations, Receipts and Packets. Only the record types listed in 6.2 are protected.
- **Delegate.** Items 5 and 7 of 11.4 test expiry, `notBefore` and revocation only against `r.created`, which the delegate writes. A delegate keeps using an expired or revoked delegation by backdating. 11.5 calls short expiry "the primary defence", but it defends nothing.
- **Removed key.** Under 6.3, a key removed without a compromise time stays valid forever for proofs pinned to older versions, and 12.4 applies this to packets too.
  - After a custody handover (L0 6), the gateway can go on signing as the person.
  - A departed employee's device key can go on signing for the institution.
- **Repudiation.** Amina can publish an `Update` that revokes `amina-phone` with `compromisedSince` set to 2026-10-30T10:00:00Z. Her proof on the accepted vector Commitment (created 10:22) then stops counting, and its status falls back to `proposed`. The same key signed the collective's genesis at 09:20, so the collective's log now fails L1 4.1. The collective, its charter and everything signed under it become invalid. **Any member can destroy any collective it helped found.**

**Evidence.**
- Each attack follows directly from the text.
- `oip_vectors.py` implements none of `revoked`, `compromisedSince`, `notBefore` or `Revocation`, so no vector exercises them.
- `oip_vectors.py` compares the expiry check as strings. A Commitment created at `…10:20:00.5Z` still counts under a delegation that expires at `…10:20:00Z`.

**Fix.**
- Add to core 9:
  > 9.3. The **witnessed time** of a record, for a verifier, is the earliest of: when the verifier first received it; the anchor time of an anchored checkpoint (L1 10.6) covering it; and the `received` time of a valid `Ack` for it by a mind other than its author. Verifiers MUST store first-received times. Rules that defend against stolen, removed or revoked keys, and against expired or revoked delegations, use witnessed time, never `created`.
- Replace the last condition of L1 6.1 with:
  > …and K was not removed or revoked by an event E of X's log witnessed before the record was witnessed. If E gives `compromisedSince` c, a proof with `created` ≥ c also does not count, unless the record already carried a valid proof counting for another mind before E was witnessed.
- Delete L1 6.3, or limit it to records witnessed before the removal.
- L1 9.4: take membership "from the latest version witnessed before the record".
- L1 11.4 item 5: "the witnessed time of r is within [`notBefore`, `expires`], allowing the core 9.1 skew".
- L1 11.4 item 7: "…by a Revocation witnessed before r".
- Add: "A verifier MUST NOT re-evaluate another mind's identity event that it accepted before it witnessed a revocation affecting that event."

### C2. Delegation spending limits can be bypassed with crafted strings

**Where:** L1 11.3; L2 5.1 (a Commitment's `terms.price` has no defined type); core 1.3.

**Problem.**
- If either operand is not an integer or a decimal string, the ordering operators fall back to comparing strings by code point. With the vectors' own policy `["<=", ".terms.price.amount", "500"]`, the amounts `"4,000,000"`, `"0500000"` and `"1e9"` all pass, because `"4"`, `"0"` and `"1"` sort before `"5"`.
- L2 types `price` for Offers (4.2) but not for Commitments, so schema validation does not catch these values.
- Timestamps are also compared as strings: `"…00:00.5Z" <= "…00:00Z"` is true, because `.` sorts before `Z`.
- The vector policy never constrains the currency, so 500 BTC also passes.

**Evidence.** I re-signed the vector Commitment with the agent's key, binding Lexis Ltd to **"4,000,000" USD**, and separately to 500 BTC. Under the spec text, and in `oip_vectors.verify_signed_by`, both **count for Lexis Ltd** under its 500 cap.
- `oip_vectors.py` also disagrees with the spec on `"0500000"` and `"1e9"`: Python's `Decimal` parses them, so it rejects where the spec text accepts.

**Fix.**
- Replace the third bullet of L1 11.3 with:
  > If both operands are integers or decimal strings, compare them numerically using exact decimal arithmetic (never binary floating point). If both are timestamps, compare them as instants. If exactly one operand is an integer or decimal string, the statement is false. Otherwise `==` and `!=` compare JCS forms; ordering operators compare two strings by code point and are false for other types.
- Add to L2 5.1: "`price`: `{ "amount": <decimal>, "currency": <string> }`, as in an Offer".
- Add `["==", ".terms.price.currency", "USD"]` to the vector policy and the paper example.

### C3. Any third party can close another mind's Intent or exhaust its Offer

**Where:** L2 8.1 and 8.2.

**Problem.** The status rules "an accepted Commitment lists it in `resolves` with `closesIntent` true" and "at least that many accepted Commitments list it in `resolves`" say nothing about who the parties are. Two throwaway addresses can make an accepted Commitment between themselves that closes the victim's Intent. Repeated `terms.quantity` times, the same trick exhausts the victim's Offer. Indexers then drop both. This is a free griefing attack on the market itself.

**Fix.**
- 8.1: "satisfied if an accepted Commitment **with a proof counting for the Intent's author** lists it in `resolves` with `closesIntent` true".
- 8.2: "at least that many accepted Commitments, **each with a proof counting for the Offer's author**, list it in `resolves`".

### C4. A routine key rotation invalidates a mind's whole feed history, its checkpoints and its Acks

**Where:** L1 6.2, which lists `Entry`, `Checkpoint`, `Ack` and `QueryResult` alongside `Location`, `Participant` and `Hello`; L1 10.4 and 10.6.

**Problem.** Entries, checkpoints and Acks are historical records. Under 6.2, every one signed with key K fails once K leaves the key set, even when no compromise is recorded.
- This contradicts 10.4, under which entries made before a compromise stay valid and the feed continues "from its last valid entry". After rotation there is no valid entry left.
- It also makes anchored checkpoints (10.6) worthless.

**Evidence.** I appended an `Update` that replaces `lexis-agent-i1` to the agent's log. The key that signed the vector feed entry is no longer in the latest state, so the entry fails 6.2.

**Fix.**
- Limit 6.2 to records that only have meaning as current state: `Location`, `Participant` used as the current profile, `Hello`, `Packet`, `Forwarded`, and the HTTP signatures of 13.3.
- `Entry`, `Checkpoint`, `Ack` and `QueryResult` then follow 6.1, with the witnessed-time rule from C1.
- Adding `Packet` also closes the removed-key packet hole described in C1.

### C5. The vector packet is invalid under the spec that requires it to be reproduced

**Where:** `vectors.json`, `cases.packet`; L1 12.1, 14.2 and 14.3; `spec/README.md`, "Conformance profiles".

**Problem.**
1. `"nonce": "p1"` breaks 12.1, which requires a nonce of 8 to 64 characters.
2. The packet has `session` and `seq: 0` but no `prev`. 12.1 says `session`, `seq` and `prev` appear "together", while 14.3 says `prev` appears only after the first packet. The vector follows 14.3, so the spec contradicts itself.
3. This is Lexis's first packet in the session, yet it has verb `propose` and no `Session` record. 14.2 requires verb `open` with the Session record "unless the receiver has already been shown it", and nothing in the vectors shows it.

The README says implementations "MUST reproduce every value", and BUILD M1 requires every vector to verify. A validating implementation must reject this packet, so it cannot meet both requirements.

**Fix.**
- Regenerate the packet with a nonce of at least 8 characters, for example `"p1-7Hq2vX9a"`.
- Either carry the Session in the packet's content as `{"parts": [ <Session>, <Offer> ]}`, or add Amina's opening packet to the vectors.
- 12.1 row: "`session`, `seq`: together. `prev`: REQUIRED when `seq` > 0, absent when `seq` = 0."
- 14.2: "The first packet each participant sends in a session MUST carry the Session record in `content`, as the body or a part; its verb SHOULD be `open`."
  - This drops the unverifiable "already shown" exception.
  - It also resolves the clash between the verbs `open` and `propose`.

---

## Important

### I1. A collective's identity is controlled by its members' everyday keys, and generic verifiers reject its events

**Where:** L1 3.11, 4.1, 4.4, 9.2 and 5.2.

**Problem.**
- Collective events (adding or removing members, changing the threshold, `Retire`) are authorised by members' **operational** keys. Stealing the device keys of `threshold` members therefore takes over the collective's identity. Pre-rotation exists to prevent exactly that: paper 5.2 says "stealing an operational key does not let an attacker change the identity log".
- Member proofs on identity events use the purpose `capabilityInvocation`. But 5.2 lists operational keys only under `authentication`, `assertionMethod` and `capabilityDelegation`, so a generic Data Integrity verifier rejects every member proof on a collective event.

**Fix.**
- Add a third key set to 3.5: `invocation`, holding at most 16 Ed25519 keys that may sign other minds' identity events as a member.
- Require member proofs under 4.1, 4.4 and 9.2 to use `invocation` keys, and list those keys under `capabilityInvocation` in 5.2.
- At a minimum, add `capabilityInvocation` for operational keys to 5.2 and document the weaker protection.

### I2. Duplicity can be faked, happens without any compromise, and is permanent

**Where:** L1 7.1–7.3, 10.3 and 17.1.

**Problem.**
- **(a) "Different" is not defined.** Proofs sit outside the content ID, and core 5.5 allows extra proofs. So anyone can add a junk proof to a real event or feed entry and submit it. An implementation that compares bytes then "detects duplicity", and 7.3 refuses every later record from that mind, with no resolution in this revision.
- **(b) Real duplicity needs no compromise.** Three ordinary situations produce it:
  - In a 2-of-5 collective, two disjoint quorums can each sign a different event.
  - Any holder of one of several `next` keys can sign an event when `nextThreshold` is 1.
  - A control key that has already been used can sign a conflicting event at its own position. I re-signed a different seq-1 event with `amina-control-1`, and it verifies against Amina's genesis.

  This contradicts paper 5.2: "Stealing a control key that has already been revealed is useless". One rogue holder can kill the mind for good.
- **(c) Longest log wins.** 17.1 serves "the longest valid log", which hands an attacker's longer fork priority over the first-seen events kept under 7.2 and 17.2.

**Fix.**
- 7.1 and 10.3: "…with **different content IDs**".
- 17.1: "the log made of the first-seen valid event at each position".
- 3.4: "`threshold` SHOULD exceed half the members, and `nextThreshold` half of `next`", so that any two quorums share a signer.
- 3.11: "Controllers MUST destroy the private keys an event reveals once it is published."
- Define a v1 outcome in 7.3 instead of deferring it. For example: keep accepting records pinned at or before the last version before the fork, and nothing newer.

### I3. The Ed25519 verification rule is ambiguous, and BUILD.md's recommended library conflicts with it

**Where:** core 5.4; BUILD.md §3.

**Problem.** "Verify under RFC 8032, rejecting non-canonical encodings" leaves two things open:
- Whether the verification equation is cofactored or cofactorless. RFC 8032 allows either.
- Whether small-order or mixed-order public keys (A) and signature commitments (R) are rejected.

Common libraries already disagree on both points:
- OpenSSL, which `oip_vectors.py` uses through `cryptography`, compares the re-encoded R, which is the cofactorless check.
- `@noble/curves` 1.9.1 always checks the cofactored equation (`edwards.js` line 421). By default (`VERIFY_DEFAULT = { zip215: true }`, line 16) it also accepts non-canonical encodings where y < 2²⁵⁶.

A malicious signer can therefore craft a proof that one verifier accepts and another rejects. Examples: a Commitment that the counterparty accepts but an arbiter rejects, or an identity event on which resolvers disagree, which splits their duplicity judgements.

**Fix.**
- Core 5.4: "Reject unless S < L, and A and R are canonical encodings (y < 2²⁵⁵−19) of points in the prime-order subgroup, and [S]B = R + [k]A." With torsion excluded, the cofactored and cofactorless equations agree.
- Add Ed25519 edge-case vectors.
- BUILD.md: pass `{ zip215: false }` and add an explicit subgroup check on R.

### I4. Record-reference matching is undefined

**Where:** core 6.3; L2 2 (`supersedes`), 6.1 (`about`), 8.1–8.3 (`resolves`, "Receipts about the Commitment").

**Problem.** The status functions must be implemented "exactly", but the spec never says whether `did:oip:A/<cid>` and `did:oip:B/<cid>` name the same record. The vectors use the Commitment's author (the agent, who is not a party) as the mind part, so whether a Receipt that cites `did:oip:<lexis_ltd>/<cid>` counts is open to interpretation.

**Fix.** Core 6.3: "A record-ref matches a record when its content ID equals the record's content ID. The mind part is a fetch hint and MUST be ignored when matching."

### I5. A content ID can be written in eight different ways

**Where:** core 3.2 and the 6.1 ABNF.

**Problem.**
- The 34 bytes of a content ID occupy 54.4 base32 characters, so the last character carries only 2 bits. Only `a`, `i`, `q` and `y` are canonical final characters.
- The regex `^b[a-z2-7]{55}$` accepts eight spellings of every ID. Lenient decoders map them all to the same bytes, while strict decoders reject seven of them.
- As a result, string comparison and byte comparison disagree on `prev`, addresses, duplicate detection and the `resolves` counts behind Offer exhaustion.

**Evidence.** The intent ID ending `…w5i` and the altered spelling ending `…w5j` both match the regex, and Python's `base64.b32decode` decodes both to identical bytes.

**Fix.**
- Core 3.2: use `^bciq[a-p][a-z2-7]{50}[aiqy]$`, which all 25 IDs in the vectors match.
- Add: "Content IDs are compared as strings; a non-canonical spelling MUST be rejected."
- Update the ABNF to match.

### I6. Delegation chains, collectives and commands are underspecified

**Where:** L1 11.1 (`chain`), 11.2, 11.4, 11.6, 10.1 and 12.1.

**Problem.**
- **(a) Chain assembly.** It is not specified whether `authority` holds only the leaf delegation, whose `chain` lists its ancestors, or the full sequence d₁…dₙ. Nor does the spec say how a verifier chooses among several chains.
- **(b) Collectives cannot delegate.** Item 1 of 11.4 requires the author's "valid operational key", so a collective without keys of its own can never delegate.
- **(c) Two commands cannot work.**
  - `/oip/publish` can never be exercised, because 10.1 requires an Entry to be signed by its author's own key.
  - `/oip/send` is never checked anywhere, because 12.1 requires a packet's proof to come from the key of its `from` mind.
- **(d) Policy input.** The spec does not say whether a policy is evaluated on the record with or without `proof`.

**Fix.**
- 11.6:
  > `authority` lists leaf delegations. Each leaf's `chain` lists d₁…dₙ₋₁, root first. Each dᵢ's own `chain`, if present, equals the first i−1 entries. Verifiers try every leaf.
- 11.4 item 1: "has a `capabilityDelegation` proof that counts for its author by route 1 or route 3 of L2 7.1".
- `/oip/send`: a receiver treats a packet as sent for P (`provenance.onBehalfOf` = P) only if `authority` holds a chain from P that covers `/oip/send`.
- `/oip/publish`: let route 2 count for an Entry's author.
- Policies are evaluated on the record without its `proof`.

### I7. Delegated co-signers cannot be added after the first signature

**Where:** L2 5.3 and 7.1(2); L1 11.6.

**Problem.** `authority` is part of the signed content (core 3.1). A second party who signs through a delegate must have its delegation listed before anyone signs. Adding it later changes the content ID and voids every existing proof, so "sign in any order" fails for delegated parties.

**Fix.** L2 7.1(2): "the verifier holds a chain from P to D that is valid for r. The chain may come from `r.authority` or from any other source, such as the packet's `authority` or an `accepted` Receipt." Chains verify themselves, so they do not need to be inside r.

### I8. Replay and authentication gaps

**Where:** L1 12.4, 13.3 and 13.4.

**Problem.**
- **(a) Packet lifetime is unbounded.** `created` can be arbitrarily old and `expires` arbitrarily late, and session packets need no `expires` at all. Duplicate-detection state may only be discarded after `expires`, so a receiver either remembers every ID forever or becomes open to replay.
- **(b) Duplicate-detection poisoning.** Nothing says to record a content ID only after the packet verifies. An attacker who first delivers a copy with a corrupt proof can cause the genuine packet to be discarded as a duplicate.
- **(c) WebSocket relay.** The server's `Challenge` carries `domain`. A client that copies it will sign for whatever origin a malicious server names. That server can relay a real server's challenge and log in there as the client.
- **(d) RFC 9421 requests.** Nothing requires rejecting a reused nonce or a stale `created`. No key-validity rule is given, and no Content-Digest algorithm.

**Fix.**
- 12.4: "Reject a packet whose `expires` − `created` exceeds P7D, or whose `created` is older than the receiver's duplicate window. Record a content ID only after verification. Session packets are also deduplicated by (`session`, `from`, `seq`)."
- 13.4: "The client MUST set `domain` to the origin it connected to and MUST NOT copy it from `Challenge`. The server MUST reject any other `domain`."
- 13.3: "Reject a signature whose `created` is outside now ± 300 s, that has expired, or whose (keyid, nonce) pair has already been seen. Apply 6.2. Content-Digest uses sha-256."

### I9. Retired minds keep signing

**Where:** L1 3.10, 4.5 and 6.1.

**Problem.** A `Retire` event does not clear the mind's keys. Its operational keys therefore keep producing valid proofs, including current-state records under 6.2 unless `keys` was emptied.

**Fix.** "The state after a `Retire` has no operational or agreement keys. Proofs by the mind on records witnessed after the `Retire` do not count."

### I10. Status functions have gaps around superseding records and ties

**Where:** L2 2, 6.2, 8.1 and 8.2; L1 15.2 and 16.4.

**Problem.**
- **(a) Withdrawal notices show as open.** A superseding Intent with `status: "withdrawn"` is still an Intent: it must carry `want`, and nothing supersedes it. So 8.1 computes it as `open`, and the withdrawal notice reappears at indexers as an open Intent. The same applies to Offers.
- **(b)** Conflicting superseding records have no precedence.
- **(c)** An edit (supersession without `status`) leaves the original record `open`.
- **(d) Competing charters.** The "most recent" charter is decided by the self-asserted `created`. Two quorums can publish competing charters, a future-dated one wins indefinitely, and there is no tie-break.
- **(e)** Two Location records with the same highest `seq` have no tie-break either.

**Fix.**
- "A record that carries `status` has that status and is never `open`."
- "A record superseded by a valid record without `status` is `superseded`."
- Precedence among superseding records: `satisfied` > `withdrawn`, then the earlier one, then the lower content ID.
- Current charter: "the valid charter that no other valid charter supersedes. Ignore records whose `created` is more than 300 s in the future. Break ties by later `created`, then lower content ID."
- Apply the same tie-break in 15.2.

### I11. Collectives: nesting, cycles and which point in time applies

**Where:** L1 4.7 and 9.4; L2 6.2 and 7.1(3).

**Problem.**
- **(a) Nesting needs a held key.** A member that is itself a collective can only give consent through its own operational key, because 9.2 requires "a valid operational key". "Collectives of collectives" therefore require a key that someone holds.
- **(b) Depth and cycles.** The spec does not define what "depth of 4 collectives" counts, nor what happens when the limit is exceeded. Cycles are also possible: A can add B after B's genesis has named A. Following 6.1's "X's log verifies" then recurses until the depth cap.
- **(c) Inconsistent reference times.**
  - The threshold route in 9.4 uses membership at the record's `created`.
  - The role route in L2 7.1(3) uses the charter that is current now.

  A charter change therefore retroactively removes or grants authority over old records, which flips Commitment status.
- **(d) Wording mismatch.** 9.4 says the role holder "has a valid proof"; L2 7.1(3) says it "has a proof that counts for itself".

**Fix.**
- 4.7: "The collective being verified is at depth 1; a member collective of a depth-d collective is at depth d+1. A proof by a member deeper than 4, or by a collective already on the verification path, does not count."
- Let a member collective consent by the 9.4 threshold rule as an alternative to its own key.
- Use the charter that was current at the record's witnessed time (C1), and align the wording of 9.4 and 7.1(3).

### I12. Sessions with more than two participants break the packet chain

**Where:** L1 14.1, 14.3 and 12.1.

**Problem.**
- Each sender's `seq`/`prev` chain covers the whole session, but a packet's `to` may name only some of the participants. A participant left out of packet n sees a gap at n+1 that can never be filled, because 12.4 rejects packets not addressed to it.
- The spec never requires `from` and `to` to be participants.
- Two different packets with the same `session`, `from` and `seq` are not treated as equivocation.

**Fix.** 14.3: "A packet with `session` MUST have `from` in `participants` and `to` listing every other participant. Two such packets with the same `session`, `from` and `seq` and different content IDs are equivocation, as in 10.3."

### I13. Endpoint bindings are undefined

**Where:** L1 15.1, 15.3, 13.2 and 13.4; the vector Location record.

**Problem.**
- The spec never defines binding names: they appear only in paper Appendix B.
- It also never says how a binding's `url` maps to operations. 13.4 says `{endpoint}/ws`, but the vector's `wss` endpoint is `wss://lexis.example/oip/ws`, which would give `…/oip/ws/ws`.

**Fix.** Add a table to 15.1:

| Binding | Meaning of `url` |
|---|---|
| `https` | The base URL. Inbox at `POST {url}/inbox`; WebSocket at `{url}/ws` with the `wss` scheme |
| `wss` | The full WebSocket URL |
| `mailbox` | The `{mailbox}` of 13.5 |
| Others | Reserved; unknown bindings MUST be ignored |

### I14. The size limits do not fit together

**Where:** core 1.6; L1 12.6, 13.1 and 17.1.

**Problem.**
- **Bundles grow without limit.** A `Bundle` is a record that contains the whole log. My estimate, using the vector's 443-byte member proof:
  - A 256-member collective's genesis is about 127 KiB.
  - Each later event that restates the membership with a 129-member quorum is about 72 KiB.
  - The Bundle therefore passes the 256 KiB floor after genesis plus 2 events, and the 1 MiB ceiling after about 13.
- **Sealing expands packets by 4/3.** A 256 KiB packet becomes a Sealed record of about 342 KiB.

**Fix.**
- "`Bundle`, `FeedPage` and `DuplicityEvidence` are containers: the limit applies to each record they contain."
- "A `Sealed` record may exceed the limit by its encoding overhead."
- Add paging for logs: `GET …/mind/m/log?after=<seq>`.

### I15. One mind can hold several roles in a Commitment

**Where:** L2 5.1; 8.3 step 3.

**Problem.** A mind may be both debtor and creditor. Its own `fulfilled` Receipt then "counts for a creditor", which makes the Commitment `fulfilled` without the real creditor.

**Fix.** 5.1: "Each mind MUST appear at most once in `parties`."

### I16. `Merge` is "reserved" but still accepted

**Where:** L1 3.9 and 4.6.

**Problem.** 4.6 rejects only event types not listed in Section 3. A v1 verifier must therefore accept a `Merge` event whose effects (`retire`, `child`) are undefined.

**Fix.** "In this revision, a log containing a `Merge` MUST be rejected."

### I17. Policies cannot bound what a Commitment obliges

**Where:** L1 11.3 (selector grammar); L2 5.1.

**Problem.** A policy has no way to cover several parts of a Commitment:
- Selectors cannot index arrays, so `parties` and the counterparty are out of reach.
- Selectors cannot name members that contain dots or hyphens, so reverse-DNS `ext` namespaces are out of reach.
- `promise` is free text, and L2 1.1 makes it binding.

**Fix.**
- Extend the selector grammar to `1*( "." name / "[" index "]" / "[" json-string "]" )`.
- Add a note that a policy bounds only the members it selects. Delegators SHOULD constrain currency, counterparties and `ext`.

### I18. The gateway named in a bridged mind is never checked

**Where:** L0 1.2 and 1.4.

**Problem.** Anyone can create a mind with `ext["oip.bridge"].gateway` set to a reputable gateway. Its Receipts are then attributed to that gateway under 1.4.

**Fix.** "Verifiers MUST NOT attribute a bridged mind to a gateway unless the gateway's own signed Participant lists the bridged mind's address."

### I19. Number precision and string length are undefined

**Where:** core 1.3 and 1.4; every "at most N characters" rule.

**Problem.**
- **Decimal precision.** Comparing `"500.0000000000000001"` with `"500"` in binary floating point gives a different answer from exact decimal arithmetic.
- **Timestamp precision.** Timestamps may carry 9 fractional digits, but many platforms keep only milliseconds.
- **"Characters".** JavaScript counts UTF-16 code units while Python counts code points, so a name of 100 emoji is valid in one and invalid in the other.

**Fix.**
- "Use exact decimal arithmetic, with at most 64 significant digits."
- "Compare timestamps at full precision", or allow at most 3 fractional digits.
- "String lengths are counted in Unicode code points."

### I20. `oip_vectors.py` is more lenient than the spec

**Where:** `spec/test-vectors/oip_vectors.py`. The test-vectors README calls it an implementation that checks the vectors, and BUILD §6.2 makes it the cross-check for the TypeScript tests.

**Problem.** It passes its own vectors but accepts records the spec rejects. I reproduced each of these with a probe:
- `proofPurpose` is never checked. A Genesis signed with `assertionMethod` is accepted, and so is an Intent signed with `capabilityInvocation` (core 5.6).
- Proof members are not checked: a proof containing `id` counts (core 5.2). A `proofValue` beginning `x…` instead of `z…` verifies.
- An unversioned `did:oip:X#K` verification method is accepted, although core 6.2 requires a pinned version. The 6.2 latest-state rule is not implemented. Only the log up to V is verified, not the whole log as 6.1 requires.
- One control key listed twice satisfies a 2-of-2 `nextThreshold`, although L1 4.3 requires distinct keys.
- In member-controlled logs, events after `Retire` and an unknown type (`Frobnicate`) are accepted. Key-controlled logs also accept unknown types (L1 4.6).
- A mind with `kind: "collective"` and a key controller is accepted (L1 3.6).
- Delegated proofs count even when the record has no `authority` (L2 7.1(2)).
- Delegation expiry is compared as strings.
- The policy code uses `Decimal(str(x))` with a string fallback. It disagrees with the spec on `"0500000"`, `"1e9"`, `null` and booleans, and it accepts `"4,000,000" <= "500"` (C2).
- `revoked`, `compromisedSince`, `notBefore`, `Revocation`, chains longer than one link, and the nesting bound are not implemented.

**Fix.**
- Bring the checker into line with the spec.
- Add **negative vectors**: invalid records, each with the expected rejection reason.

### I21. Vector coverage and documentation are incomplete

**Where:** `spec/test-vectors/README.md`; `vectors.json`.

**Problem.**
- **Undocumented X25519 key.** The X25519 agreement key is derived from `"oip-test-vector-x25519:" + label`, not the documented `"oip-test-vector:" + label`. The documented rule gives `z6LScNAf3Tqc…`; the vector holds `z6LSjppgRXVW…`. The key is also missing from `keys`.
- **Missing vectors.** There are none for:
  - `Update` with `revoked`, or `Retire`;
  - Checkpoint Merkle roots;
  - `Sealed`, `Ack`, `Hello`, `Resume`, `Branch` and `Revocation`;
  - delegation chains longer than one link;
  - DID documents;
  - collective events after genesis;
  - role-route signing;
  - each branch of the status functions;
  - any invalid case.

**Fix.**
- Add the X25519 seed to `keys` and document how it is derived.
- Add the missing vectors in order of BUILD milestones M1–M4.

---

## Minor

### M1. Cross-reference errors

- L2 5.3 cites "core 3.3"; the right reference is core 3.1, the content ID that excludes `proof`.
- L1 9.4 cites "Layer 2, Section 7"; it should be L2 6.2 and 7.1(3).
- L1 13.1 says "A2A Agent Cards (Layer 0)"; it should be L0 3.2.
- L1 16.2 says "as in a Layer 2 Offer" and "Layer 2 evidence items"; these should be L2 4.2 and L2 9.
- L1 6.4 cites "(Section 17)"; it should be 13.1 and 17, because missing events can also be fetched from homes.
- The L0 introduction says "Sections 2–4 are normative", but Section 1 contains MUST statements. It should say "Sections 1–4".
- The fragment `#a2a-extension` in the L0 3.3 extension URI matches no heading; GitHub generates `#3-a2a`. Add an explicit anchor.
- The core 6.1 ABNF uses `base58char` without defining it. Add `base58char = %x31-39 / %x41-48 / %x4A-4E / %x50-5A / %x61-6B / %x6D-7A`.

### M2. Smaller internal inconsistencies

- Core 7 requires `created` in every record except `Bundle` and `Sealed`, yet `FeedPage` and `DuplicityEvidence` have no `created`.
- Core 5.1 lists unsigned records only as examples ("such as"). `Resume`, `Branch`, `FeedPage` and `DuplicityEvidence` are left unclassified. Add a table of every record type giving: signed or not, signer, `proofPurpose`, and key rule (6.1 or 6.2).
- Participant:
  - L1 16.1 makes `supersedes` a content ID; L2 2 makes it a record-ref.
  - L1 16.1 requires the author's own key under 6.2; L2 2 accepts any proof that counts, including delegation. State which rules apply.
- L1 18.5 calls `maxFanout` a member of the query, but 18.2 does not list it.
- L0 4.1 includes AT Protocol handles and the `dns:` alias form; L1 5.3 defines neither.
- L2 8.2 omits "by the same author", which 8.1 includes.
- Core 9.1 applies the 300 s clock-skew allowance to expiry checks, but L1 12.4 says only "expires has passed". Write `now > expires + 300 s`.

### M3. Ambiguities, with proposed wording

**core**
- 1.2: say whether consumers reject numbers written as `1.0` or `1e2`. Proposal: "MUST reject".
- 1.4: the regex accepts month 13 and second 99. Proposal: "MUST also be a valid RFC 3339 date-time".
- 1.5: give a regex: `^P(?!$)([0-9]+D)?(T(?=[0-9])([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$`.
- 5.4: add the 5.2 checks to the verification steps: allowed members, purpose, `created` format, `z` prefix and a 64-byte signature.

**L1**
- 3.4: a later event's controller MUST be of the same kind (key or member) as the genesis controller.
- 4.5: cover three cases.
  - Revoking an agreement key.
  - Several revocations of the same key: use the earliest `compromisedSince`.
  - Re-adding a revoked key: reject.
- 5.2: say whether home service ids start at 0 or 1, and how `OIPEndpoint` service ids are formed.
- 5.3: the `text/plain` body may end with one trailing LF or CRLF. Say how multiple TXT strings combine.
- 10.5: "The RFC 9162 input D[i] is the 32-byte digest, so leaf hashes are SHA-256(0x00 ‖ digest). `size` ≥ 1."
- 12.2: content has "exactly one of `body`, `ref` or `parts`".
- 13.1: a FeedPage request without `after` starts at seq 0, and `next` is the value to pass as `after`.
- 13.2: for a `Sealed` body, say:
  - whether the host decrypts before acknowledging;
  - that `packet` is the inner packet's content ID;
  - who signs the Ack when the host does not hold the mind's keys.
- 16.1: `kind` "MUST equal the kind in the identity state".
- 18.2: tag matching is AND. State which query members are optional, and the default `limit`.

**L2**
- 5.1: give the default for `required`, and define what `onBehalfOf` means.
- 7.2: proofs made after a Commitment's `expires` do not count.

**L0**
- 3.1: `cardDigest` is `"sha256:<hex>"` of the exact bytes of the response body.

---

## Verdict

1. The core encoding layer is precise enough to interoperate: a second implementation written only from `core.md` reproduced every content ID, address, key hash and signature in `vectors.json`.
2. Above core, an engineer cannot yet build an implementation that is both interoperable and safe:
   - time-based validity is defeated by backdating (C1);
   - policy evaluation and the status functions can be exploited (C2, C3);
   - feeds break on routine key rotation (C4);
   - the conformance vectors contradict the spec (C5);
   - record-ref matching, chain assembly, endpoint bindings and the Ed25519 rule are left to guesswork.
3. M1 (core) can start now. Fix C1–C5 and I1–I13 in the spec, and add negative vectors to a stricter `oip_vectors.py`, before M2–M5 begin.
