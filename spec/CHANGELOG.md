# Specification changelog

## Revision 2026-11-17 (Draft)

Security and consistency fixes from two independent reviews of revision 2026-10-30, one of the technical paper and one of the specifications ([reviews/](../reviews/)). Record formats change little; most changes are clearer rules about who may sign what, and when. Every mind address in the test vectors is unchanged.

**Time (core 9).** Time rules use a proof's evaluation time `t(p) = max(p.created, τ(p))`, where `τ(p)` comes from evidence (the verifier's own first-seen record, a witness it trusts, an anchored checkpoint or an acknowledgement), never from the signer's claim. This closes backdating around key removal, compromise, delegation expiry, revocation and collective membership. Identity events that remove keys, change membership or retire a mind take effect at their own evaluation time, so they cannot be backdated either; `compromisedSince` is the one deliberately retroactive statement, and a commitment it affects shows as `disputed`. A proof made after its record's `expires` does not count.

**Keys (Layer 1, 3 and 6).** One definition of a valid operational key, used everywhere: present at the pinned version, not removed or retired before `t(p)`, not compromised at `t(p)`, the right proof purpose, and, for `Location`, `Participant` and `Hello` only, still current. Feed entries, checkpoints and acknowledgements no longer break when keys rotate. New **invocation keys** (`invocation`) are the only keys a member uses to sign another mind's identity events, so operational keys never change any identity; such member proofs are judged at their position in the log, so no member can unmake a collective by disowning old keys. Revoked keys can never be added again. The DID document lists invocation keys under `capabilityInvocation` and uses versioned ids when produced for a `versionId`.

**Thresholds and logs (Layer 1, 3–4).** Thresholds count distinct keys and members and must be majorities (`2t > n`), so duplicity is always attributable. Parameters are validated; every event's type is checked; controllers keep their kind; nothing follows `Retire`; `Merge` and the member name `recovery` are reserved and rejected. Collectives have a height of at most 4 and cannot contain themselves.

**Duplicity (Layer 1, 7).** Duplicity means two events with different content IDs at one position. Branches are never chosen by length or recency: the earlier-evidenced branch wins, otherwise the mind is duplicitous for that verifier. Used control keys must be destroyed; identity events go to at least two witnesses; resolvers record and serve first-seen times.

**Lineage (Layer 1, 8).** New `Lineage` record: a parent acknowledges a child with an operational key, so routine forks no longer use up a control-key rotation.

**Delegation (Layer 1, 11; Layer 2, 7).** A delegated proof lists its delegations in its own `authority` member, signed with it, instead of in the record, so parties acting through different delegates can sign one record in any order. Only `Intent`, `Offer`, `Commitment` and `Receipt` can be signed under delegation; `/oip`, `/oip/sign` and `/oip/publish` are reserved (no blanket grants), and `/oip/send` is defined. Policies gain UCAN-style connectives (`not`, `and`, `or`) and quantifiers (`all`, `any`) and array selectors, so a delegation can limit counterparties; ordering operators compare decimals only; amounts are non-negative. A party bound through a delegate is bound by the structured `terms`. `Delegation.chain` is removed. Nonces have 8–64 characters. Revocations take effect from their evaluation time.

**Collectives (Layer 1, 9; Layer 2, 6–7).** A collective signs at the earliest time its state's threshold is met by members of that state; charter roles use the charter in force at the proof's time, with a tie-break. Recursive threshold signing is reserved.

**Layer 2 status (8).** Only a commitment that counts for an Intent's or Offer's author can satisfy or exhaust it. A withdrawal has its own status, an edit makes the original `superseded`, and superseding records have a precedence. Each mind appears at most once among a commitment's parties. Status depends on the evaluation time, which is stated.

**Feeds, packets and sessions (Layer 1, 10–15, 18).** Feed entries may commit to the proofs on what they publish, making anchored checkpoints evidence for them; a feed has a single writer; log paging. Any verb may open a session; sending chains are per sender and `instance`; session packets go to every participant and are deduplicated per chain; `prev` is needed only after a chain's first packet. Packets live at most 7 days; duplicate detection records a packet only after it verifies. The WebSocket `domain` is set by the client; HTTP signatures have replay rules. Endpoint bindings are defined. Capability-query packets carry `brokers` and `maxFanout` inside the signed packet, and `Forwarded` names its recipient.

**Bridge (Layer 0).** A bridged mind's genesis carries a proof by its gateway; without it the label is only `claimed`. Corrected the A2A Agent Card mapping and digest, Web Bot Auth key identifiers, aliases that cannot point back, and custody handover.

**Core.** Content IDs have one canonical spelling (`^bciq[a-p][a-z2-7]{50}[aiqy]$`) and record-refs match by content ID alone. Ed25519 verification is pinned down (canonical encodings, prime-order subgroup, `S < L`). Number validity depends on value; decimals are exact and at most 64 characters; timestamps are compared at full precision; string lengths count code points; containers are exempt from the record size limit. Content IDs are not IPFS CIDs. At most 256 proofs per record. New table of every record type.

**Test vectors.** The generator implements all of the above. New vectors: a two-step delegation chain, two agents committing for their principals, a collective's charter role, a `Lineage` record, a checkpoint, an `Ack`, a `Hello`, DID documents, withdrawals and edits, and the X25519 key. 36 negative cases (each with its reason) must be rejected, and 3 must-accept cases accepted. A second, independent checker written from the earlier specification text is in `reviews/spec-review-workfiles/`.

## Revision 2026-10-30 (Draft)

First revision: core records, identifiers and proofs; Layer 1 (Mind Network); Layer 2 (Mind Web); Layer 0 (Bridge); test vectors with an independent Python implementation.
