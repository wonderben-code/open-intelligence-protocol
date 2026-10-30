# Specification changelog

## Revision 2026-10-31 (Draft)

Security and consistency fixes from two independent reviews of revision 2026-10-30 ([reviews/](../reviews/)). The record formats are almost unchanged; most changes are clearer rules about who may sign what, and when.

**Time (core 9).** Time rules now use a proof's evaluation time `t(p) = max(p.created, τ(p))`, where `τ(p)` comes from evidence (first-seen records, trusted witnesses, anchored checkpoints, acknowledgements), never from the signer's own claim. This closes backdating around key removal, compromise, delegation expiry, revocation and collective membership. Identity events' `created` must be non-decreasing.

**Keys (Layer 1, 6).** One definition of a valid operational key, used everywhere: present at the pinned version, not removed or retired before `t(p)`, not compromised at `t(p)`, correct proof purpose, and current for current-state records. Removing a key now stops it signing anything new (previously a removed key stayed valid for old version pins). The DID document lists operational keys under `capabilityInvocation` too, and uses versioned verification-method ids when produced for a `versionId`.

**Thresholds (Layer 1, 3–4).** Thresholds count distinct keys and members and must be majorities (`2t > n`), so duplicity is always attributable. Parameters are validated; every event's type is checked; nothing follows `Retire`; `Merge` and the member name `recovery` are reserved and rejected.

**Duplicity (Layer 1, 7).** Conflicting branches are never chosen by length or recency. The branch with the earlier evidence at the point of divergence wins; otherwise the mind is duplicitous for that verifier. Used control keys must be destroyed; minds publish identity events to at least two witnesses. Resolvers record and serve first-seen times.

**Lineage (Layer 1, 8).** New `Lineage` record: a parent acknowledges a child with an operational key, so routine forks no longer use up a control-key rotation.

**Collectives (Layer 1, 9; Layer 2, 6–7).** Members sign only with their own valid keys. A collective signs at the earliest time its state's threshold is met by members of that state; charter roles use the charter in force at the proof's time. Recursive threshold signing is reserved.

**Delegation (Layer 1, 11; Layer 2, 7).** Only `Intent`, `Offer`, `Commitment` and `Receipt` can be signed under delegation; `Delegation`, `Revocation`, `Collective`, `Lineage`, identity events and current-state records need the author's own authority. `/oip`, `/oip/sign` and `/oip/publish` are reserved (no blanket grants). Policy ordering operators compare decimals only; amounts are non-negative. A party bound through a delegate is bound by the structured `terms`. `Delegation.chain` is removed: `authority` lists the whole chain, as a UCAN invocation lists `prf`. Nonces have 8–64 characters. Revocations take effect from their evaluation time.

**Layer 2 status (8).** Only a commitment that counts for an Intent's or Offer's author can satisfy or exhaust it. Status depends on the evaluation time, which is stated.

**Feeds, packets and sessions (Layer 1, 10–14, 18).** Feed entries may commit to the proofs on the published record (`proofs`), making anchored checkpoints evidence for them; a feed has a single writer. Any verb may open a session; sending chains are per sender and `instance`; `prev` is required only after a chain's first packet. Capability-query packets carry `brokers` and `maxFanout` inside the signed packet, and `Forwarded` names its recipient.

**Bridge (Layer 0).** A bridged mind's genesis carries a proof by its gateway; without it the label is only `claimed`. Corrected the A2A Agent Card mapping, Web Bot Auth key identifiers, aliases that cannot point back, and custody handover.

**Core.** Ed25519 verification rule pinned down (canonical encodings, `S < L`, no small-order points). Number validity depends on value, not lexical form. Content IDs are lower case and are not IPFS CIDs. At most 256 proofs per record.

**Test vectors.** The generator implements all of the above, including delegation chains, revocation, collective roles and Layer 2 status, and adds 29 negative cases with their reasons. A second, independent checker written from the specification text is in `reviews/spec-review-workfiles/`.

## Revision 2026-10-30 (Draft)

First revision: core records, identifiers and proofs; Layer 1 (Mind Network); Layer 2 (Mind Web); Layer 0 (Bridge); test vectors with an independent Python implementation.
