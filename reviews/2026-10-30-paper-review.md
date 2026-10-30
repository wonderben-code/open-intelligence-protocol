# Independent review: Technical Architecture paper (draft of 30 October 2026)

Reviewer: independent agent with no access to the author's reasoning. Reviewed `papers/02-technical-architecture.md` at commit fb041a9 against `research/01–04`, `spec/test-vectors/` (generator and vectors), `papers/01-founding-paper.md`, and the specs added in commit 8419dfe. Line numbers refer to the paper at commit fb041a9. Saved to the repository by the main session from the reviewer's final report, verbatim in substance.

**Values: no mismatches.** Every quoted address, content ID, key, proofValue and versionId matches vectors.json, including abbreviated prefixes. The Genesis JSON (lines 337–353) recomputes to Amina's address. The Location record's `participant` and `feed.head` equal the content IDs of the profile and Entry. Key-hash commitments equal keyHash of the next control keys. All 25 content IDs and key hashes are 56 characters and match `^b[a-z2-7]{55}$`. Multikey prefixes are correct. `oip_vectors.py --check` passes all 9 checks.

## Critical

**C1. Appendix A.5's delegated branch never checks that the signing key belongs to the signer (lines 1075–1078).** The first branch checks `key ∈ keys(party, version)`; the delegated branch only runs `verifyProof(record, p, key)` with a key parsed from an attacker-written verificationMethod. Anyone who knows a public chain P→S can sign with their own key under `did:oip:S?versionId=V#<attackerKey>`. The code (oip_vectors.py:407) and spec L2 7.1 are correct; the paper's pseudocode is forgeable. *Fix:* one `validKey(p)` helper (key present at pinned version, not compromised, current-state rule, purpose check) used in every branch.

**C2. Thresholds count duplicate keys (lines 331, 362, 1054; oip_vectors.py:264–271).** `|revealed| ≥ nextThreshold` counts list entries, so a 2-of-3 `next` can be rotated with one key listed twice (PoC accepted the log and installed attacker operational keys). Spec L1 4.3 says "distinct"; paper, A.4 and generator do not. *Fix:* "distinct" everywhere plus a negative vector.

**C3. A delegate can create unlimited authority for its principal (lines 445, 664–668, 857, A.5).** Section 6.3 lets a delegate supply the author's signature on any object; `/oip` and `/oip/sign` cover `/oip/sign/Delegation` and `/oip/sign/Revocation`; policies can be satisfied by adding junk fields. PoC: an agent holding `/oip/sign` with `price<=500` signs a Delegation "authored" by Lexis Ltd with no policy and a one-year expiry, and the generic signed-by check accepts it. Spec L1 11.4.1 blocks this inside chains but nothing blocks it for Revocation. "Delegations can only narrow" (line 857) is false as written. *Fix:* list the record types that may be signed under delegation (Intent, Offer, Commitment, Receipt, Packet); require the author's own key for Delegation, Revocation, Collective, identity-log and current-state records; reserve or drop bare `/oip/sign`.

**C4. Delegation policies don't limit what the principal is committed to (lines 178, 426, 446, 450, 630, 654, 857).** (a) The example caps `amount` but not `currency` ("400 BTC" passes). (b) Negative amounts pass upper caps (core 1.3 allows `-`). (c) Spec L1 11.3 falls back to code-point comparison for non-decimal strings ("1,000,000" ≤ "500"); the code's Decimal fallback accepts "-Infinity", "1e2", full-width digits, " 400 " and "0x10". (d) The binding plain-language `promise` is invisible to policies: `price.amount:"120"` with a promise to pay 900 USD passes. *Fix:* ordering operators false unless both values are valid decimals; amounts non-negative; pin currency in the example and vectors; under delegation, structured `terms` are authoritative and the promise cannot exceed them.

**C5. Every time-based protection trusts the signer's own clock (lines 372, 408, 447–448, 490, 847, 850, 857; spec L1 6.1, 9.4, 11.4.5, 11.4.7).** Expiry, notBefore, revocation, `compromisedSince` and collective membership "as of" a version are judged against self-asserted `created`. A key thief backdates before `compromisedSince` and pins an old version; an agent with an expired or revoked delegation backdates with a sock-puppet co-signer; removed collective members backdate. So "version pinning and compromise times bound what a stolen key can sign" (850) and "short expiry is the first line of defence" (448) do not hold. *Fix:* evaluate time rules at max(created, first-seen); reject live proofs whose `created` is older than the skew allowance; for later third-party checks require evidence the record existed before expiry or compromise (anchored checkpoint, counterparty co-signature or Ack).

**C6. Used control keys are not "useless"; fork handling allows takeover or permanent shutdown (lines 331, 368, 374, 484, 813, 848; spec 7.3, 17.1).** A control key revealed at seq k can sign a different event at seq k and extend that branch; only verifiers who saw the real event first reject it. Clients "keep the freshest valid answer" (484) and resolvers return "the longest valid log" (spec 17.1), so a longer forged branch wins with new verifiers; otherwise the mind is "untrusted until resolved" with no v1 resolution. Same for a former custodian after handover (374, 813); for collectives, where one member signing two proposals produces two valid conflicting events; and for any threshold ≤ n/2, where two honest disjoint groups can do it — contradicting line 368. *Fix:* require revealed control keys to be destroyed; never choose between forks by length or freshness; define a v1 resolution rule (e.g. earliest anchored or witnessed branch wins); require thresholds > n/2; correct lines 331, 374, 813.

## Important

**I1. Proof purpose never checked; DID document breaks the "any Data Integrity verifier" claim (238–239, 300, A.2, A.5; oip_vectors.py:167–180).** An `authentication` or `capabilityInvocation` proof counts as a Commitment signature. Operational keys are not listed under capabilityInvocation although members sign collective identity events with them (CID 1.0 §2.3 would reject). CID 1.0 §2.2.4 matches verification-method ids exactly, but OIP URLs carry `?versionId=…` and projected ids don't. *Fix:* add the purpose check; align DID document purposes with actual signing; soften line 239.

**I2. Collectives weaker and less specified than claimed (331, 405–409, 856, 1066, 1079–1081).** (a) Members' operational keys can rewrite a collective's log, so "stealing an operational key does not let an attacker change the identity log" is false for collectives; a key removed without a compromise time keeps this power by pinning an old version (PoC: Amina's removed phone key plus one other member rewrote membership with a backdated event). (b) "As of the collective's identity version" is undefined; spec picks by `created` (backdatable), checker uses latest state. (c) Collectives of collectives can't be verified as specified (no keys of their own; proof format can't express "Amina, for C1, for C2"; code rejects nested genesis). (d) No cap on total verification work. *Fix:* require members' current keys for collective identity events; define version selection; specify recursive countsFor with a work budget; cap proofs per record and log length.

**I3. No parameter validation in paper or A.4; code accepts logs anyone can write to (331, 344, 402, 1043–1060).** `nextThreshold: 0` accepts an unsigned Update; a collective with `threshold: 0` was taken over by an outsider; collective events after `Retire` are accepted; later events' `type` never checked; A.4's `or 1` turns 0 into 1 but the code keeps 0. *Fix:* 1 ≤ t ≤ n, non-empty key lists, allowed event types, negative vectors.

**I4. Implementation and vector claims overstated; vectors break the spec (23, 42, 366, 1006).** The generator lacks A.6, delegation chains, collective role signing, revocation and `compromisedSince`, and purpose checks, so "implements each of these" (1006) is false. Vectors are generated and checked by the same code (self-consistency, not independent verification). The "tampered rotation" test fails on the signature, not the pre-rotation rule. Packet `nonce` "p1" breaks spec 12.1 (8–64 characters). The only session packet (seq 0) uses `propose` and lacks the `Session` record (spec 14.2). *Fix:* correct 1006 and 366, add negative vectors, fix the packet vector.

**I5. "Rotating operational keys revokes everything they signed" (448) contradicts spec 6.3 and line 372;** line 372 doesn't say where `compromisedSince` goes (spec: `revoked[]`); A.4 and the code ignore revocation.

**I6. Moving away from a hostile host is incomplete (477–479).** The old host usually holds an operational key and can keep publishing higher-`seq` Location records up to 2^53−1; a move only works after a control Update removes that key. *Fix:* say so and bound `seq` jumps.

**I7. Multi-instance minds clash with one linear chain per sender (475, 582, 590, 596–598, 604).** Concurrent instances produce duplicate `seq` in sessions and feeds (line 598 calls that equivocation); a CRDT doesn't merge a hash chain; continuing a feed after compromise also duplicates `seq`. *Fix:* one chain per (mind, instance) or a single writer per session or feed.

**I8. Every Fork uses up a control rotation (312, 320, 385; spec 3.8),** so routine forking needs offline control keys, contradicting line 320. *Fix:* a KERI `ixn`-style acknowledgement signable by operational keys.

**I9. Outsiders can change the status of someone else's Intent or Offer (647, 656, 676–677).** Any accepted Commitment (even between sock puppets) with `resolves` and `closesIntent` marks another person's Intent satisfied; enough mark an Offer exhausted. *Fix:* count a Commitment only if the Intent's or Offer's author is a required party who signed it.

**I10. Assurance labels are self-declared (766–776, 854).** A gateway that omits them looks native; anyone can name a reputable gateway. *Fix:* gateway-signed attestation plus a link back from the gateway's feed; soften the claim.

**I11. Prompt-injection defence overstated (863, 782).** Separating content from authority stops packets granting authority; it doesn't stop an agent holding `oip_commit` being steered into using authority it has. Section 7.2 omits spec L0 2.2's human-confirmation and keys-outside-context rules.

**I12. Roadmap's "no format change, no breakage" claim is false (373, 391, 898–905; founding paper line 146).** v1 verifiers would treat recovery overrides as duplicity; Merge has no rules; v1 rejects P-256 and post-quantum proofs (core 4.2). *Fix:* mark these as core-rule changes; reserve a `recovery` field in Genesis now.

**I13. Novelty claims go beyond the research notes (23, 298, 378).** Location-independent DIDs exist (KERI/did:keri, did:peer:4; note 02 §12.1 calls did:oip "KERI in JSON"). Member-controlled collective identity has prior art (Safe multisig, KERI multisig). General commitments and receipts have prior art (Ricardian contracts, Singh, EAS). Line 378 omits KERI delegated inception (`dip`) and the 2026 Proof-of-Descendancy thesis. Merge is claimed but deferred. *Fix:* claim the combination; cite prior art.

**I14. UCAN stated as final (417) but the notes mark it [uncertain] (rc.1);** the `chain` ↔ `prf` mapping (442) is wrong for UCAN 1.0: `prf` belongs to Invocations, so OIP's `authority` field is the closer analogue.

## Minor

- 316: reads as if Genesis carries `seq: 0`; code doesn't reject a `mind` field on Genesis.
- 184: says the Receipt references a payment; the vector has only the deliverable digest.
- 656 / vectors: the Commitment has no `closesIntent`, so Amina's Intent stays `open`.
- 165–175: the diagram never shows the agent sending the Commitment to Amina.
- 262: Appendix B omits `Bundle`, `FeedPage`, `Hello`, `Forwarded`, `DuplicityEvidence`; API list omits `/oip/v1/submit` and `/oip/v1/duplicity`.
- 552: `expires` marked optional (spec 12.1 requires it outside sessions); `purpose.schema` missing though line 586 uses it; `Forwarded` and `maxFanout` undefined (538).
- 486, 903: DNS aliases placed in v1.x but line 818 and spec 5.3 have them in v1; duplicity reporting in v1.x (903) but Sections 5.2 and 9 have it in v1.
- 445: `/oip` "(everything)" doesn't cover `/x402/pay`; `/oip/publish` conflicts with Entry needing the author's own key.
- 678, A.6, 632: lifecycle table omits `claimed-fulfilled`, `disputed`, `overdue`; A.6 "conflict with s" undefined (spec 8.3 steps 4–6 explicit); A.6 wants one cancelled Receipt signed by all (spec allows several); A.5 lets members' delegates count towards a collective threshold (spec 9.4 doesn't); status also depends on evaluation time.
- 631: a withdrawal record must restate `want`, and its own computed status is `open`.
- 217–218, 277: an OIP content ID is not a CID (multiformats decoder errors on first byte 0x12; IPFS storage needs a CIDv1 mapping, and stored bytes lack proofs); "case-insensitive" conflicts with the lowercase-only regex; a new hash changes length, not only the prefix.
- 515: Participant is not a superset of an A2A Agent Card (no version, supportedInterfaces, default modes, skill `name`); one `/.well-known/agent-card.json` per origin while a host serves many minds.
- 517: GossipSub has no wildcard subscriptions; MQTT separates levels with `/`.
- 622: Web Bot Auth uses a JWK-thumbprint `keyid` plus a `Signature-Agent` directory, not a verification-method URL.
- 602, 849: the repo timestamps git commits, not feed checkpoints; OpenTimestamps can anchor both sides of a fork, so it detects split views rather than preventing them.
- 600: "any static web host" conflicts with query-parameter pagination.
- 276 vs 919: passkeys can't produce `ecdsa-jcs-2019` proofs; that suite is cited in neither the notes nor the references.
- 651: Ricardian contracts are signed by the issuer, not by all parties.
- 817: a `did:key` alias can't point back (did:key documents have no `alsoKnownAs`).
- 834: agentproto has no protocol yet; say "designed to travel".
- 64, 378: most cited IETF agent-identity work is individual drafts.
- 97: "integrity and identity coincide" overclaims (compare line 867).
- 372: no default "short expiry"; the vector's delegation lasts 31 days.
- 490: a receiver learns it is behind only if the signer pins a newer version.
- 535–538: capability-query packets have no recipient binding (replay and amplification); put allowed brokers and `maxFanout` inside the signed packet.
- 592: v1 sealing has no forward secrecy or post-quantum confidentiality.
- 868: content IDs of private records are unsalted and guessable when referenced publicly.
- Other gaps: A.2 has no `@context` handling; the code compares timestamps as strings; duplicate keys and `1.0`/`1e2` not handled in Section 4.1; the exact Ed25519 verification rule (e.g. ZIP-215) is unspecified.
- 139–140: for collectives these records aren't signed by "an operational key"; the collective-owned `keys` option is never mentioned.
- 17, 23, 313: the abstract presents merge as available (v1.x); whether a v1 verifier accepts a `Merge` event is undefined.
- References: cite RFC 9964 at the RFC Editor; add RFC 9457, RFC 4648/multiformats, the ECDSA cryptosuites, OpenTimestamps, KERI `dip`, Proof-of-Descendancy.
- 926 naming (verify): KServe's "Open Inference Protocol" is commonly called OIP; `did:oip` is not yet in the W3C DID method registry.
- 929: ensure "the papers are archived with permanent identifiers" is true at publication.

## Verdict

Values, the worked scenario and claims about outside standards check out (only UCAN's status is overstated), and the design stays consistent with the founding paper's aims.

The security core is not ready yet: Appendix A as written can be forged (C1, C2), delegation escapes its limits (C3, C4), and the time-based and fork protections fail against backdating or old keys (C5, C6).

Fix C1–C6, add negative test vectors, and tone down the novelty and "no breaking changes" claims before calling this Version 1.0; most fixes are clearer rules rather than redesigns.
