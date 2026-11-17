# Fix verification: specification revision 2026-11-17

> **Note added after the review.** This report checked the pre-publication candidate of revision 2026-11-17 at commit `ab980a8`. Every finding in it, N1–N10 and M1–M11, together with the remaining paper items it lists, is addressed in revision 2026-11-17 as published; [spec/CHANGELOG.md](../spec/CHANGELOG.md) says how, and the test vectors include a negative case, and where it matters a control, for each. The report itself is unchanged below.

**Reviewer:** independent agent, 17 November 2026, with no access to the author's reasoning.
**Scope:** `spec/core.md`, `spec/layer-1-mind-network.md` (L1), `spec/layer-2-mind-web.md` (L2), `spec/layer-0-bridge.md` (L0), `spec/README.md`, `spec/CHANGELOG.md`, `papers/02-technical-architecture.md` (Draft 2, "paper"), `spec/test-vectors/oip_vectors.py` ("the checker") and `vectors.json`, and `BUILD.md`. These were checked against the findings of `reviews/2026-10-30-paper-review.md` (cited here as P-C1…P-I14) and `reviews/2026-10-30-spec-review.md` (S-C1…S-I21).

**Method.**
- I read every document listed above.
- `python3 spec/test-vectors/oip_vectors.py --check` passes: 18 checks, 3 must-accept cases and 36 negative cases.
- I built attack records with `oip_vectors.py` imported as a module.
- The probe scripts are in the reviewer's scratch directory, `fixcheck/`, outside the repository: `harness.py`, `probe_time_keys.py`, `probe_collectives.py`, `probe_chain_dos.py`, `probe_ed25519.py` and `probe_misc.py`. Each runs as `python3 <script>`.
- I also ran the earlier reviewer's independent checker, `reviews/spec-review-workfiles/indep_check.py`, against the current vectors.
- No repository file other than this one was changed.

## Summary

- **Earlier findings.** Of the 46 Critical and Important findings in the two reviews, 37 are resolved and 9 are partly resolved; none is unresolved. The revision is a large, careful improvement:
  - evaluation times;
  - majority thresholds and parameter checks;
  - delegable types and reserved commands;
  - decimal-only ordering;
  - the canonical content-ID spelling;
  - record-ref matching;
  - proof-level `authority`;
  - Layer 2 status precedence;
  - the current-state rule limited to `Location`, `Participant` and `Hello`;
  - 36 negative vectors, each of which fails for its stated reason.
- **Remaining problems** sit mainly where the new design meets collectives and evidence:
  - **Critical (N1).** Member proofs on a collective's identity events are "judged at their position", so time never applies to them. Invocation keys that members have removed and declared compromised can still append events to the collective's log, including one that installs an operational key of the attacker's own. Every verifier that does not consult a witness accepts it, and so does the checker. The witness rule that is supposed to stop this cannot work for a witness that sees the collective for the first time.
  - **The checker disagrees with the spec on the time model and on Ed25519.**
    - It keys evidence by content ID, not by proof, so a co-signature added later inherits the record's first-seen time and can be backdated (N2).
    - It accepts mixed-order and small-order Ed25519 public keys, which core 4.4 forbids (N5).
  - **Other new Important findings:**
    - a member collective can invalidate its parent collectives (N3);
    - the search for a delegation chain is exponential (N4);
    - one proof can count for several parties, and role holders do not choose to act (N6);
    - a collective's stale `Location` can never be superseded (N7);
    - a key removal can be outraced at verifiers that use no witness (N8);
    - the bridged-mind proof cannot verify (N9);
    - a Commitment's price has no payer (N10).
- **Verdict:** fix N1 and bring the checker into line with core 9 and core 4.4 (N2, N5) before publishing this revision as the draft that implementers build on. The other findings can follow in the next draft (see the end of this report).

## Verdicts on the earlier findings

R = resolved, P = partly resolved, N = not resolved.

### Paper review

| Finding | Verdict | Evidence |
|---|---|---|
| P-C1 A.5 delegated branch never checks the signer's key | R | A.6 requires "a valid key of some D ≠ P" via `validKey` (A.5); L2 7.1 item 2; checker `delegated_time` calls `valid_key`. Negative vector `delegated-key-not-in-signers-log`. |
| P-C2 Thresholds count duplicate keys | R | L1 3.4 and 4.3 ("distinct"); paper 5.2 step 3; A.4; checker `_check_key_controller`; member signers form a set. Negative vector `threshold-duplicate-control-key`. |
| P-C3 A delegate can create unlimited authority | R | Only `Intent`, `Offer`, `Commitment` and `Receipt` are delegable (L1 11.2, L2 7.2). `/oip` and `/oip/sign` are reserved. `Revocation`, `Delegation` and `Collective` need own authority (core 11). Negative vectors `delegate-signs-delegation` and `reserved-blanket-command`. |
| P-C4 Policies don't limit what the principal is committed to | R | Currency pinned (paper 5.6, vectors); amounts non-negative (core 1.3); ordering compares decimals only (L1 11.3); terms prevail over the promise (L2 5.4). Seven policy negative vectors. Price direction is still undefined (new N10). |
| P-C5 Time-based protections trust the signer's clock | P | Core 9.3–9.6 and L1 6.1 items 3–4, 9.5 and 11.4 items 5 and 7 use `t(p)`, with five backdating vectors plus controls. Not fixed for collective identity events, which use no time (N1). Per-record evidence in the checker (N2) and own-first-seen removal times (N8) reopen backdating in practice. |
| P-C6 Used control keys not useless; fork choice | R | Never by length or recency (L1 7.3, 17.1); earliest evidence wins; control keys destroyed (7.4); majorities (3.4); handover wording fixed (L0 6, paper 5.3). The checker holds one log per mind and does not exercise 7.3 (no duplicity vectors). |
| P-I1 Proof purpose unchecked; DID document | R | Core 5.4 and 5.6, A.2, checker `valid_key`/`_control_signed`; invocation keys under `capabilityInvocation`, versioned ids (L1 5.2); paper 4.3 softened. Negative vector `wrong-proof-purpose`. |
| P-I2 Collectives weaker than claimed | P | (b) "as of" defined by the state at T (L1 9.5). (c) Nesting through the member's own keys works, with recursive threshold signing reserved. (a) Not fixed: a removed key still controls the log by pinning an old version, now with invocation keys (N1). (d) 256 proofs and height 4 are capped, but the chain search is not (N4), and height creates a griefing vector (N3). |
| P-I3 No parameter validation | R | L1 3.4 (1 ≤ t ≤ n, 2t > n), 4.6 (types, `Retire`), A.4 (the `or 1` is gone), checker; negative vectors for zero and minority thresholds and events after `Retire`. |
| P-I4 Implementation and vector claims overstated | P | The generator now implements chains, roles, revocation, compromise and purpose, and the packet vector is valid. Still overstated: Appendix A's "implements each of these" (A.2 strict verification, A.3 per-proof evidence: N2, N5). The new rules are checked only by the generator: the independent checker reports 8 problems on the current vectors because it predates them. |
| P-I5 "Rotating revokes everything" | R | Paper 5.3 ("stops it signing anything new"); `compromisedSince` lives in `revoked[]` (L1 3.7, 4.5); the checker implements it. |
| P-I6 Moving away from a hostile host | R | L1 15.4 (MUST remove the host's key) and paper 5.7; the current-state rule ends the host's records. No `seq` bound was added, which matters for collectives (N7). |
| P-I7 Multi-instance vs one chain | R | Chains per (sender, `instance`) (L1 14.3); a feed has a single writer (10.3); invalid entries are not equivocation (10.4). |
| P-I8 Every fork uses a control rotation | R | `Lineage` record (L1 8.3); vector `lineage`. |
| P-I9 Outsiders change someone's Intent or Offer status | R | L2 8.1 and 8.2 ("counts for the Intent's/Offer's author"). Negative vector `outsider-closes-intent`. Offer exhaustion has no vector. |
| P-I10 Assurance labels self-declared | P | The gateway's proof on the `Genesis` is required and `claimed` is defined (L0 1.2–1.3), but that proof cannot verify under core 5.4 and 5.6 (N9). |
| P-I11 Prompt-injection defence overstated | R | Paper 8.2 and 7.2; L1 12.5; L0 2.2. |
| P-I12 "No breakage" roadmap | R | Paper 10 marks rule changes; `recovery` is reserved and `Merge` rejected (L1 3.9, 3.12); founding paper principle 6 reworded. |
| P-I13 Novelty claims | R | The abstract claims the combination; KERI `dip`, did:keri, did:peer:4, Safe, KERI multisig, Ricardian contracts, Singh, EAS and Proof-of-Descendancy are cited (paper 5.1, 5.4, 5.5, 6.2). |
| P-I14 UCAN status and `prf` mapping | R | "A release candidate at the time of writing"; `authority` ↔ `prf` (paper 5.6, L1 11.1). |

### Specification review

| Finding | Verdict | Evidence |
|---|---|---|
| S-C1 Backdating defeats revocation, expiry, removal; repudiation | P | Core 9; L1 6.1, 11.4 and 11.5; the repudiation attack on collectives is stopped (must-accept vector `collective-survives-member-compromise-claim`). The at-position rule that stops it lets stale keys extend or fork collectives (N1), and the witness rule reintroduces the repudiation for new witnesses. Also N2 and N8. |
| S-C2 Spending limits bypassed with crafted strings | R | Core 1.3 and 1.4; L1 11.3; Commitment `price` typed "as in an Offer" (L2 5.1); vectors for commas, exponent, infinity, spaces, full-width digits and currency. |
| S-C3 Third party closes an Intent or exhausts an Offer | R | L2 8.1 and 8.2; negative vector. |
| S-C4 Key rotation invalidates feed history | R | The current-state rule now covers only `Location`, `Participant` and `Hello` (L1 6.1 item 6); `Entry`, `Checkpoint` and `Ack` use 6.1. |
| S-C5 Vector packet invalid | R | 16-character nonce; the `Session` record travels in `parts`; L1 12.1 now says "`prev` when `seq` > 0"; L1 14.2 lets any verb open a session. |
| S-I1 Collective identity controlled by everyday keys | R | Invocation keys (L1 3.5, 6.4) listed under `capabilityInvocation` (5.2). Negative vector `collective-signed-with-operational-keys`. The new rule has its own flaw (N1). |
| S-I2 Duplicity fakeable, compromise-free, permanent | R | "Different content IDs" (L1 7.1); majorities (3.4); destroy control keys (7.4); first-seen, never longest (17.1); a v1 outcome is defined (7.3). |
| S-I3 Ed25519 rule ambiguous | P | Core 4.4 and BUILD.md §3 pin the rule, but the checker (OpenSSL) does not apply it (N5), and the Ed25519 edge-case vectors are deferred (vectors README). |
| S-I4 Record-ref matching undefined | R | Core 6.3 (content ID only); paper 4.4. |
| S-I5 Eight spellings of a content ID | R | Core 3.2 and the ABNF. I re-derived `^bciq[a-p][a-z2-7]{50}[aiqy]$` from the bits of 0x12 0x20 and it is exact. Negative vector `non-canonical-content-id`. |
| S-I6 Chains, collective delegation, commands, policy input | R | Chains listed in the proof (L1 11.6); collectives delegate by threshold (11.1); `/oip/publish` reserved and `/oip/send` defined (11.2); policies apply to the record without `proof` (11.3). The search itself is unbounded (N4). |
| S-I7 Delegated co-signers can't sign later | R | `authority` lives in the proof (core 5.2, L1 11.6); vector `commitment_agents` signs in either order. |
| S-I8 Replay and authentication gaps | R | Seven-day lifetime, record after verify and per-chain deduplication (L1 12.4); the client sets `domain` (13.3); RFC 9421 replay rules and `sha-256` (13.3). Small leftovers: Minor M2 and M3. |
| S-I9 Retired minds keep signing | R | L1 3.10 and 6.1 items 3 and 6 (`Retire` counts as a removal; the current-state rule requires "not retired"). |
| S-I10 Status gaps around superseding records and ties | R | L2 4.3 and the 8 header (precedence, own status, `superseded`); charter in force with a tie-break (6.2); Location tie-break (L1 15.2). The checker lacks the charter tie-break (M9). |
| S-I11 Nesting, cycles, reference times | R | Height and cycles (L1 4.7); recursive signing reserved (9.4); the charter in force at `t(p)` (L2 7.1 item 4); wording aligned. The new height rule enables griefing (N3). |
| S-I12 Sessions with more than two participants | R | L1 14.3 (`from` in `participants`, `to` lists everyone else, equivocation). |
| S-I13 Endpoint bindings undefined | R | Binding table in L1 15.1; the vector's `wss` URL is a full URL. |
| S-I14 Size limits | R | Containers exempt and `Sealed` overhead (core 1.6); log paging (L1 13.1). `LogPage` is missing from core's container list (M8). |
| S-I15 One mind in several roles | R | L2 5.1 ("each mind appears at most once"); checker `record_ok`. The related issue of one *proof* counting for several parties is new (N6). |
| S-I16 `Merge` reserved but accepted | R | L1 3.9 and 4.6; negative vector `merge-reserved`. |
| S-I17 Policies can't bound what a Commitment obliges | R | Array and quoted selectors, quantifiers and connectives (L1 11.3); terms authoritative (L2 5.4); counterparty vector `policy-counterparty`. Price direction is new (N10). |
| S-I18 Gateway never checked | P | L0 1.2 requires the gateway's proof on the `Genesis`, but that proof cannot pass core 5.4 and 5.6 (N9). |
| S-I19 Number precision, string length | R | Core 1.3 (exact, at most 64 characters), 1.4 (nanoseconds) and 1.8 (code points); the checker uses `Decimal` and integer nanoseconds. |
| S-I20 Checker more lenient than the spec | P | Every item listed is now implemented, with negative vectors, but the checker still departs from the spec on per-proof evidence (N2), Ed25519 (N5), the charter tie-break, the L2 5.2 author rule, `/oip/send` and duplicity (M9). |
| S-I21 Vector coverage | P | The X25519 seed is documented; new vectors cover revocation, `Retire`, checkpoint, `Ack`, `Hello`, chains, DID documents, collective events and roles, plus 36 negatives. Still missing: `Sealed`, `Resume`, `Branch`, Ed25519 edge cases, Offer `exhausted`/`withdrawn`/`superseded`, Intent `expired`, and Commitment `claimed-fulfilled`/`broken`/`cancelled`. |

### Minor findings not resolved

Everything else in the Minor lists of both reviews (paper review Minor; spec review M1–M3) is resolved.

- **Paper 3.2 table (paper review, lines 139–140).**
  - The table still says location records, profiles and feeds are "Signed by an operational key", which is not true for collectives.
  - The paper never mentions collective-owned `keys` (L1 9.5).
- **Paper 5.2 (paper review, line 316).** "Every event after the genesis carries … `seq` (0 for the genesis, then 1, 2, …)" still reads as if the genesis carries `seq`.
- **Naming (paper review, line 926).** KServe's "Open Inference Protocol" is not mentioned. Paper 12 addresses only "OIPs".
- **Participant and Location signing (spec review M2).**
  - L1 15.1 and 16.1 require "a valid operational key".
  - L2 7.2 allows the member threshold for current-state records.
  - These still disagree (N7).
- **L1 14.2.** It keeps "unless the receiver has already been shown it", which a receiver cannot check (the spec review proposed dropping it under S-C5).

All spec-review M1 cross-reference corrections are in place. I spot-checked about 70 further section references across the four specifications and the paper (for example core 9.4 → L1 10 and 13.2, L1 6.3 → 13.1 and 17, L1 7.4 → L0 6, L2 5.4 → 7.1 items 2 and 4, L0 6 → L1 3.7 and 7.4) and found none that points to the wrong section.

## Consistency of specs, paper and checker

I compared the specs, the paper's Appendix A and the checker on each core rule. The following agree:
- thresholds and log verification: L1 3–4, A.4 and `verify_log`;
- key validity items 1–7: L1 6.1, A.5 and `valid_key`;
- delegation chain rules: L1 11.4, A.6 and `chain_ok`;
- policy semantics: L1 11.3 and `statement_holds`;
- Commitment, Intent and Offer status: L2 8, A.7 and the status functions.

These disagree:

1. **Evidence granularity.**
   - Core 9.3–9.4 and A.3 define evidence per proof.
   - The checker (`Verifier.t_of`: `self.seen.get(content_id(record))`), the vectors' `seen` map ("content ID → time") and the resolver's `firstSeen` (L1 13.1) key it by content ID. (N2)
2. **Default evaluation time without evidence.**
   - Core 9.3 uses the time the verifier first obtained the proof.
   - The checker uses the proof's `created`. This is documented in the vectors README, but it means the vectors cannot express "first seen late" except through `seen`.
3. **Ed25519.**
   - Core 4.4, A.2 `verifyStrict` and BUILD.md §3 require strict verification.
   - The checker uses OpenSSL's verification, which accepts mixed-order and small-order keys. (N5)
4. **Witness rule for invocation keys.**
   - L1 6.4 (last sentence) and paper 5.5 have witnesses apply 6.1 items 3–4.
   - A.5 `memberSignsAtPosition` and the checker never do.
   - For a witness that first receives the collective after a member's claim, the witness rule also contradicts the must-accept vector `collective-survives-member-compromise-claim`. (N1)
5. **Collective height.**
   - L1 4.7 does not say at which version a member's height is taken.
   - The checker uses the member's current height and re-verifies the member's whole current log. (N3)
6. **Charter in force.**
   - L2 6.2 breaks ties by lower content ID.
   - The checker takes `max` by time only, so the result depends on store order. (M9)
7. **Charter signing.**
   - L2 6.2 says "under the threshold rule".
   - Core 11 and L2 7.2 say "own authority" (own keys or threshold).
   - The checker accepts both. (M7)
8. **Current-state records of collectives.**
   - L1 15.1 and 16.1 require "a valid operational key".
   - L2 7.2 item 3 and the checker allow the threshold, with no rule for current membership. (N7)
9. **Bridged-mind proof.**
   - L0 1.2 requires `assertionMethod` on a `Genesis`.
   - Core 5.4 and 5.6, L1 3.5 and 6.1 item 5, A.2 and A.5 forbid it, and the checker rejects it. (N9)
10. **Commitment author.** L2 5.2 says the author must be a party or a delegate of one; A.6, A.7 and the checker do not check this. (M9)
11. **`/oip/send`.** Defined in L1 11.2, but absent from A.6 and the checker.
12. **Duplicity.** L1 7.3 and paper 5.2 define a resolution rule; the checker holds one log per mind and has no duplicity handling.
13. **Containers.** L1 13.1 and paper Appendix B include `LogPage`; core 1.6 and the core 11 table do not. (M8)
14. **Claims that go beyond the specs or code.**
    - The paper abstract says time is "never on the signer's own clock".
    - Appendix A says the generator "implements each of these".
    - Paper 6.4 says "every state above except the rarer receipt outcomes".
    - The CHANGELOG says "The generator implements all of the above".
    - BUILD.md §3 says the two implementations "accept exactly the same signatures".
    - Paper 8.1 lists "signatures judged at their position" as a mitigation against capture of a collective, when it enables N1.
    - (M10)

## New findings

### Critical

**N1. Stale invocation keys can extend or fork a collective's log, and the witness rule cannot protect new witnesses.**

*Location:* L1 6.4, 4.1, 4.4 and 9.3; core 9.5 (last sentence); core 11 ("at position"); paper 5.5 ("Signatures are judged at their position") and 8.1 ("Capture of a collective"); A.5 `memberSignsAtPosition`; checker `Verifier.valid_key(..., at_position=True)`.

*Problem.* A member's proof on a collective's identity event counts whenever its key was an invocation key at the version it pins; no time is checked. Unlike control keys, invocation keys are reused, so they cannot be destroyed after use (L1 7.4 protects only control keys). Anyone who ever holds a threshold of members' invocation keys can therefore act on the collective's log, even keys the members have since removed and declared compromised:
- **(a) Append events.** Add members, give the collective an operational key, change homes or retire it. Every verifier that does not consult a witness accepts these. No MUST requires consulting one: core 9.4 item 2 is the verifier's choice, and `hints` (L1 12.1) let the attacker choose where the log is fetched.
- **(b) Sign an alternative event at any past position.** For verifiers without evidence, this makes the collective duplicitous (7.3) or replaces its history.

The last sentence of 6.4 has witnesses apply 6.1 items 3–4 "when they receive" an event. That works only for witnesses already following the log. A witness that first receives an existing collective, such as a new resolver, has two choices, and both fail:
- **Apply items 3–4 to every event.** A member that rotates, or claims compromise of, an old invocation key then unmakes the collective for every new witness. This is exactly the S-C1 repudiation that the at-position rule was introduced to stop, and it contradicts the must-accept vector.
- **Judge at position.** The witness then accepts the forged log, because it cannot tell an old event from a new forgery.

For key-controlled minds, by contrast, a used control key can sign only at its own position, and only the unrevealed next keys can extend the log.

*Evidence:* `probe_time_keys.py` §2.
- Amina and the researcher remove their invocation keys on 2 Nov, declaring them compromised since 1 Nov.
- On 1 Dec, a holder of the two old keys appends an `Update` that gives the collective its own operational key.
- `Verifier.log` accepts the log (`collective keys now: True`).
- A `Delegation` signed with that key counts for the collective (`True`), so the holder can delegate, re-charter and commit for it.

*Fix.*
- Judge member proofs on identity events at the event's evaluation time using 6.1 items 1–3 and 5. Removal and retirement take effect at their own evaluation time and are not retroactive.
- Do not apply item 4 (`compromisedSince`) to other minds' identity events. That keeps members unable to unmake a collective retroactively.
- Make evidence mandatory for collective identity events: a verifier MUST take each event's time from a witness it trusts or from an anchor, and resolvers MUST serve those times (they already record them, 17.2). This is the same evidence model core 9.7 already applies to every other record.
- Add vectors: an event signed by removed invocation keys, rejected when its evidence is later than the removal and accepted when it is earlier.
- Until this is done, mark collective identity as unstable in the draft, and correct paper 5.5 and 8.1.

### Important

**N2. The checker keys evidence by content ID, so a proof added later can be backdated.**

*Location:* `oip_vectors.py` `Verifier.t_of` (`seen = self.seen.get(content_id(record))`); vectors README, "Evaluation times"; L1 13.1 `firstSeen`. These conflict with core 9.3–9.4 and A.3, which define evidence for the proof itself.

*Problem.* Proofs do not change a content ID, so a co-signature added on 5 Nov to a record first seen on 30 Oct is evaluated at 30 Oct. A holder of a compromised, removed or expired key, or of a revoked delegation, can complete any record the verifier saw earlier (typically a proposed Commitment) and backdate past every time rule: the attack class of S-C1 and P-C5. The vectors cannot express per-proof evidence, so the five backdating negatives cover only proofs first seen together with their record. An implementation that copies the checker, as BUILD.md §6.2 encourages, inherits the hole.

*Evidence:* `probe_time_keys.py` §1.
- The vector `commitment_proposed` was seen on 30 Oct at 10:20.
- A proof by Amina's phone key, declared compromised since 31 Oct, is added later with `created` 30 Oct 10:25.
- `counts_for` returns `True`, and the Commitment's status becomes `overdue`, which means accepted.
- Under core 9.3 the proof was first obtained on 5 Nov and does not count.

*Fix.*
- Key evidence by proof (the proof digest of L1 10.1, `sha256:` + hex(SHA-256(JCS(proof)))) in the checker, in `seen` and in resolver `firstSeen` for anything other than identity events.
- Add a negative vector: a late co-signature on an early-seen record.

**N3. A member collective can invalidate every collective it belongs to.**

*Location:* L1 4.7 and 6.4 ("M's log verifies"); checker `verify_log` (heights) and `Verifier.log` (depth).

*Problem.* L1 4.7 does not say at which version a member's height counts. The checker uses the member's current height and re-verifies its whole current log one level deeper. A member collective that later adds a height-3 member reaches height 4, which is valid on its own. That pushes its parent to height 5, and the parent's entire log is rejected, genesis included. The parent's other members have no say. This contradicts the at-position principle that a member's later changes do not reach back.

*Evidence:* `probe_collectives.py` §1.
- Y = {C1, q1, q2} verifies at height 2.
- C1's own members add D3 (height 3) to C1, and C1 verifies at height 4.
- Y is then rejected: "every founding member must sign with an invocation key".

*Fix.* Take a member's height, and its log validity, at the version its proof pins: verify the member's log only up to that version. A member's later growth then affects only new events that pin later versions.

**N4. The delegation chain search is exponential.**

*Location:* L1 11.6 ("some sequence of the delegations listed"); A.6 ("for each chain d1 … dn drawn from p.authority"); checker `Verifier.chains`.

*Problem.* With up to 16 entries and chains of up to 8, a verifier that looks for "some sequence" explores up to 16!/8! orderings. The entries are searched before any signature is checked, and nothing forbids `author` = `delegate`, so every entry can follow every other. One record can carry 256 such proofs, and each principal of interest is searched separately.

*Evidence:* `probe_chain_dos.py`.
- 10 unsigned inline entries of the form `ltd→ltd`: 2,606,500 prefixes and 3.15 s for one `counts_for`.
- 16 entries: 582,913,216 prefixes, about 12 minutes at the measured rate, for each proof and each principal.

*Fix.*
- Require `authority` to list exactly the chain, root first, in the order L1 11.4 already uses for d₁…dₙ.
- Verify only that order, and reject the proof if it fails rather than searching.
- Forbid `author` = `delegate`.

**N5. The checker does not apply core 4.4, and core 4.4 admits the identity point.**

*Location:* `oip_vectors.py` `verify_proof` (OpenSSL through `cryptography`); core 4.4; A.2 `verifyStrict`; BUILD.md §3 ("so that this implementation and the Python checker accept exactly the same signatures"); paper 4.6.

*Problem.* OpenSSL checks S < L and the cofactorless equation, but not that A is in the prime-order subgroup. A signer with a mixed-order key can grind (one message in eight) for proofs that the checker accepts and a 4.4-compliant verifier, such as the TypeScript implementation BUILD.md specifies, rejects. That is the split S-I3 warned about, now between the spec's own two implementations. Separately, core 4.4 accepts the identity point as a public key (it is in the subgroup), and anyone can sign any message for it. A mind that uses it can disown any of its signatures, which defeats the attributability of duplicity (L1 3.4, 7.1).

*Evidence:* `probe_ed25519.py`, with `cryptography` 50.0.1 and OpenSSL 4.0.2:
- a mixed-order key A = [a]B + T₈ with k ≡ 0 mod 8 is accepted;
- an order-8 key with no private key at all is accepted;
- an `Intent` by a mind whose operational key is mixed-order counts in the checker.

*Fix.*
- In the checker, decode A and R, reject non-canonical encodings and any point P with [L]P ≠ O, then verify.
- Add to core 4.4 "and A is not a point of small order (including the identity)".
- Add the deferred Ed25519 edge-case vectors as negative cases.

**N6. One proof counts for several parties, and role holders do not choose to act.**

*Location:* L1 11.6; L2 7.1 items 2 and 4, and 7.3; paper 4.3, 5.6 and 6.3 ("the choice to act for a principal is itself signed").

*Problem.*
- Nothing limits how many parties one proof counts for. A delegate holding delegations from both sides can accept a deal between them alone (dual agency).
- A delegate or role holder that is itself a party can bind its principal to itself (self-dealing).
- A role-based proof carries no statement that the member acts for the collective, so a member signing as a party also binds the collective automatically. This undercuts the rationale for moving delegations into the proof.

*Evidence:* `probe_time_keys.py` §4:
- (a) the Lexis agent alone makes an accepted Commitment in which Lexis Ltd owes the agent 500 USD, because the vector delegation has no counterparty limit;
- (b) the steward alone makes an accepted Commitment in which the collective owes the steward 500 USD, with no `authority` member;
- (c) one agent holding delegations from Amina and from Lexis Ltd accepts a deal between them with a single proof.

*Fix.*
- In L2 7.3, require a distinct proof for each required party other than the signer's own mind.
- Require role-based proofs to name the collective, for example `authority: [<charter record-ref>]`.
- Add counterparty limits to the vector delegation and charter, and recommend in L1 11.3 that delegators exclude the delegate itself as counterparty.

**N7. A collective's stale `Location` can never be superseded.**

*Location:* L1 6.1 item 6, 15.1–15.2 and 16.1; L2 7.2; core 11.

*Problem.*
- The specs disagree on whether a member threshold may sign current-state records (see the Consistency list, item 8).
- The checker allows it, but applies the current-state rule only to each member's key in the member's own log, not to the collective's current membership.
- A quorum can therefore sign a `Location` with `seq` 2⁵³−1. Once a verifier or resolver holds it, it stays current even after those members leave, and nothing can ever have a higher `seq`.
- For key-controlled minds, removing the key ends this (15.4). Collectives have no equivalent.

*Evidence:* `probe_collectives.py` §2.
- Amina and the researcher sign a `Location` with `seq` 2⁵³−1, first seen on 30 Oct.
- The researcher is removed on 31 Oct.
- The record still counts for the collective.

*Fix.*
- Decide whether a threshold may sign current-state records.
- If it may, require the signers to meet the threshold of the collective's latest state.
- Bound `seq`, for example to at most the previous value plus 2³².

**N8. A key removal takes effect at the verifier's own first sight of it, which a removed key's holder can outrace.**

*Location:* core 9.3–9.5; L1 6.1 item 3, 6.3 and 9.5; paper 5.3 ("stops it signing anything new") and 8.1.

*Problem.*
- Without a witness, the evaluation time of a removal is when the verifier first obtained it.
- A verifier that receives a proof before refreshing the signer's log ends up comparing "when I saw the proof" with "when I saw the removal". That does not show which came first.
- The holder of a removed key wins against such verifiers. This covers removals without `compromisedSince`: a former employee, a departed host.
- Late verifiers likewise date membership additions late, so valid collective records signed by newly added members fail.
- L1 6.3 says only SHOULD refresh, and refreshing after receipt does not help without witness times.

*Evidence:* `probe_misc.py` §2.
- Amina removes her phone key on 2 Nov.
- An `Intent` signed with the key on 3 Nov, received on 3 Nov, counts for a verifier that first sees the removal on 4 Nov.
- With the witness time (2 Nov), it does not count.

*Fix.*
- Before counting a proof by a key of X, a verifier MUST hold X's log with witness or anchor times obtained after τ(p).
- It MUST use those times for X's events, rather than its own later first sight.
- State the race in paper 5.3 and 8.1.

**N9. The bridged-mind proof required by L0 1.2 cannot verify.**

*Location:* L0 1.2–1.3; core 5.4 and 5.6; L1 3.5 and 6.1 item 5; A.2 and A.5; paper 7.1.

*Problem.*
- L0 1.2 requires the gateway to sign the bridged mind's `Genesis` with an operational key and `proofPurpose` `assertionMethod`.
- Core 5.4 requires the purpose that 5.6 assigns to the record type, which is `capabilityInvocation` for a `Genesis`.
- L1 3.5 says operational keys never sign identity events.
- A verifier following core and A.5 therefore never accepts the gateway's proof, and every bridged mind is only `claimed`.

*Evidence:* `probe_misc.py` §1.
- The gateway's `assertionMethod` proof fails `valid_key`.
- The same proof with `capabilityInvocation` passes, which contradicts L1 3.5.

*Fix.* Either:
- make the gateway's attestation a separate gateway-authored record naming the bridged mind's address, signed with `assertionMethod`; or
- add to core 5.6 an explicit exception for a gateway proof on a `Genesis` that does not count towards the log.

Add a vector either way.

**N10. A Commitment does not say who pays its price.**

*Location:* L2 5.1 (`terms.price` "as in an Offer") and 5.4; L1 11.3; paper 3.4 ("a spending limit"), 5.6 and 6.9.

*Problem.*
- `price` has an amount and a currency but no payer.
- In the vectors the creditor (Amina) pays the debtor (Lexis Ltd). With the roles swapped, the same policy lets the agent commit Lexis Ltd to pay.
- L2 5.4 makes the structured terms prevail for a delegated party, but the terms do not say whether that party pays or is paid.
- Policies bound each record, not totals, so the vector delegation is a per-Commitment price cap that the agent can use any number of times, not the "spending limit" paper 3.4 describes.

*Evidence:* by inspection; `probe_time_keys.py` §4(a) shows Lexis Ltd committed as debtor to a 500 USD price payable to its own agent.

*Fix.*
- Add a structured payer and payee to `price`, or state normatively who pays in terms of roles.
- Constrain roles in the vector policy.
- Describe the vector delegation as a per-commitment cap, and note that cumulative limits need an extension.

### Minor

- **M1. Policy negation fails open.** `["not", …]` turns a comparison that is false because of a missing path or a non-decimal operand into true, so `["not", [">", ".x", "500"]]` holds when `.x` is absent. Make a missing path or a type mismatch fail the whole policy, or warn against negating comparisons on optional members.
- **M2. Replay window at expiry.** L1 12.4 accepts packets until `expires` + 300 s but lets receivers discard duplicate-detection state "after its `expires`". That leaves a 300-second replay window. Write "after `expires` + 300 seconds".
- **M3. Session age rule vs `Resume`.**
  - L1 12.4 rejects a session packet older than the receiver's duplicate-detection window.
  - L1 14.4 retransmits original packets after a pause (paper 5.10: "a pause of a week").
  - So a receiver with a short window can never fill the gap. Exempt retransmissions, which are already deduplicated by (`session`, `from`, `instance`, `seq`).
- **M4. Acks of sealed packets are not usable evidence.** The `Ack` of a `Sealed` body names the `Sealed` record (L1 13.2). HPKE is randomised, so a third party cannot link it to the inner packet, and it is not usable as evidence under core 9.4 item 4 for the binding records it carries. Also name the inner packet's content ID.
- **M5. Removals under duplicity.** L1 7.3 keeps records pinned before a divergence valid, but does not say which branch's later removals and compromise declarations apply. Apply the union of all branches.
- **M6. Old consent can complete a collective record.** A member's signature on an abandoned charter or proposal can be combined much later with other members' signatures to complete it (L1 9.5). Recommend `expires` on such records.
- **M7. Charter signing.** L2 6.2 says "under the threshold rule"; core 11 and L2 7.2 allow own authority. Pick one.
- **M8. `LogPage` is not a container in core.** It is a container in L1 13.1 and paper Appendix B, but missing from core 1.6 and the core 11 table. Core 7 then requires it to carry `created`.
- **M9. Further checker gaps:**
  - no charter tie-break: the steward depends on insertion order (`probe_collectives.py` §3);
  - no L2 5.2 author check: a Commitment authored by a non-party is accepted (`probe_time_keys.py` §5);
  - no `/oip/send`;
  - no duplicity handling;
  - event evaluation times are made monotonic (`times[-1]`), a sensible rule that the spec does not state.
- **M10. Claims beyond the specs and code.**
  - Paper abstract: "never on the signer's own clock".
  - Appendix A: "implements each of these".
  - Paper 6.4: "every state above except the rarer receipt outcomes". Four states that are not receipt outcomes are untested: Intent `expired` and Offer `withdrawn`, `superseded` and `exhausted`.
  - BUILD.md §3: N5.
  - CHANGELOG: "The generator implements all of the above".
  - Paper 1.2's independent-reproduction sentence applies only to the first revision.
- **M11. `notBefore` cannot prevent pre-signing.** A proof made early counts for any verifier that first sees it after `notBefore`. Say so in L1 11.1.

### Checked and sound

- **Third-party `authority`.** A third party cannot attach a delegation to someone else's proof: `authority` is inside the signed proof options (core 5.3, checker `verify_proof`).
- **Forgeries after a compromise declaration.** A forgery made after the declaration fails on the key's removal (L1 6.1 item 3) and shows as `proposed`, not `disputed` (`probe_time_keys.py` §3). `disputed` arises only for proofs made between `compromisedSince` and the declaration, which is the intended case.
- **Backdated removals and revocations** cannot withdraw records seen earlier (the must-accept vectors).
- **Chain narrowing, decimal comparison and counterparty quantifiers** behave as specified.
- **The canonical content-ID pattern** is exactly the set of canonical spellings.
- **Values.** Every mind address is unchanged from the first revision, and every value quoted in the paper is in `vectors.json`.

## Verdict

The revision resolves the large majority of what the two reviews found, and most fixes are clear, well-placed rules with negative vectors that fail for the stated reason. The security core is close, but not yet ready to publish as the draft that implementers build on.

**Before publishing:**
- **N1.** Fix it, or mark collective identity events as unstable in the draft and stop presenting judgement at position as a mitigation.
- **N2 and N5.** Bring the checker into line with core 9 and core 4.4. BUILD.md makes the checker the cross-check for the reference implementation, so these disagreements would otherwise be copied.

**Next draft:**
- **N4.** Order the chain; this is a small change.
- **N3, N6, N7, N8, N9, N10:** clarifications with modest format impact.
- The Minor items.

With N1, N2 and N5 addressed, the revision is ready to publish as a draft.
