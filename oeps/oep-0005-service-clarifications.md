---
oep: 5
title: Service clarifications found while building the reference servers
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 1 # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: 2026-11-19
requires: [1, 2, 3, 4]
replaces: []
discussion: # the pull request of milestone M5
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0005: Service clarifications found while building the reference servers

## Summary

Writing the resolver of the reference implementation showed places where Layer 1, Section 17 (revision 2026-11-17, with OEP-0001 to OEP-0004) names a thing without saying what it is, or gives a rule without saying what follows when only part of what a client sent meets it. This proposal settles each.

The milestone is not finished. The host and the indexer are still to be built, and items are added as they are. The list is final when the milestone is.

## Motivation

A resolver is a witness. Clients take the times it first saw an event as evidence (core 9.4), and merge what two or more resolvers tell them. So two resolvers that are shown the same bundles in the same order must hold the same things, and what one of them serves must not harm a client that also asks another.

1. **What is `<mindId>`?** Section 17 uses it in three paths and does not define it. The technical paper does: the content ID of the genesis.
2. **What does a resolver do with a bundle of which only part verifies?** 17.2 says it verifies every record before storing or serving it. A published log may hold events that verify and then one that does not.
3. **Which proofs does a resolver keep?** Each proof stands on its own (core 5.5), anyone can add one to a copy of an event, and a verifier shown more proofs for one event than a record carries treats the log as not verified (7.1). A resolver that kept and served every proof it was shown would be the means of that.
4. **Can a resolver first see two events at once?** 7.3 gives a position to the event with strictly the earliest evidence. A resolver's clock has a resolution.
5. **How does a mind publish its own log where publication must be signed?** 17.3 lets a resolver require a signed request. The signature is judged against the signer's log (13.3), which the resolver does not hold before the log is published.
6. **What is a cursor?** 17.1 says the stream takes `since=<cursor>` and that events carry one.

## Specification

Each item is a change to `spec/layer-1-mind-network.md`, made in the same commits as the code.

1. **`<mindId>` (17.1).** The content ID of the mind's `Genesis` event: its address without `did:oip:`, and the `m` of 13.1. A path that names anything else names no mind and is answered `404`. A bundle published under one mind's `<mindId>` whose `mind` or whose log is another's is `invalid-record`.
2. **What a resolver takes of a bundle (17.2).** The events of the published log that verify, from the genesis on, and nothing after the first that does not, whether that event is invalid or undecided (4.9). What verified before it is merged. The request is answered with that event's problem: `invalid-proof` if it is invalid, `unsupported-critical` if the resolver cannot read it for a critical extension it does not implement, and otherwise `stale-version`. A location record or a profile is stored only if the mind's own authority signed it under the current-state rule, and no first-seen time is recorded for the proofs of a record that is not stored.
3. **Which proofs a resolver keeps (17.2).** Those that can count for the event: a proof whose signature verifies, by a control key the event reveals (3.4) or by an invocation key a member has at the version the proof names (6.4). A resolver MAY keep another proof whose signature verifies where leaving it out would leave the event unverified. It MUST NOT serve more proofs for one event than a record carries.
4. **Order (17.2).** A resolver MUST NOT record the same first-seen time for two events of one mind. Where its clock has not moved, it records the later a nanosecond after the earlier.
5. **Authenticated publication (17.3).** A resolver that requires it accepts a request signed by a mind whose key is valid by the logs the resolver holds, or by the mind whose bundle is published, judged against the log in that bundle as far as it verified. The signer need not be the mind whose bundle it is.
6. **The stream's cursor (17.1).** A string of decimal digits; cursors rise in the order the resolver took things in. Without `since` the stream starts from the first. A server-sent event's `id` is its cursor, and `Last-Event-ID` may stand for `since`. Each identity event and each location record is told of once, when it is first stored.

## Rationale and alternatives

- **Item 2: keep what the publisher showed, as a verifier keeps the copies of a source it trusts (4.9).** A publisher is anyone. A resolver that held every event it was shown, to judge later, would hold whatever anyone sent it for a mind, and one undecided event would stop the mind's log there for as long as it was held. 4.9 ends: "A copy from a source the verifier does not trust in that way is no reason to stop relying on one that is." That is the resolver's case.
- **Item 2: refuse the whole bundle when any event fails.** Simpler to say. But the time a resolver first saw a valid event is what protects a mind against a later rival event, and a resolver that discarded valid events because of what followed them in a copy would give that time away.
- **Item 3: keep every proof whose signature verifies.** Such a proof may be by any key at all, and costs its maker nothing. The harm is to clients, not to the resolver: each resolver alone stays within the 256 a record carries, and the two together need not.
- **Item 3: let a client keep only the proofs that count.** It should, and 7.1 could say so. But a client cannot rely on every other client doing it, and a resolver that serves no such proof needs nobody to.
- **Item 4: a counter in place of a clock.** A first-seen time is evidence because other evidence is compared with it. A counter compares with nothing outside the resolver.

## Backwards compatibility

No record format changes, and no test vector. A resolver built to the earlier text may differ in what it stores of a bundle that verifies in part, and in which proofs it serves. Items 1, 5 and 6 say what the earlier text left to the implementer.

## Security and privacy considerations

Item 3 closes a way to deny a mind to clients that ask two resolvers. Item 4 keeps a resolver from calling a mind duplicitous on the strength of its own clock's resolution. Item 2 means that a mind's own event which a resolver cannot judge, because it uses a critical extension the resolver does not implement, is not stored: that resolver then serves the log up to the event before it. See the open questions.

## Test vectors

None yet. Vectors for requests and responses over HTTP are planned with the conformance suite over the wire, in this milestone.

## Reference implementation

`LogArchive` of `@oip/server`, in `packages/server`: `intake.ts` (items 2 and 3) and `archive.ts` (items 1, 4 and 5). `@oip/resolver`, in `packages/resolver`: `app.ts` (items 1, 2, 5 and 6).

## Open questions

1. **A mind's own event that a resolver cannot judge.** The resolver serves the log up to the event before it, and a `Bundle` has no way to say that the resolver has been shown more. A client that takes the bundle as the whole log, known up to now, may count a key the event removed. A member such as `undecidedAfter`, naming the position, would let a client treat the log as it treats one with an undecided event (4.9). Anyone could then make a resolver say so of any mind, by sending it an event it cannot read, so the cure may be worse: a client that asks two resolvers, one of which implements the extension, is not misled.
2. **What a `401` carries.** RFC 9110 asks for `WWW-Authenticate` with a `401`, and RFC 9421 defines `Accept-Signature` for asking for a signature. 13.3 names neither.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
