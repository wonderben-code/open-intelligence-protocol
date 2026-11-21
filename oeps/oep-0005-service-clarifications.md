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

Writing the resolver, the host and the indexer of the reference implementation showed places where Layer 1, Sections 13, 17 and 18 (revision 2026-11-17, with OEP-0001 to OEP-0004) name a thing without saying what it is, or give a rule without saying what follows when only part of what a client sent meets it. This proposal settles each. Items 1 to 6 are from the resolver, 7 and 8 from the host, and 9 to 12 from the indexer.

## Motivation

A resolver is a witness. Clients take the times it first saw an event as evidence (core 9.4), and merge what two or more resolvers tell them. So two resolvers that are shown the same bundles in the same order must hold the same things, and what one of them serves must not harm a client that also asks another.

1. **What is `<mindId>`?** Section 17 uses it in three paths and does not define it. The technical paper does: the content ID of the genesis.
2. **What does a resolver do with a bundle of which only part verifies?** 17.2 says it verifies every record before storing or serving it. A published log may hold events that verify and then one that does not.
3. **Which proofs does a resolver keep?** Each proof stands on its own (core 5.5), anyone can add one to a copy of an event, and a verifier shown more proofs for one event than a record carries treats the log as not verified (7.1). A resolver that kept and served every proof it was shown would be the means of that.
4. **Can a resolver first see two events at once?** 7.3 gives a position to the event with strictly the earliest evidence. A resolver's clock has a resolution.
5. **How does a mind publish its own log where publication must be signed?** 17.3 lets a resolver require a signed request. The signature is judged against the signer's log (13.3), which the resolver does not hold before the log is published.
6. **What is a cursor?** 17.1 says the stream takes `since=<cursor>` and that events carry one.

A host and an indexer must work with hosts, indexers and clients that others wrote.

7. **Where does a broker deliver?** 12.4 has a receiver accept a packet addressed to a query only inside a `Forwarded` record from a broker, and 18.5 has a broker forward one. 13.2 says an inbox takes a `Packet` or a `Sealed` record, and 13.5 the same of a mailbox. A host built to that text refuses every brokered delivery.
8. **What is said over a socket after the welcome?** 13.4 says "each message is one record", and that a mind's instance may hold a socket open to receive its packets. It does not say how the instance tells its host what it has, so that the host can stop keeping it, or what a server does with a message it refuses.
9. **What must an indexer check before it lists a record?** 18.4 has clients verify what a result names. 18.1 does not say that an indexer verifies anything.
10. **What does `/*` match?** 18.2: "a value ending in `/*` matches any value with that prefix". The prefix of `oasf:nlp/*` could be `oasf:nlp` or `oasf:nlp/`.
11. **What of a query whose `constraints` or `evidence` an indexer cannot weigh?** 18.4 says ranking is the indexer's own policy. A filter is not a ranking.
12. **What does a broker owe the sender and the recipients?** 18.5 says to how many minds a packet goes, and not whether the same packet is forwarded again when it is sent again, whether it may go back to its sender, where it is posted, or what the broker answers.
13. **What media type has a submission, or a query?** core 10.1 names the media type of a record. A submission and a capability query are JSON and not records, and 18.1 names no media type for them.

## Specification

Each item is a change to `spec/layer-1-mind-network.md`, made in the same commits as the code.

1. **`<mindId>` (17.1).** The content ID of the mind's `Genesis` event: its address without `did:oip:`, and the `m` of 13.1. A path that names anything else names no mind and is answered `404`. A bundle published under one mind's `<mindId>` whose `mind` or whose log is another's is `invalid-record`.
2. **What a resolver takes of a bundle (17.2).** The events of the published log that verify, from the genesis on, and nothing after the first that does not, whether that event is invalid or undecided (4.9). What verified before it is merged. The request is answered with that event's problem: `invalid-proof` if it is invalid, `unsupported-critical` if the resolver cannot read it for a critical extension it does not implement, and otherwise `stale-version`. A location record or a profile is stored only if the mind's own authority signed it under the current-state rule, and no first-seen time is recorded for the proofs of a record that is not stored.
3. **Which proofs a resolver keeps (17.2).** Those that can count for the event: a proof whose signature verifies, by a control key the event reveals (3.4) or by an invocation key a member has at the version the proof names (6.4). A resolver MAY keep another proof whose signature verifies where leaving it out would leave the event unverified. It MUST NOT serve more proofs for one event than a record carries.
4. **Order (17.2).** A resolver MUST NOT record the same first-seen time for two events at one position of a mind's log. Where its clock has not moved since it recorded the first, it records the second a nanosecond later. Events it receives together in one log are evaluated at the time it receives them (core 9.5) and MAY share that time: the log gives their order. An earlier wording of this item said "two events of one mind", which asked more than its reason does and more than core 9.5 allows: the conformance suite over the wire showed the difference.
5. **Authenticated publication (17.3).** A resolver that requires it accepts a request signed by a mind whose key is valid by the logs the resolver holds, or by the mind whose bundle is published, judged against the log in that bundle as far as it verified. The signer need not be the mind whose bundle it is. The logs the resolver holds are those it held before it took the bundle, so that a mind can publish the event that removes the key it signs the request with, or that retires it. The client of M6 found the need: by the log in such a bundle no key of the mind signs the request, and the reference resolver, which judged a mind's own request by that log alone, refused a mind its own retirement.
6. **The stream's cursor (17.1).** A string of decimal digits; cursors rise in the order the resolver took things in. Without `since` the stream starts from the first. A server-sent event's `id` is its cursor, and `Last-Event-ID` may stand for `since`. Each identity event and each location record is told of once, when it is first stored.
7. **What an inbox and a mailbox take (13.2, 13.5).** A `Packet`, a `Sealed` record, or a `Forwarded` record that carries a packet. An inbox judges a forwarded packet as 12.4 says. The packet is the same packet whichever broker forwarded it: an `Ack` names it by its own content ID, and the same packet from another broker is a duplicate. A mailbox judges nothing, as before.
8. **After the welcome (13.4).** A `Packet`, a `Sealed` record or a `Forwarded` record sent to the server is delivered as at the inbox, and the server MAY send back the `Ack`. To a mind's own instance the host sends the records it keeps for the mind. The instance says that it has one by sending its own `Ack` for it, after which the host MAY remove the record from the mailbox; until then the record stays there. A server that does not accept a message closes the connection with code 1008 and SHOULD give the error code as the reason.
9. **Submission (18.1).** An indexer MUST verify a record before it lists it: a `Participant`, an `Offer` or an `Intent` is signed by its author's own authority, judged by a log the indexer holds. Its `202` MAY say what became of each record: `{ "taken": <count>, "refused": [ { "index", "type", "detail" } ] }`.
10. **Tag prefixes (18.2).** A value ending in `/*` matches any tag that begins with the value without its final `*`. `oasf:nlp/*` matches `oasf:nlp/translation`, and neither `oasf:nlp` nor `oasf:nlpx`.
11. **Unweighed constraints and evidence (18.2).** An indexer MUST NOT return a result for a query whose `constraints` or `evidence` it has not checked against that result. One that weighs neither returns no result for a query that states either.
12. **A broker (18.5).** It forwards a packet once: the same packet again is answered as before and forwarded no second time. It does not forward a packet to its own sender. It posts each `Forwarded` record to an inbox of the mind's current location record, or to a mailbox where no inbox accepts it (15.3). It answers `202` with `{ "stored": true }`, and MAY add `forwarding`, the number of minds the packet goes to.
13. **Submissions and queries (18.1).** Both are sent as `application/json`. A `QueryResult` is a record, and is served as one (core 10.1).

## Rationale and alternatives

- **Item 2: keep what the publisher showed, as a verifier keeps the copies of a source it trusts (4.9).** A publisher is anyone. A resolver that held every event it was shown, to judge later, would hold whatever anyone sent it for a mind, and one undecided event would stop the mind's log there for as long as it was held. 4.9 ends: "A copy from a source the verifier does not trust in that way is no reason to stop relying on one that is." That is the resolver's case.
- **Item 2: refuse the whole bundle when any event fails.** Simpler to say. But the time a resolver first saw a valid event is what protects a mind against a later rival event, and a resolver that discarded valid events because of what followed them in a copy would give that time away.
- **Item 3: keep every proof whose signature verifies.** Such a proof may be by any key at all, and costs its maker nothing. The harm is to clients, not to the resolver: each resolver alone stays within the 256 a record carries, and the two together need not.
- **Item 3: let a client keep only the proofs that count.** It should, and 7.1 could say so. But a client cannot rely on every other client doing it, and a resolver that serves no such proof needs nobody to.
- **Item 4: a counter in place of a clock.** A first-seen time is evidence because other evidence is compared with it. A counter compares with nothing outside the resolver.
- **Item 7: a mailbox that takes no `Forwarded` record.** 13.5 as it stood. A mind that is paused is reached at its mailboxes only (15.3), and a packet addressed to a query is accepted only inside the wrapper (12.4): the bare packet in a mailbox would be refused by the mind that drained it. So a paused mind could not be reached by a broker at all.
- **Item 8: a message of its own for "I have it".** Every message on the socket is a record already, and the `Ack` is the record that says a recipient has a packet. It is signed, so a host can tell it from anyone else's word, and the same `Ack` is what the mind would send the sender.
- **Item 8: remove a record once it is sent.** A connection can drop between the send and the receipt, and the record would be lost.
- **Item 10: the prefix without the slash.** `oasf:nlp/*` would then match `oasf:nlpx`, which no one means. That it does not match `oasf:nlp` itself follows from the same reading; a query that wants both lists the tag it wants, or the taxonomy's parent.
- **Item 11: ignore what cannot be weighed, and rank the rest.** A client that asked for twenty receipts would be given minds with none, in a result signed by the indexer, with nothing to tell it so.
- **Item 11: refuse the query.** Honest too. An empty result says the same and needs no new error.
- **Item 12: forward again what is sent again.** A sender that retries after a lost answer would reach every recipient twice, and anyone holding a signed packet could have it sent again for as long as it is valid.

## Backwards compatibility

No record format changes, and no test vector. A resolver built to the earlier text may differ in what it stores of a bundle that verifies in part, and in which proofs it serves. Items 1, 5 and 6 say what the earlier text left to the implementer. A host built to the earlier text refuses a `Forwarded` record at its inbox and its mailbox: item 7 is the one change here that such a host must make to receive brokered packets. Items 8 to 12 say what the earlier text left open; an indexer that returned results it had not checked against a query's `constraints` or `evidence` must stop.

## Security and privacy considerations

Item 3 closes a way to deny a mind to clients that ask two resolvers. Item 4 keeps a resolver from calling a mind duplicitous on the strength of its own clock's resolution. Item 2 means that a mind's own event which a resolver cannot judge, because it uses a critical extension the resolver does not implement, is not stored: that resolver then serves the log up to the event before it. See the open questions.

## Test vectors

None yet. Vectors for requests and responses over HTTP are planned with the conformance suite over the wire, in this milestone.

## Reference implementation

`LogArchive` of `@oip/server`, in `packages/server`: `intake.ts` (items 2 and 3) and `archive.ts` (items 1, 4 and 5). `@oip/resolver`, in `packages/resolver`: `app.ts` (items 1, 2, 5 and 6).

## Open questions

1. **A mind's own event that a resolver cannot judge.** The resolver serves the log up to the event before it, and a `Bundle` has no way to say that the resolver has been shown more. A client that takes the bundle as the whole log, known up to now, may count a key the event removed. A member such as `undecidedAfter`, naming the position, would let a client treat the log as it treats one with an undecided event (4.9). Anyone could then make a resolver say so of any mind, by sending it an event it cannot read, so the cure may be worse: a client that asks two resolvers, one of which implements the extension, is not misled.
2. **What a `401` carries.** RFC 9110 asks for `WWW-Authenticate` with a `401`, and RFC 9421 defines `Accept-Signature` for asking for a signature. 13.3 names neither.
3. **How a mind brings its host what the host serves.** 13.1 says what a host serves for a mind: its bundle, its feed, the records the feed lists. Nothing says how the mind hands them over, so a mind's software works only with the host it was written for. The reference host takes a signed `PUT` of the `Bundle`, a signed `PUT` of each record under its content ID, and a signed `POST` of feed entries as a `FeedPage` ([its README](../packages/host/README.md)). If that is to be common ground it belongs in Section 13.
4. **A mind that wants no brokered packets.** A profile has no way to say so, and a broker no duty to ask.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
