---
oep: 4
title: Mind Network clarifications found while building the reference implementation
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Layer 1 # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: 2026-11-18
requires: [1, 2, 3]
replaces: []
discussion: # the pull request of milestone M4
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0004: Mind Network clarifications found while building the reference implementation

## Summary

Writing `@oip/net`, the package of the reference implementation for feeds, packets, sessions, locations and profiles, showed places where Layer 1, Sections 10 and 12 to 16 (revision 2026-11-17, with OEP-0001 to OEP-0003) allow two readings or set no rule. This proposal settles each. All but one choose the reading the implementation takes and say it in the text. One changes a record format: an `Ack` may list the digests of the proofs it acknowledges.

The milestone is not finished. Items are added as its parts are built, and the list is final when the milestone is.

## Motivation

A receiver decides, packet by packet, what it will act on. Two receivers that hold the same packets and the same evidence must come to the same answer, and each item below is a case where they might not, or where the text promised more than its rules gave.

1. **What is left of a feed that equivocates?** 10.3 says two valid entries at one `seq` are equivocation and that the two are evidence. It does not say how much of the feed a verifier still relies on.
2. **May the first entry of a feed name a `prev`?** The schema allows `prev` at `seq` 0. Nothing says what it would name.
3. **Who signs a collective's feed, location record, profile or packet?** 10.1, 12.1, 13.2 and 15.2 ask for "a valid operational key" of the author. A collective may have no key of its own and sign by its threshold (9.5).
4. **One entry in several copies.** An entry's proofs may reach a verifier in two copies. 7.1 says of identity events that they are judged with the proofs of every copy. Nothing said it of entries.
5. **Which proofs does an `Ack` acknowledge?** core 9.4, item 4 makes an `Ack` evidence for the proofs a packet carries, and says evidence is keyed by a proof's digest. An `Ack` names the packet by its content ID. That covers the proofs of the records in its `content`, and not the packet's own proof: a proof added to the packet later has the same content ID. 13.2 nevertheless called the `Ack` evidence "that the packet, with the sender's proof, existed".
6. **A `Forwarded` record around a packet addressed by a list.** 12.4 asks for a `Forwarded` record only for a packet addressed to a query. It did not say what a receiver makes of one that carries a packet addressed by a list.
7. **A query packet that lives longer than an hour.** 12.1 limits its `expires` to one hour after `created`. 12.4 lists what a receiver rejects and named only the seven days.
8. **The duplicate-detection window.** 12.4 rejects a session packet "older than the receiver's duplicate-detection window". Nothing gave the window a value or said whose it is.
9. **Which packet carries the `Session` record?** 14.2 said "the first packet each participant sends". A participant with two instances has two chains, each with a first packet. And nothing said whether a receiver that holds the record must reject a first packet without it.
10. **May a session packet be addressed beyond the participants?** 14.3 requires `to` to list every other participant. It did not say whether it may list anyone else.
11. **What is a valid packet of a chain?** 14.3 called "two valid packets with the same values and different content IDs" equivocation. If valid means only "signed", then what a receiver concludes depends on the order in which packets arrive, which a network attacker can choose.
12. **The first packet of a chain with a `prev`.** As item 2.
13. **Is the packet that carries a `Resume` in a chain?** 14.4 did not say. And "the receiver verifies the chains" did not say what a receiver does with a `Resume` that names a packet it never sent.
14. **Sealing to a key of small order.** RFC 9180, 7.1.4 requires a sender to refuse a recipient key with which the shared secret is all zero. 12.6 did not say what a sender then does, and nothing stops a mind from listing such a key.
15. **What a `Sealed` record opens to.** 12.6 says the plaintext is "the canonical form of the signed packet". It did not say what a recipient does with a record that opens to another writing of a packet, or to another record.

## Specification

Each item is in the specification as of this proposal, and the [CHANGELOG](../spec/CHANGELOG.md) lists them.

1. **10.3.** "A verifier treats the feed as verified up to the entry before the two, and no further: nothing in the entries tells which of them the author stands by."
2. **10.1.** "An entry at `seq` 0 has no `prev`: one that has is not valid."
3. **6.1.** "Where a clause of this specification asks that a record be signed by a valid operational key of a mind (a feed entry, a checkpoint, a location record, a profile, a packet, an acknowledgement, a `Forwarded` record), a record signed by a collective under Section 9.5 meets it for that collective. A `Hello` is the exception (9.5)."
4. **10.1.** "The same entry with other proofs is one entry (core 3.1), and a verifier judges it with the proofs of every copy it holds."
5. **13.2 and core 9.4, item 4.** An `Ack` MAY carry `proofs`, an array of at most 256 digests (10.1) of the proofs the packet carried on itself when it was received, and recipients SHOULD list them. An `Ack` is evidence, at its `received` time, for the proofs on the records in the packet's `content` and for the packet's own proofs that `proofs` lists, and for no other proof.
6. **12.4.** "A packet whose `to` lists addresses is judged by its own proof however it arrived: a `Forwarded` record around it adds nothing to it and takes nothing away."
7. **12.4.** A receiver rejects a packet whose `expires` is more than one hour after `created` when `to` is a query.
8. **12.4.** "The duplicate-detection window is the receiver's to choose, and SHOULD be at least one hour."
9. **14.2.** "The first packet of each sending chain" carries the `Session` record. "A receiver that does not hold the `Session` record MUST reject a session packet that does not carry it. A receiver that holds it MAY accept a first packet without it."
10. **14.3.** "`to` MAY also list minds that are not participants."
11. **14.3.** "A packet is a link of its chain if it has `seq` 0 and no `prev`, or if its `prev` is the link at the `seq` before its own; a session packet that is no link has no place in its chain, and receivers MUST reject it. Receivers deduplicate links by (`session`, `from`, `instance`, `seq`); two links with the same values and different content IDs are equivocation, treated as in Section 10.3."
12. Covered by item 11.
13. **14.4.** "A `Resume` that names, for a chain of the receiver's own, a packet that the chain does not have at that `seq` is invalid. The packet that carries a `Resume` is a packet of the session like any other, with its place in its sender's chain."
14. **12.6.** "A sender MUST NOT seal to an agreement key that is a point of small order, with which every sender would share the same secret (RFC 9180, Section 7.1.4): it uses another of the recipient's agreement keys, and if there is none the packet cannot be sealed."
15. **12.6.** "It MUST reject a record that opens to anything but the canonical form of a `Packet`: one writing for one packet, and no other record."

## Rationale and alternatives

- **Item 5.** The alternative is to leave the format alone and say that an `Ack` is evidence only for what the content ID covers. Then nothing is evidence for the packet's own proof but a witness or an anchored feed, and 13.2's "evidence that the packet, with the sender's proof, existed" would be untrue. A sender whose key is later compromised needs that evidence most.
- **Item 14.** An agreement key of small order could instead make the identity event that lists it invalid. That is a change to what a log is, for a fault that harms only the mind that lists the key, and a sender can check it for itself.
- **Item 11.** The feed has this rule already (10.2, 10.4): an entry counts only where it stands. With it, two receivers that hold the same packets come to the same chain, whatever order the packets came in.

## Backwards compatibility

Item 5 adds an optional member to `Ack`. An `Ack` without it is as valid as before, and is evidence for less than 13.2 said.

Items 7 and 11 make a receiver reject packets that the text did not clearly reject. No conforming sender makes them.

## Security and privacy considerations

Item 5 closes a gap between core 9.4, which keys evidence by a proof's digest, and 13.2, which had no digest to key by.

Item 11 removes a way in which the order of arrival, which a network attacker may control, decides what a receiver concludes about a sender.

## Test vectors

To come with the part of the milestone that gives the Python checker its verdicts on feeds, packets and sessions. Until then the rules above are held by the unit tests of `@oip/net`, each of which cites its clause.

## Reference implementation

`@oip/net` in `packages/net`, and the Python checker `spec/test-vectors/oip_vectors.py`.

## Open questions

- **A `Hello`'s own date.** 13.3 bounds the age of the challenge, which bounds when a `Hello` can have been made. The `created` of the record and of its proof are not otherwise read.
- **A recipient that is no participant (item 10)** receives the packets it is listed in and can miss others. The reference implementation's `Sessions` follows only the sessions its own mind is a participant of.
- **`expires` earlier than `created`** is nowhere forbidden for a packet. A receiver rejects such a packet as soon as its `expires` is 300 seconds past.
- **How an anchor's attestation is carried** (10.6) is still unspecified, so no checkpoint is yet evidence of time.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
