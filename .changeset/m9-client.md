---
"@oip/client": minor
---

What a gateway needs, and what anyone needs to know of a mind a gateway made (Layer 0, Section 1).

- `NewMind.ext` and `ProfileFields.ext`: extension blocks in a new mind's `Genesis` and in a profile. A gateway names itself there for a mind it bridges (Layer 0, 1.2).
- `Lookup.assurance(mind)` says whether a mind is `native`, `bridged` by a gateway whose own feed attests it, or only `claimed` to be (1.3), with the gateway, protocol and endpoint the mind names.
- A gateway attests a mind with `publishRecord` of the mind's `Genesis`: the entry of its feed is the attestation.
- `publishRecord` of the record whose entry waited after a failed call returns that entry, and signs no second one for the record. A caller that asks again after a failure lists the record once.
- `Mind.pass(packet, to)` brings a packet that another mind signed to one of the minds it is for, sealed, as a courier does. A gateway that was handed a packet over another protocol passes it on with this (Layer 0, 3.3).
- A packet sent for another mind is taken as sent for it on a clock that moves. The delegations a packet's proof carries are first seen when the packet is, at one reading of the clock. They were recorded a reading later, so that each looked signed after the proof that used it (Layer 1, 11.4, item 1), and `Received.sentFor` was never set outside a test with a clock that stands still.
- `Lookup.record` records its first sight of the delegations a fetched record's proofs carry at the reading of the clock at which it records the proofs. A Commitment read from a feed, signed by an agent for its firm, now counts for the firm on a clock that moves.
- `Mind.receive({ keep })` calls `keep` with the packets it accepted before it notes that it has them. A program that must not lose a packet writes each down there: a mailbox gives a packet once.
- `Mind.holdRevocations(record)` reads the feeds of the authors of the delegations a record rests on, and holds the Revocations it finds (Layer 1, 11.5). `Mind.delegationsStand(record)` says whether those delegations stand now. `Mind.sentFor(packet)` says for which mind a packet was sent. A proof is judged as of when it was made, which is right for what a record binds its principal to. A program that is about to act for a delegate asks these first. `holdRevocations` fetches the author's own copy of a Revocation unless the copy this mind holds counts for its author: a copy under a signature that is nobody's does not keep the author's word unread. `delegationsStand` takes a delegation that is named and not held, a reference that is none, and a delegation with no end that can be read, as not standing.
- The records a packet carries are held at one reading of the clock. A delegation that a packet carries by reference counted only if its part came first.
- `Lookup.assurance` reads the gateway's feed page by page until it has the entry a profile names, and reads the block of the mind's `Genesis` as well as the profile's (OEP-0006, items 3 and 8).
