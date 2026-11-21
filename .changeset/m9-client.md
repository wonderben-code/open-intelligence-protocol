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
