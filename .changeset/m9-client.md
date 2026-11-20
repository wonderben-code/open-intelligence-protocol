---
"@oip/client": minor
---

What a gateway needs, and what anyone needs to know of a mind a gateway made (Layer 0, Section 1).

- `NewMind.ext` and `ProfileFields.ext`: extension blocks in a new mind's `Genesis` and in a profile. A gateway names itself there for a mind it bridges (Layer 0, 1.2).
- `Lookup.assurance(mind)` says whether a mind is `native`, `bridged` by a gateway whose own feed attests it, or only `claimed` to be (1.3), with the gateway, protocol and endpoint the mind names.
- A gateway attests a mind with `publishRecord` of the mind's `Genesis`: the entry of its feed is the attestation.
