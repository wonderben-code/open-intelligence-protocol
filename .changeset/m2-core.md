---
"@oip/core": patch
---

`canonicalSizeUpTo` is exported: the size of a value's canonical form, counted without writing it out. `@oip/identity` measures with it what it holds of an event (Layer 1, 7.1).

`canonicalize`, `canonicalBytes` and `contentId` throw `UnfitProcess` (from `@oip/schema`; an `Error`, as before) in a process where other code has put a `toJSON` on every object. Every function that answers for a failure notes one that says nothing of the value judged, with `noteCutShort` ([ADR-0010](../docs/adr/0010-checks-cut-short.md)). `parseJson`, `parseJsonBytes`, `parseRecord`, `parseExtensionRecord`, `verifyProof` and `verifyProofs` then refuse with the clause `implementation limit`. `verifyEd25519` notes it too when the library's own `catch` took the failure: after a `false` it repeats the three steps the library guards, and notes what they throw for want of room.
