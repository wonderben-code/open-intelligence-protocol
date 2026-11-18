---
"@oip/core": patch
---

`canonicalSizeUpTo` is exported: the size of a value's canonical form, counted without writing it out. `@oip/identity` measures with it what it holds of an event (Layer 1, 7.1).

`canonicalize`, `canonicalBytes` and `contentId` throw `UnfitProcess` (from `@oip/schema`; an `Error`, as before) in a process where other code has put a `toJSON` on every object. Every function that answers for a failure notes one that says nothing of the value judged, with `noteCutShort`.
