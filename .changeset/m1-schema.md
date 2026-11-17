---
"@oip/schema": minor
---

- `validateJson` and the type `JsonValue`: the check every validator applies first, on its own. It says whether a value is plain JSON within the profile of core Section 1.
- An array must be a plain array: one with another prototype, or with a member besides its elements, is rejected. A serialiser would call a `toJSON` found on it.
- The nesting limit of 64 is now the specification's (core 1.9), and issues cite it.
- `validateExtensionRecord` requires `critical`: a record of a type an extension defines lists that extension (core 7).
- An error under `ext`, `critical` or `proof` cites the clause of that member, and a bad `type` in a proof cites core 5.2.
- Messages about values no longer begin "the record contains", because the same check is used for proofs and other values.
