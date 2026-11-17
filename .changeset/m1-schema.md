---
"@oip/schema": minor
---

- `validateJson` and the type `JsonValue`: the check every validator applies first, on its own. It says whether a value is plain JSON within the profile of core Section 1.
- An array must be a plain array: one with another prototype, or with a member besides its elements, is rejected. A serialiser would call a `toJSON` found on it.
- The nesting limit of 64 is now the specification's (core 1.9), and issues cite it.
- `validateExtensionRecord` requires `critical`: a record of a type an extension defines lists that extension (core 7).
- An error under `ext`, `critical` or `proof` cites the clause of that member, and a bad `type` in a proof cites core 5.2.
- Messages about values no longer begin "the record contains", because the same check is used for proofs and other values.
- Every validator now validates, and returns, a plain copy of what it was given, built from property descriptors. Use the copy: no accessor is called, and an object that answers differently each time it is read is seen once.
- Containers (`Bundle`, `LogPage`, `FeedPage`, `DuplicityEvidence`) are limited part by part: the depth limit applies to each record a container carries, counted from that record, and to the container without them. `containerParts` and `MAX_CONTAINER_DEPTH` are exported for it.
- A string or member name with a noncharacter is rejected (core 1.1; RFC 7493, 2.1). `textFault` is exported.
- A duration is at most 64 characters (core 1.5).
- A path in an issue is safe to log: control characters are escaped and a long path is cut.
- `MAX_VALUES`, the most values read in one record, is exported, and exceeding it is reported as an implementation limit.
