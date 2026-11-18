---
"@oip/schema": minor
---

An HTTPS origin is defined by its characters (Layer 1, 3.13; OEP-0002): `https://` and then ASCII letters, digits and `.`, `-`, `:`, `[`, `]` only. The pattern `httpsOrigin` allowed any character but `/`, `?`, `#`, `@` and white space, which is not one set in every regular-expression engine. A home with a character outside ASCII, or with `_`, `%` or the like, is no longer well formed.

An entry of `revoked` and an entry of `parents` have no other members, and an event revokes at most 80 keys (Layer 1, 3.6, 3.7; OEP-0002). A misspelt `compromisedSince` was accepted and ignored, and `revoked` had no limit.

`validateWithoutProof`: a value checked as plain data apart from its member `proof`, which is not read. It is what a content ID covers (core 3.1), and `@oip/identity` tells with it which event a value is a copy of when its proofs are not plain data (Layer 1, 7.1).

`noteCutShort`, `cutShortCount`, `judging`, `finding`, `cutShort`, `CUT_SHORT` and `UnfitProcess`: how a check that could not be made is told from a verdict ([ADR-0010](../docs/adr/0010-checks-cut-short.md)). A `catch` that answers for a failure notes it. A failure counts when it is the engine's report of a spent call stack, told by its exact message, or `UnfitProcess`; no other error counts, so a value that is simply wrong is still refused for its own fault. `noteCutShort` never throws. `judging` and `finding` run a check and answer with the refusal `implementation limit` (or `undefined`) when the count moved; whatever keeps an answer uses them, or compares the count before and after. `validateJson`, `validateRecord` and `parseSelector` note what they catch, and `validateJson` and `validateRecord` refuse with `implementation limit` when they were cut short.
