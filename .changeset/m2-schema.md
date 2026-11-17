---
"@oip/schema": minor
---

An HTTPS origin is defined by its characters (Layer 1, 3.13; OEP-0002): `https://` and then ASCII letters, digits and `.`, `-`, `:`, `[`, `]` only. The pattern `httpsOrigin` allowed any character but `/`, `?`, `#`, `@` and white space, which is not one set in every regular-expression engine. A home with a character outside ASCII, or with `_`, `%` or the like, is no longer well formed.

An entry of `revoked` and an entry of `parents` have no other members, and an event revokes at most 80 keys (Layer 1, 3.6, 3.7; OEP-0002). A misspelt `compromisedSince` was accepted and ignored, and `revoked` had no limit.
