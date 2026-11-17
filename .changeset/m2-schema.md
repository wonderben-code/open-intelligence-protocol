---
"@oip/schema": minor
---

An HTTPS origin is defined by its characters (Layer 1, 3.13; OEP-0002): `https://` and then ASCII letters, digits and `.`, `-`, `:`, `[`, `]` only. The pattern `httpsOrigin` allowed any character but `/`, `?`, `#`, `@` and white space, which is not one set in every regular-expression engine. A home with a character outside ASCII, or with `_`, `%` or the like, is no longer well formed.
