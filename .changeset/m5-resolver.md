---
"@oip/resolver": minor
---

First version: the resolver of Layer 1, Section 17.

- `start`, and the command `oip-resolver`: the resolver as a service, set up from `OIP_RESOLVER_` variables. It listens, answers `/healthz`, `/readyz` and `/metrics`, and stops in order.
- `resolverApp`: `GET` and `PUT` on `/oip/v1/resolve/<mindId>`, `/oip/v1/duplicity/<mindId>`, and `/oip/v1/stream` as server-sent events, with a rate limit for each address and problem details for every error (core 10.2). A resolver may ask that publication is signed (17.3), and a mind can then publish its own log for the first time.
- What it keeps and how it judges is the `LogArchive` of `@oip/server`: only what verifies, with the time it was first seen ([OEP-0005](../oeps/oep-0005-service-clarifications.md)).
- The setting `ED25519`: `native`, the default, has OpenSSL do the arithmetic of each signature; `portable` leaves it to the library. The service says in its log if OpenSSL was asked for and could not be used.
