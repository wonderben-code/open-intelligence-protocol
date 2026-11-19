---
"@oip/resolver": minor
---

First version: the resolver of Layer 1, Section 17.

- `start`, and the command `oip-resolver`: the resolver as a service, set up from `OIP_RESOLVER_` variables. It listens, answers `/healthz`, `/readyz` and `/metrics`, and stops in order.
- `resolverApp`: `GET` and `PUT` on `/oip/v1/resolve/<mindId>`, `/oip/v1/duplicity/<mindId>`, and `/oip/v1/stream` as server-sent events, with a rate limit for each address and problem details for every error (core 10.2). A resolver may ask that publication is signed (17.3), and a mind can then publish its own log for the first time.
- `Resolver`: what verifies is kept with the time it was first seen, once, in tables that let no row be changed; at every position the event seen first is served, and a second valid event is kept as evidence (7.2, 7.3). It serves a mind's current location record and the profile it names.
- `judgeCopy`: of a published log, the events that verify and nothing after the first that does not; of an event's proofs, those that can count, checked against the verifier ([OEP-0005](../oeps/oep-0005-service-clarifications.md)).
