---
"@oip/server": minor
---

First version: what the host, the resolver and the indexer share ([ADR-0013](../docs/adr/0013-the-server-package.md)).

- `Clock`, `Randomness`: the present and random bytes, behind interfaces. The packages below read neither.
- `readConfig` and the settings `integer`, `flag`, `text`, `origin`, `list`: a service's configuration from its own environment variables. Everything wrong is said at once, and the service does not start. A secret is never shown.
- `Database`: SQLite as Node.js has it built in ([ADR-0012](../docs/adr/0012-service-stack.md)), in WAL mode, with a commit on the disk before it returns; migrations recorded with a digest; `appendOnly` for tables whose rows are never changed or removed.
- `readBody`, `readRecord`, `responseFor`: a body bounded before it is read, a record read by the reader of `@oip/core`, and failures as problem details (core 10.2). A check that was cut short is a 503.
- `authenticate`, `StoredNonces`: who a request is from (Layer 1, 13.3), for the service's configured origin, with nonces that outlast the process.
- `LogArchive`, `judgeCopy`: an archive of identity logs. Of a published log it takes the events that verify and nothing after the first that does not; of an event's proofs, those that can count, checked against the verifier ([OEP-0005](../oeps/oep-0005-service-clarifications.md)). What verifies is kept with the time it was first seen, once, in tables that let no row be changed. At every position the event seen first is given back, and a second valid event is kept as evidence (Layer 1, 7.2, 7.3). It keeps a mind's current location record and the profile it names. `publicationProblem` gives the problem for a bundle that was not wholly taken.
- `RateLimiter`, `addressKey`: a burst and a steady rate for each client.
- `gate`, `clientAddress`: the gate every request passes (the limit for its address, the metrics, and the one place where what was thrown becomes an answer), and the address a request came from behind trusted proxies.
- `GuardedFetcher`, `isPublicAddress`: HTTPS only, public addresses only, a connection made to an address that was checked, limits of size and time, and redirects to the same origin only (BUILD.md 3.7).
- `Log`: one line of JSON for each event, with plain values only; the message of an error that is not ours is withheld.
- `Metrics`: counters, gauges and histograms in the Prometheus text format, with a bound on the series of each.
- `Shutdown`, `healthResponse`, `readyResponse`: an orderly stop, `/healthz` and `/readyz`.
