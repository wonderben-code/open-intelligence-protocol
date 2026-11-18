---
"@oip/server": minor
---

First version: what the host, the resolver and the indexer share ([ADR-0013](../docs/adr/0013-the-server-package.md)).

- `Clock`, `Randomness`: the present and random bytes, behind interfaces. The packages below read neither.
- `readConfig` and the settings `integer`, `flag`, `text`, `origin`, `list`: a service's configuration from its own environment variables. Everything wrong is said at once, and the service does not start. A secret is never shown.
- `Database`: SQLite as Node.js has it built in ([ADR-0012](../docs/adr/0012-service-stack.md)), in WAL mode, with a commit on the disk before it returns; migrations recorded with a digest; `appendOnly` for tables whose rows are never changed or removed.
- `readBody`, `readRecord`, `responseFor`: a body bounded before it is read, a record read by the reader of `@oip/core`, and failures as problem details (core 10.2). A check that was cut short is a 503.
- `authenticate`, `StoredNonces`: who a request is from (Layer 1, 13.3), for the service's configured origin, with nonces that outlast the process.
- `RateLimiter`, `addressKey`: a burst and a steady rate for each client.
- `GuardedFetcher`, `isPublicAddress`: HTTPS only, public addresses only, a connection made to an address that was checked, limits of size and time, and redirects to the same origin only (BUILD.md 3.7).
- `Log`: one line of JSON for each event, with plain values only; the message of an error that is not ours is withheld.
- `Metrics`: counters, gauges and histograms in the Prometheus text format, with a bound on the series of each.
- `Shutdown`, `healthResponse`, `readyResponse`: an orderly stop, `/healthz` and `/readyz`.
