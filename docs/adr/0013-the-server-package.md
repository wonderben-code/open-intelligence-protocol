# ADR-0013: A package the three services share

**Status:** Accepted, 18 November 2026 (M5).

## Context

BUILD.md 3.2 lists a host, a resolver and an indexer, and nothing between them and the protocol packages. BUILD.md 3.1 makes the three siblings: they do not import each other.

Each of them needs the same things before it does anything of its own: a configuration checked at start-up, a database with migrations, a limit on what it reads, rate limits, the one guarded way to fetch a URL a record named, problem details for its errors, a log that holds no secret, metrics, health and an orderly stop. BUILD.md 3.7 asks for some of these to exist once: "one guarded fetcher".

## Decision

A package, `@oip/server`, holds what the services share. It is a layer of its own in `scripts/layers.cjs`, above `@oip/client` and below the three services. It is not pure: it is where a service reads the clock, takes randomness, opens files and connects to the network, each through a small interface (`Clock`, `Randomness`, `Database`, `GuardedFetcher`) that a test replaces.

| Part                          | What it is                                                                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `edges`                       | The clock and randomness. The packages below read neither.                                                                                 |
| `config`                      | Settings read from the service's own variables. Everything wrong is said at once, and the service does not start. A secret is never shown. |
| `storage`                     | SQLite ([ADR-0012](0012-service-stack.md)): migrations recorded with a digest, transactions, tables that are append-only.                  |
| `http`                        | A body bounded before it is read, a record read by the reader of `@oip/core`, and errors as problem details (core 10.2).                   |
| `auth`                        | Who a request is from (Layer 1, 13.3): `verifyRequest` of `@oip/net`, for the service's own origin, with nonces kept in the database.      |
| `rate`                        | A burst and a steady rate for each client, on the caller's clock.                                                                          |
| `ip`, `fetcher`               | Which addresses are public, and the fetcher that connects only to an address it has checked (BUILD.md 3.7).                                |
| `log`, `metrics`, `lifecycle` | One line of JSON for each event, the Prometheus text format, `/healthz`, `/readyz` and an orderly stop.                                    |

Rules it keeps:

- **A failure that will pass is a 503, never a verdict.** A check that was cut short ([ADR-0010](0010-checks-cut-short.md)) and a database another writer holds both say nothing of the request. The client asks again.
- **A failure nobody expected says nothing of itself to the client.** The answer is a 500 with no detail. The service logs it, under the rule of ADR-0012.
- **What is recorded as evidence is not rewritten.** A table of first-seen times is made append-only by triggers, and replacing a row counts as removing it.
- **The service's own origin comes from its configuration**, not from a request. A signature covers the URI clients address the service by.

## Consequences

- `docs/conformance/plan.json` lists `server` under M5, so that a clause of Layer 1, 13, 17 or 18 counts as tested by a test here.
- The package is in the mutation run. Its parts that judge a request or guard what a service connects to (`auth`, `http`, `ip`, `fetcher`) are held to the coverage threshold of the verification packages, 95% for each file. The rest is at the general threshold.
- A fourth service, or a gateway, starts from this package and not from a copy of one of the three.
