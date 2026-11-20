---
"@oip/conformance": minor
---

The Resolver, Host and Indexer profiles, run against any implementation over the wire.

- `resolverProfile`, `hostProfile`, `indexerProfile`, and `runWire` for a profile by its name: each asks an implementation as its clients do, over HTTP, server-sent events and WebSocket, and gives a `WireReport`. The suite makes minds of its own for each run, with fresh keys.
- A `WireReport` is JSON. Each `WireCheck` cites its clauses, has a level (`MUST` or `SHOULD`) and ends as `pass`, `fail`, `not-applicable` or `skipped`, with what was required and what happened. `conforms` is true only if every `MUST` check passed or did not apply.
- The command `oip-conformance <profile> <url>`, with `--origin`, `--timeout` and `--json`. It ends with 0 only if the implementation conforms. `formatReport` writes a report for a person.
- `HostSetup` and `referenceHostSetup`: how the suite has a host take a mind on and brings it a feed, which the specification leaves to the host. `WatchedInbox`: an inbox the suite can read, for what an indexer forwards.
- `WireMind`, `WireClient`: a mind of the suite, and how the suite asks.
