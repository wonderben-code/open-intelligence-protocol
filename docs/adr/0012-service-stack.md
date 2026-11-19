# ADR-0012: The service stack

**Status:** Accepted, 18 November 2026 (M5).

## Context

BUILD.md, Section 4, names libraries for the three services: Hono with `@hono/node-server`, `ws`, `better-sqlite3`, `pino`, OpenTelemetry and a Prometheus endpoint. It also says to check each choice when it is adopted, and to prefer few, audited dependencies.

The services are the first packages that do I/O, hold state between requests and face the network. A dependency here is in the path of hostile input, and its install script runs on every machine that builds a service.

## Decision

Three of the named libraries are not taken. Each is replaced by something smaller that the services need anyway.

| Concern      | BUILD.md                  | Taken                                                      | Dependencies added          |
| ------------ | ------------------------- | ---------------------------------------------------------- | --------------------------- |
| Storage      | `better-sqlite3`          | **`node:sqlite`**, the SQLite built into Node.js           | none                        |
| Logs         | `pino`                    | **a log of our own**, in `@oip/server`                     | none                        |
| Metrics      | a Prometheus endpoint     | **the text format written by hand**, in `@oip/server`      | none                        |
| HTTP routing | Hono, `@hono/node-server` | as BUILD.md: `hono` 4.13.18 and `@hono/node-server` 2.1.7  | two, with none of their own |
| WebSocket    | `ws`                      | as BUILD.md, when the host is built                        | one, with none of its own   |
| Traces       | OpenTelemetry             | `@opentelemetry/api` only, when the first service is built | one, with none of its own   |

### Storage: the SQLite that comes with Node.js

`better-sqlite3` is a native add-on. It is built or downloaded by a script when it is installed, from a place npm's provenance does not cover, once for each platform and each version of Node.js. Node.js 24 has SQLite built in: the same synchronous model, WAL, FTS5, a busy timeout and a defensive mode, with no dependency, no install script and no binary of anyone else's. Node.js 24.22 carries SQLite 3.53.4.

Against it: the Node.js documentation gives `node:sqlite` "Stability: 1.2 - Release candidate" (since 24.15), not "2 - Stable". Its interface may still change.

So:

- `node:sqlite` is named in one file, `packages/server/src/storage.ts`. A service's own store is written against the `Database` of that file, and answers its callers in the terms of the protocol.
- `engines` of `@oip/server` is `node >= 24.15`.
- If the built-in interface changes or is withdrawn, `better-sqlite3` goes behind the same file. The tests of that file run against whatever is there.
- SQLite's version is the one in the Node.js binary. A fix to SQLite reaches a deployment with an update of Node.js. The container image pins Node.js by digest.

A commit reaches the disk before it returns (`synchronous = FULL`). A resolver is a witness: a first-seen time it has served must still be the time it gives after a loss of power.

### Logs: what can be logged at all

CLAUDE.md says never to log a private key or any other secret. Redaction removes what someone thought to name. The rule taken here is about what a log line can hold:

- A line is an event's name and fields that are plain values. There is no way to log a record, a request, a header or any other object.
- An error is logged as its class, its code and where it was thrown. Its message is logged only if the error is one of ours, whose messages are built from constants. Some libraries put the value they choked on into a message.

With that rule the features `pino` is chosen for (serialisers, redaction by path, child bindings) have nothing to do. What is left is `JSON.stringify` and a write to the standard output, which on Linux is synchronous for a pipe and loses no line when the process ends. `pino` would add about ten packages to do it.

### Metrics: the text format by hand

A counter, a gauge and a histogram in the Prometheus text format are some hundred lines, with the one rule that matters built in: a metric holds a bounded number of series, so that a label a stranger chose cannot grow the service's memory. `prom-client` and the OpenTelemetry SDK with its exporter each bring more code than that for the same lines of text.

## Alternatives

- **`better-sqlite3`**: above. It is the fallback.
- **`pino`**: mature, and what BUILD.md names. Not taken because the rule above is the point, and the rule does not need it. A service whose log volume makes synchronous writes a cost can put `pino`'s writer behind the same `Log` interface.
- **Fastify, Express** in place of Hono: Hono has no dependencies, and its handlers take and return the `Request` and `Response` of the web platform, so a handler is a function a test calls.

## Consequences

- The three services add four packages to the lock file in all, none with dependencies of its own, and none with an install script.
- `@oip/server` holds code that libraries would have held: a logger, the metrics format, the rate limiter, the address rules of the fetcher. Each is small, has its own tests, and is in the mutation run.
- `hono` and `@hono/node-server` were added with the resolver, at the newest versions that the workspace's minimum release age of seven days allows. Both are MIT, with no dependency and no install script. `ws` was added with the host at 8.22.2: MIT, no dependency, no install script, and no advisory against that version in the OSV database on 19 November 2026. `maxPayload` is set to the most bytes of a record the host reads, and per-message compression is off (`packages/host/src/upgrade.ts`). 8.23.0 was released on 12 November 2026 together with releases of the 5, 6 and 7 lines, which is how a security fix is usually released; it was under the minimum release age when the host was built, and is to be taken as soon as it is seven days old.
