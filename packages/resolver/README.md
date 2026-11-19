# @oip/resolver

The resolver of the Open Intelligence Protocol (Layer 1, Section 17). It takes in the identity logs that are published to it, keeps what verifies with the time it first saw it, and serves that. It is a witness: clients that trust it use those times as evidence (core 9.4), and it keeps and publishes any second valid event it is shown for a position of a log (Layer 1, 7.2).

It is built on [`@oip/server`](../server/README.md), whose `LogArchive` is what it keeps and judges with. It runs on Node.js 24.15 or later.

## Run it

```
OIP_RESOLVER_ORIGIN=https://resolver.example OIP_RESOLVER_DATABASE=/data/resolver.db oip-resolver
```

Every setting is a variable that starts with `OIP_RESOLVER_`. A resolver that is misconfigured says everything that is wrong and does not start.

| Variable                              | Default              | What it is                                                                                      |
| ------------------------------------- | -------------------- | ----------------------------------------------------------------------------------------------- |
| `ORIGIN`                              | none: it must be set | The origin clients reach the resolver at. A signed request names it                             |
| `HOST`, `PORT`                        | `0.0.0.0`, `8080`    | Where it listens                                                                                |
| `DATABASE`                            | `./resolver.db`      | Its database file                                                                               |
| `AUTHENTICATED_PUBLICATION`           | `false`              | Whether a bundle may be published only by a request a mind has signed (17.3)                    |
| `MAX_BUNDLE_BYTES`                    | `8388608`            | The most bytes of a published bundle that are read                                              |
| `READ_BURST`, `READ_PER_MINUTE`       | `120`, `600`         | What one address may read                                                                       |
| `PUBLISH_BURST`, `PUBLISH_PER_MINUTE` | `20`, `60`           | What one address may publish                                                                    |
| `MAX_STREAMS`                         | `256`                | The most streams open at once                                                                   |
| `TRUSTED_PROXIES`                     | `0`                  | How many proxies stand in front, each adding the address it was asked from to `X-Forwarded-For` |
| `UNDERSTOOD`                          | none                 | The extension namespaces it implements (core 8.3), separated by commas                          |
| `LOG_LEVEL`                           | `info`               | `debug`, `info`, `warn` or `error`                                                              |
| `SHUTDOWN_GRACE_MS`                   | `10000`              | How long it may take to stop                                                                    |

It stops in order on `SIGTERM` or `SIGINT`: its streams end, what is in flight is answered, and the database is closed last.

## What it serves

| Request                               | Answer                                                                                                                                                                                                           |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /oip/v1/resolve/<mindId>`        | The mind's `Bundle`: its log as the resolver verifies it, its current location record, and `firstSeen`. `404` if it holds no log of the mind                                                                     |
| `PUT /oip/v1/resolve/<mindId>`        | `202` with `{ "added": n }`. `409` `duplicity` if the log holds another valid event at a position than the one seen first. A problem if an event does not verify: what verified before it is merged all the same |
| `GET /oip/v1/duplicity/<mindId>`      | `DuplicityEvidence`: the pairs of conflicting valid events it has seen                                                                                                                                           |
| `GET /oip/v1/stream?since=<cursor>`   | Server-sent events, one for each identity event and location record it takes in. `Last-Event-ID` may stand for `since`                                                                                           |
| `GET /healthz`, `/readyz`, `/metrics` | Whether it runs, whether it can do its work, and its counts in the Prometheus text format                                                                                                                        |

`<mindId>` is the content ID of the mind's genesis: its address without `did:oip:`. Errors are RFC 9457 problem details with the types of core 10.2.

## Use it as a library

```ts
import { formatTimestamp, MEDIA_TYPE, mindId } from "@oip/core";
import {
  type Clock,
  Database,
  Log,
  LogArchive,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";

import { RESOLVER_MIGRATIONS, resolverApp } from "@oip/resolver";

/**
 * A resolver in memory, asked as a client would ask one over HTTP: a log is
 * published, then another event for the same position of it, and the
 * resolver says what it holds.
 *
 * @param logs - Two logs of one mind that part at their second event, as arrays of events.
 */
export async function example(
  mind: string,
  logs: readonly [readonly unknown[], readonly unknown[]],
  clock: Clock & { at: bigint },
): Promise<string[]> {
  const db = Database.open({ path: ":memory:" }, RESOLVER_MIGRATIONS, clock);
  const log = new Log({ service: "resolver", clock, sink: () => undefined });
  const limiter = (): RateLimiter => new RateLimiter({ burst: 100, perMinute: 600 }, clock);
  const app = resolverApp({
    resolver: new LogArchive({ db, clock }),
    clock,
    log,
    metrics: new Metrics(),
    origin: "https://resolver.example",
    nonces: new StoredNonces(db),
    authenticatedPublication: false,
    limits: { read: limiter(), publish: limiter() },
    shutdown: new Shutdown({ log }),
    ready: {},
  });
  const path = `/oip/v1/resolve/${mindId(mind) ?? ""}`;
  const ask = (at: string, init?: RequestInit): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`https://resolver.example${at}`, init), {}));
  const lines: string[] = [];
  for (const events of logs) {
    const response = await ask(path, {
      method: "PUT",
      headers: { "content-type": MEDIA_TYPE },
      body: JSON.stringify({ oip: "1", type: "Bundle", mind, log: events }),
    });
    const answer = (await response.json()) as { added?: number; type?: string };
    lines.push(
      `published at ${formatTimestamp(clock.now())}: ${response.status} ${answer.type ?? `added ${answer.added ?? 0}`}`,
    );
    // An hour passes between the two.
    clock.at += 3_600_000_000_000n;
  }
  const bundle = (await (await ask(path)).json()) as {
    log: unknown[];
    firstSeen: Record<string, string>;
  };
  lines.push(
    `serves ${bundle.log.length} events, the second of them the one it saw first: ${String(
      JSON.stringify(bundle.log[1]) === JSON.stringify(logs[0][1]),
    )}`,
    `first seen: ${Object.values(bundle.firstSeen).join(", ")}`,
  );
  const evidence = (await (await ask(path.replace("/resolve/", "/duplicity/"))).json()) as {
    pairs: unknown[];
  };
  lines.push(`pairs of conflicting events held as evidence: ${evidence.pairs.length}`);
  db.close();
  return lines;
}
```

With two logs of one mind that part at their second event, and a clock that starts at noon on 18 November 2026, `example` gives:

```
published at 2026-11-18T12:00:00Z: 202 added 2
published at 2026-11-18T13:00:00Z: 409 urn:oip:error:duplicity
serves 2 events, the second of them the one it saw first: true
first seen: 2026-11-18T12:00:00Z, 2026-11-18T12:00:00Z
pairs of conflicting events held as evidence: 1
```

## What it exports

| Export                                                                        | What it is                                                                                                  |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `start`, `Running`, `Edges`, `SETTINGS`, `PREFIX`, `clientAddress`, `Arrived` | The resolver as a running service, its settings, and how it tells where a request came from                 |
| `resolverApp`, `ResolverAppOptions`, `Arrival`                                | Its HTTP interface, as a function from a request to a response                                              |
| `RESOLVER_MIGRATIONS`                                                         | Its database: an archive of identity logs (`LogArchive` of `@oip/server`) and the nonces of signed requests |

## What to know

- **It stores only what verifies** (17.2; [OEP-0005](../../oeps/oep-0005-service-clarifications.md)). Of a published log it takes the events that verify, from the genesis on, and nothing after the first that does not. Whoever published is no source it trusts to serve a whole log (4.9). The request is answered with why that event was not taken: `invalid-proof`, `unsupported-critical`, or `stale-version` where the resolver lacks what would judge it. Publish the logs of a collective's members before the collective's.
- **It keeps the proofs that can count, and no others.** A proof whose signature verifies, by a control key the event reveals or an invocation key of a member at the version named. Anyone can put a proof on a copy of anyone's event, and a client shown more for one event than a record carries treats the log as not verified (7.1). The reading of which proofs can count is checked against the verifier of `@oip/identity`: if a log verifies less far with only those, every proof whose signature verifies is kept.
- **A first-seen time is recorded once, and never rewritten.** It is written in the same transaction as the event, in a table that lets no row be changed. No two events of one mind are first seen at the same time: where the clock has not moved, the later is a nanosecond after.
- **At every position it serves the event it saw first** (7.3), never the longer branch or the later copy. A second valid event for a position is kept beside it and served as evidence.
- **What it holds in memory is what the database holds.** It is rebuilt from the database when the resolver starts, which reads every log it holds, and whenever a write fails after the memory has moved.
- **A location record ends with the key that signed it** (15.2). The bundle carries the one with the highest `seq` among those that still count when it is asked for.
- **Not yet here.** Records are kept for as long as the database is: nothing prunes old location records. A resolver does not yet fetch a mind's homes or follow other resolvers' streams.

## Tests

- What it keeps and how it judges is tested in `@oip/server`: copies crowded with proofs that sign nothing, restarts, two valid events for one position, a clock that does not move and one that goes back, a table that goes missing in the middle of a write.
- The HTTP interface is tested as a function, and the running service over a socket on the machine.
