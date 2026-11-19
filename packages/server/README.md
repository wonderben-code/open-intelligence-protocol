# @oip/server

What the Open Intelligence Protocol services share: the host, the resolver and the indexer ([ADR-0013](../../docs/adr/0013-the-server-package.md)). It is where a service reads its configuration and its clock, keeps its database, bounds what it reads, fetches what a record names, answers with problem details, logs, counts and stops.

It runs on Node.js 24.15 or later, and uses the SQLite built into it ([ADR-0012](../../docs/adr/0012-service-stack.md)). It is not one of the pure packages: the packages below it take the time and the evidence as parameters, and this is where a service gets them.

## Use

```ts
import { contentId, formatTimestamp, MEDIA_TYPE, OipError } from "@oip/core";
import {
  appendOnly,
  type Clock,
  Database,
  integer,
  RateLimiter,
  readConfig,
  readRecord,
  recordResponse,
  responseFor,
} from "@oip/server";

const SETTINGS = {
  BURST: integer("how many requests one client may send at once", {
    min: 1,
    max: 100,
    fallback: 3,
  }),
  MAX_BYTES: integer("the most bytes of a record that are read", { min: 1, max: 8_388_608 }),
};

/**
 * An endpoint that takes a record and says when it first saw it. It is not
 * a service of the protocol: it shows what `@oip/server` gives one.
 */
export function endpoint(environment: Record<string, string | undefined>, clock: Clock) {
  // Everything wrong with the configuration is said here, and nothing starts.
  const config = readConfig("OIP_EXAMPLE_", SETTINGS, environment);
  const db = Database.open(
    { path: ":memory:" },
    [
      {
        version: 1,
        name: "first sight",
        sql: `CREATE TABLE seen (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT;\n${appendOnly("seen")}`,
      },
    ],
    clock,
  );
  const limiter = new RateLimiter({ burst: config.BURST, perMinute: 60 }, clock);

  return async (request: Request, client: string): Promise<Response> => {
    try {
      const allowed = limiter.take(client);
      if (!allowed.ok) throw new OipError("rate-limited", "too many requests: ask again later");
      // Bounded before it is read, and read by the reader of the JSON profile.
      const id = contentId(await readRecord(request, config.MAX_BYTES));
      const seen = db.transaction(() => {
        // Recorded once. The table lets no row be changed, so the first time stands.
        db.prepare("INSERT OR IGNORE INTO seen (id, at) VALUES (?, ?)").run(id, clock.now());
        return db.prepareWithTimes("SELECT at FROM seen WHERE id = ?").get(id) as { at: bigint };
      });
      return recordResponse({ record: id, firstSeen: formatTimestamp(seen.at) }, 202);
    } catch (error) {
      // An error of the caller's is said in the terms of core 10.2. Any other says nothing.
      return responseFor(error).response;
    }
  };
}

/** What the endpoint answers to a record sent twice, to what is no record, and to one request more than a burst of three. */
export async function example(record: object, clock: Clock & { at: bigint }): Promise<string[]> {
  const handle = endpoint({ OIP_EXAMPLE_MAX_BYTES: "1048576" }, clock);
  const post = (body: string): Request =>
    new Request("https://example.org/records", {
      method: "POST",
      headers: { "content-type": MEDIA_TYPE },
      body,
    });
  const lines: string[] = [];
  const sent = JSON.stringify(record);
  for (const body of [sent, sent, "{", sent, sent]) {
    const response = await handle(post(body), "203.0.113.7");
    const answer = (await response.json()) as { firstSeen?: string; type?: string };
    lines.push(`${response.status} ${answer.firstSeen ?? answer.type ?? ""}`);
    // A minute passes after the first request, and none after that.
    if (lines.length === 1) clock.at += 60_000_000_000n;
  }
  return lines;
}
```

With a signed Intent, and a clock that starts at noon on 18 November 2026, `example` gives:

```
202 2026-11-18T12:00:00Z
202 2026-11-18T12:00:00Z
400 urn:oip:error:invalid-record
202 2026-11-18T12:00:00Z
429 urn:oip:error:rate-limited
```

The record sent again has the time it was first seen. What is no record is refused in the terms of core 10.2. The fifth request is one more than the burst allows.

## What it exports

| Export                                                                                                                                                                                                | What it is                                                                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Clock`, `Randomness`, `systemClock`, `systemRandomness`                                                                                                                                              | The edges: the present and random bytes, each behind an interface a test replaces                                                                                                                       |
| `readConfig`, `describeConfig`, `integer`, `flag`, `text`, `choice`, `origin`, `list`, `Setting`, `Settings`, `ConfigOf`, `ConfigError`                                                               | A service's settings, read from its own environment variables. Everything wrong is said at once. A secret is never shown                                                                                |
| `Database`, `DatabaseOptions`, `Migration`, `appendOnly`, `isBusy`, `isConstraint`, `kept`, `StorageError`, `StatementSync`, `SQLInputValue`                                                          | SQLite: migrations, transactions, and tables whose rows are never changed or removed                                                                                                                    |
| `readBody`, `readRecord`, `recordFrom`, `requireRecordType`, `recordResponse`, `problemResponse`, `responseFor`, `HttpFailure`, `Unavailable`                                                         | A body bounded before it is read, a record read by the reader of `@oip/core`, and failures as RFC 9457 problem details                                                                                  |
| `LogArchive`, `ArchiveOptions`, `Published`, `Resolved`, `publicationProblem`, `OtherRecord`, `judgeCopy`, `Held`, `Taken`, `NotTaken`, `ArchiveStore`, `ARCHIVE_SQL`, `Sighting`, `Pair`, `Streamed` | An archive of identity logs: what verifies of the logs published to a service, with the time each event was first seen, the mind's current location record, and duplicity evidence (Layer 1, 7.2, 17.2) |
| `standing`, `overlaid`, `seenAt`                                                                                                                                                                      | A judgement refused where a check in it was cut short (ADR-0010), and evidence of first sight laid over what is held, for a record judged before its proofs are recorded                                |
| `authenticate`, `Authentication`, `StoredNonces`, `NONCES_SQL`                                                                                                                                        | Who a request is from (Layer 1, 13.3), with the nonces seen kept in the database                                                                                                                        |
| `RateLimiter`, `RateLimit`, `Allowance`, `addressKey`                                                                                                                                                 | A burst and a steady rate for each client                                                                                                                                                               |
| `gate`, `GateOptions`, `Handler`, `Asked`, `Arrival`, `clientAddress`, `Arrived`                                                                                                                      | The gate every request passes: the rate limit for its address, the metrics, and the one place where what was thrown becomes an answer. The address a request came from, behind proxies that are trusted |
| `GuardedFetcher`, `GuardedFetcherOptions`, `FetchLimits`, `DEFAULT_FETCH_LIMITS`, `Fetched`, `FetchRefused`, `FetchRefusal`, `Resolve`                                                                | The one way to fetch a URL that a record named                                                                                                                                                          |
| `parseAddress`, `isPublicAddress`, `inRange`, `Address`                                                                                                                                               | IP addresses read to their bytes, and which of them are public                                                                                                                                          |
| `Log`, `LogOptions`, `Level`, `Fields`, `FieldValue`                                                                                                                                                  | One line of JSON for each event, with no way to hold a secret                                                                                                                                           |
| `Metrics`, `Counter`, `Gauge`, `Histogram`, `Labels`, `MAX_SERIES`, `DURATION_BUCKETS`, `METRICS_MEDIA_TYPE`                                                                                          | Counters, gauges and histograms in the Prometheus text format                                                                                                                                           |
| `Shutdown`, `ShutdownOptions`, `Stop`, `StopSignal`, `healthResponse`, `readyResponse`, `every`                                                                                                       | `/healthz`, `/readyz`, an orderly stop, and a timer that does not keep the process alive                                                                                                                |

## What to know

- **An archive stores only what verifies** (Layer 1, 17.2; [OEP-0005](../../oeps/oep-0005-service-clarifications.md)). Of a published log it takes the events that verify, from the genesis on, and nothing after the first that does not; of an event's proofs, those that can count, checked against the verifier of `@oip/identity`. A first-seen time is recorded once, in the transaction that stores the event, and no two events of one mind are first seen at the same time. What it holds in memory is rebuilt from the database when it starts and whenever a write fails.
- **Storage keeps evidence.** A commit is on the disk before `transaction` returns. A table made with `appendOnly` takes rows and lets none be changed or removed, by any spelling: `UPDATE`, `DELETE`, `REPLACE` and `ON CONFLICT DO UPDATE` all fail. A database made by other migrations than the program's, or by more of them, is not opened. A time is read with `prepareWithTimes`, as a `bigint`: nanoseconds do not fit a number.
- **A transaction is synchronous.** Work that returns a promise is undone, and `transaction` throws. Do what must wait before it or after it.
- **A failure that will pass is a 503.** A check that was cut short ([ADR-0010](../../docs/adr/0010-checks-cut-short.md)) and a database another writer holds say nothing of the request. Throw `Unavailable`, or let the storage error through: `responseFor` answers 503 with `Retry-After`.
- **A failure nobody expected says nothing to the client.** `responseFor` answers 500 with no detail and tells you it was unexpected, so that you log it.
- **The fetcher refuses by default.** It fetches HTTPS only, from public addresses only, and connects to an address it has checked. `allow` is for your own test network. A name that resolves to a public address and a private one is refused whole.
- **A service's origin comes from its configuration.** `authenticate` puts the signed URI together from `origin` and the path and query asked for. It reads no `Host`.
- **A log line holds plain values.** Give `Log.event` text, numbers and booleans. Give `Log.failure` what was thrown: it logs the class, the code and the place, and the message only of an error of ours.
- **A label is a small set you chose.** A route as you name it, a status, a problem code. Never a path as it was asked for, or a mind's address.

## Tests

- The archive is tested with copies crowded with proofs that sign nothing (a stranger's control key, a mind that controls nothing, a member's name on a key that is not the member's, a signature that fails) and with a database file: restarts, two valid events for one position, a clock that does not move and one that goes back, a table that goes missing in the middle of a write.
- The storage is tested with files: two connections on one database, a process killed in the middle of a transaction, a database made by other migrations.
- The fetcher is tested against an HTTPS server on the machine, with a certificate made for the run (it needs `openssl`). Its guards had faults planted in them one at a time, and each fails a test.
- The parts that judge a request or guard a connection (`auth`, `http`, `ip`, `fetcher`) are held to 95% coverage for each file.
