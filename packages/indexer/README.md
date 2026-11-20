# @oip/indexer

The indexer of the Open Intelligence Protocol (Layer 1, Section 18). It lists what minds publish of themselves (their profiles, Offers and Intents), answers capability queries over it with a signed result, and forwards a packet addressed to a query to the minds that match.

It is built on [`@oip/server`](../server/README.md). It runs on Node.js 24.15 or later.

## Run it

```
oip-indexer init /etc/oip/indexer
OIP_INDEXER_ORIGIN=https://indexer.example \
OIP_INDEXER_BUNDLE_FILE=/etc/oip/indexer/bundle.json \
OIP_INDEXER_KEY_FILE=/etc/oip/indexer/operational.key \
OIP_INDEXER_DATABASE=/data/indexer.db oip-indexer
```

`oip-indexer init <directory>` makes the indexer's own mind, once: a key-controlled mind of kind `service`. It writes the mind's `Bundle`, the operational key the indexer signs with, and `next-control.key`, the control key that the mind's next identity event will need. The indexer never reads that last file: move it somewhere safer than the machine the indexer runs on. The control key that signed the genesis is used once and kept nowhere (Layer 1, 3.11). Both key files are readable by their owner only, and nothing is ever written over: where the mind is there already the command ends with 1, or with 0 and nothing done if `--if-missing` is given, for whatever starts the indexer each time. `--home <https origin>` names an origin that serves the mind's records, and may be given more than once.

An indexer signs what it answers, so it is a mind. It is started with the `Bundle` of that mind and with one of the mind's operational keys. The key file holds the 32 bytes of an Ed25519 private key as base64url, and must be readable by its owner only (mode 600): the indexer does not start otherwise. The key is read into the signer and goes nowhere else.

Every setting is a variable that starts with `OIP_INDEXER_`. An indexer that is misconfigured says everything that is wrong and does not start.

| Variable                              | Default              | What it is                                                                                                        |
| ------------------------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `ORIGIN`                              | none: it must be set | The origin clients reach the indexer at                                                                           |
| `HOST`, `PORT`                        | `0.0.0.0`, `8080`    | Where it listens                                                                                                  |
| `DATABASE`                            | `./indexer.db`       | Its database file                                                                                                 |
| `BUNDLE_FILE`                         | none: it must be set | A file with the `Bundle` of the indexer's own mind, as JSON                                                       |
| `KEY_FILE`                            | none: it must be set | A file only its owner can read, with an operational key of that mind                                              |
| `RESOLVERS`                           | none                 | The origins of the resolvers it asks for the log of a sender it has not met, separated by commas                  |
| `FETCH_ALLOW`                         | none                 | Address ranges it may reach besides the public ones, as `address/bits`: a test network, and nothing in production |
| `MAX_BODY_BYTES`                      | `8388608`            | The most bytes of a body that are read                                                                            |
| `MAX_RECORDS`                         | `100`                | The most records in one submission                                                                                |
| `QUERY_BURST`, `QUERY_PER_MINUTE`     | `120`, `600`         | How many queries one address may ask                                                                              |
| `SUBMIT_BURST`, `SUBMIT_PER_MINUTE`   | `20`, `60`           | How many submissions one address may make                                                                         |
| `DELIVER_BURST`, `DELIVER_PER_MINUTE` | `30`, `120`          | How many packets one address may send to be forwarded                                                             |
| `SENDER_BURST`, `SENDER_PER_MINUTE`   | `10`, `30`           | How many packets of one sender are forwarded, whatever address they come from                                     |
| `FANOUT`                              | `10`                 | How many minds a packet goes to where it does not say. Never more than 50                                         |
| `OFFERS`, `INTENTS`                   | `1000`, `1000`       | The most Offers and Intents listed for one mind                                                                   |
| `TRUSTED_PROXIES`                     | `0`                  | How many proxies stand in front, each adding the address it was asked from to `X-Forwarded-For`                   |
| `UNDERSTOOD`                          | none                 | The extension namespaces it implements (core 8.3), separated by commas                                            |
| `LOG_LEVEL`                           | `info`               | `debug`, `info`, `warn` or `error`                                                                                |
| `SHUTDOWN_GRACE_MS`                   | `10000`              | How long it may take to stop                                                                                      |

It stops in order on `SIGTERM` or `SIGINT`: what it took to forward is sent, what is in flight is answered, and the database is closed last.

## What it serves

Errors are RFC 9457 problem details with the types of core 10.2.

| Request                                                                 | Answer                                                                                                                                                                  |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /oip/v1/submit` with `{ "records": [ … ] }` as `application/json` | `202` with `{ "taken": n, "refused": [{ "index", "type", "detail" }] }`. Each record is judged by itself, in order: one that is refused stops none of the others (18.1) |
| `POST /oip/v1/query` with a capability query as `application/json`      | A `QueryResult` the indexer signed (18.2, 18.3)                                                                                                                         |
| `POST /oip/v1/inbox` with a `Packet` whose `to` is a query              | `202` with `{ "stored": true, "forwarding": n }`: how many minds it goes to (18.5)                                                                                      |
| `GET /.well-known/oip/mind/<id>`                                        | The `Bundle` of the indexer's own mind, by which what it signs is judged                                                                                                |
| `GET /healthz`, `/readyz`, `/metrics`                                   | Whether it runs, whether it can do its work, and its counts in the Prometheus text format                                                                               |

### What is listed

- A `Bundle` brings a mind's log, and the profile its location record names. Submit a mind's `Bundle` before its records: a record whose author the indexer cannot judge is refused with `stale-version`.
- A `Participant` is listed if its author's own authority signed it and its `kind` is the kind in the mind's identity state (16.1). One profile is listed for a mind: the one brought last. Each of its capabilities can be found by itself.
- An `Offer` or an `Intent` is listed if its author's own authority signed it, it has not expired, and it is for everyone: one with an `audience` other than `public` is refused. A record that supersedes one of its author's takes its place, and one that states a `status` closes it.

### What a query finds

- The words of `want` are matched against the text of what is listed, in any order, without regard to case or accents, and ranked by SQLite's FTS5. A query with no `want` finds the newest first. A word is matched whole: `lease` does not find `leases`, which is why the example below ranks the capability that matches two of the query's words above the one that matches one.
- Every one of `tags` must be carried. A tag that ends in `/*` matches any tag that begins with what stands before the star: `oasf:nlp/*` matches `oasf:nlp/translation`, and neither `oasf:nlp` nor `oasf:nlpx`. Tags are on the capabilities of profiles.
- `kinds` says which record types are searched: `Participant` unless it says.
- A `score` is from the place in the ranking: 1 for the first, less for each after it. It is a decimal string, worked out in whole numbers.
- `hints` are where the record's author is served: the homes its own identity log names.
- **A query with `constraints` or `evidence` that says anything finds nothing.** This indexer weighs neither, and claims no match it did not check.

## Use it as a library

```ts
import { type SyncSigner } from "@oip/core";
import { judgeRecord } from "@oip/identity";
import { type Clock, Database, Log, LogArchive, Metrics, RateLimiter, Shutdown } from "@oip/server";

import { Broker, Indexer, INDEXER_MIGRATIONS, indexerApp } from "@oip/indexer";

const ORIGIN = "https://indexer.example";

/**
 * An indexer in memory, asked as its clients would ask one over HTTP.
 * Records are submitted, a capability query is answered, and the answer is
 * checked to be the indexer's own.
 *
 * @param own - The indexer's own mind: its address, its `Bundle`, and an operational key of it.
 * @param records - What is submitted: the `Bundle`s of some minds, and their profiles.
 * @param query - A capability query (Layer 1, 18.2).
 */
export async function example(
  own: { readonly address: string; readonly bundle: unknown; readonly signer: SyncSigner },
  records: readonly unknown[],
  query: unknown,
  clock: Clock,
): Promise<string[]> {
  const db = Database.open({ path: ":memory:" }, INDEXER_MIGRATIONS, clock);
  const log = new Log({ service: "indexer", clock, sink: () => undefined });
  const metrics = new Metrics();
  const archive = new LogArchive({ db, clock });
  const limiter = (): RateLimiter => new RateLimiter({ burst: 100, perMinute: 600 }, clock);
  // The indexer holds its own log, as it holds any: what verifies of it.
  archive.publish(own.address.slice("did:oip:".length), own.bundle as never);
  const indexer = new Indexer({ db, archive, clock, address: own.address, signer: own.signer });
  const app = indexerApp({
    indexer,
    // This example forwards nothing: its broker has nowhere to post.
    broker: new Broker({
      indexer,
      archive,
      log,
      metrics,
      post: () => Promise.resolve({ status: 503 }),
      perSender: limiter(),
    }),
    archive,
    clock,
    log,
    metrics,
    limits: { query: limiter(), submit: limiter(), deliver: limiter() },
    shutdown: new Shutdown({ log }),
    ready: {},
  });
  const post = (path: string, body: unknown): Promise<Response> =>
    Promise.resolve(
      app.fetch(
        new Request(`${ORIGIN}${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        }),
        {},
      ),
    );

  const lines: string[] = [];
  const submitted = await post("/oip/v1/submit", { records });
  const { taken, refused } = (await submitted.json()) as { taken: number; refused: unknown[] };
  lines.push(`submitted: ${submitted.status}, ${taken} taken, ${refused.length} refused`);

  const answered = await post("/oip/v1/query", query);
  const result = (await answered.json()) as {
    author: string;
    results: { mind: string; capability?: string; score: string }[];
  };
  // A client verifies the answer's proof, by the log the indexer serves of itself.
  const judged = judgeRecord(result);
  lines.push(
    `answered: ${answered.status}, by the indexer: ${String(result.author === own.address)}, with a proof that verifies: ${String(judged.ok && judged.value.proofs.length === 1)}`,
  );
  for (const [place, found] of result.results.entries()) {
    lines.push(`${place + 1}. ${found.capability ?? "(the profile)"}, score ${found.score}`);
  }
  db.close();
  return lines;
}
```

With an indexer's own mind, the bundles and profiles of two minds and one profile nobody signed for its mind, a query for `Who translates a lease, or reviews contracts?` and a clock at two minutes past midnight on 1 January 2026, `example` gives:

```
submitted: 202, 4 taken, 1 refused
answered: 200, by the indexer: true, with a proof that verifies: true
1. review, score 1
2. translate, score 0.5
```

## What it exports

| Export                                                                               | What it is                                                                                                    |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `start`, `Running`, `Edges`, `SETTINGS`, `PREFIX`, `readKey`                         | The indexer as a running service, its settings, and how it reads its key                                      |
| `init`, `initCommand`, `InitOptions`, `Initialised`, `INIT_FILES`, `INIT_USAGE`      | The indexer's own mind, made once before it first starts, and the command `oip-indexer init`                  |
| `indexerApp`, `IndexerAppOptions`                                                    | Its HTTP interface, as a function from a request to a response                                                |
| `Indexer`, `IndexerOptions`, `IndexerLimits`, `DEFAULT_INDEXER_LIMITS`, `Submission` | What an indexer does with a record and with a query: submission, the signed answer, the minds a query matches |
| `Broker`, `BrokerOptions`, `Forwarding`                                              | Brokered delivery: a packet addressed to a query, forwarded once to the minds that match                      |
| `INDEXER_MIGRATIONS`, `IndexStore`, `Item`, `Found`, `Search`, `Kind`                | Its database: an archive of identity logs (`LogArchive` of `@oip/server`), and what a query finds             |

## What to know

- **An answer is the indexer's word, and no more.** A `QueryResult` says what the indexer listed and how it ranked it. It does not say a record still stands: an Offer may have been taken up, a profile replaced elsewhere. Fetch and verify what a result names before acting on it (18.4).
- **Ranking is this indexer's own policy** (18.4): the order SQLite's FTS5 gives, and nothing a mind can pay for.
- **Nothing a client writes is read as a query language.** Each word of `want` is given to FTS5 between quotes, and a tag is matched as the text it is.
- **A packet is forwarded once**, to at most as many minds as it says, ten where it does not say, and never more than fifty. `brokers` and `maxFanout` are inside what its sender signed. A packet that names its brokers and not this indexer is refused.
- **Forwarding goes to inboxes only**: the `https` endpoints of a mind's current location record, through the guarded fetcher of `@oip/server`. A mind with no such endpoint is counted and not reached. A delivery that fails is not tried again.
- **The key is the operator's to keep.** The indexer reads it from a file and holds it in memory. Whoever can read the file or the process can sign as the indexer.
- **Put it behind TLS**, as the host and the resolver.

The threats it is built against, and what it leaves to its operator, are in [the indexer's threat model](../../docs/threat-models/indexer.md).

## Tests

```
pnpm vitest run --project @oip/indexer
```

`test/indexer.test.ts` covers submission and queries, `test/broker.test.ts` brokered delivery, `test/app.test.ts` the HTTP interface, `test/main.test.ts` an indexer that runs, and `test/bin.test.ts` the command.
