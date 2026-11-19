# @oip/host

The host of the Open Intelligence Protocol (Layer 1, Section 13). It receives for the minds it serves: it answers at their well-known URLs, takes packets at their inboxes, keeps their mailboxes, and holds a WebSocket open to a mind's own instance.

It is built on [`@oip/server`](../server/README.md) and judges with [`@oip/net`](../net/README.md). It runs on Node.js 24.15 or later.

## Run it

```
OIP_HOST_ORIGIN=https://host.example OIP_HOST_DATABASE=/data/host.db OIP_HOST_MINDS=did:oip:b… oip-host
```

Every setting is a variable that starts with `OIP_HOST_`. A host that is misconfigured says everything that is wrong and does not start.

| Variable                              | Default                | What it is                                                                                                             |
| ------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `ORIGIN`                              | none: it must be set   | The origin clients reach the host at. A `Hello` and a signed request name it                                           |
| `HOST`, `PORT`                        | `0.0.0.0`, `8080`      | Where it listens                                                                                                       |
| `DATABASE`                            | `./host.db`            | Its database file                                                                                                      |
| `MINDS`                               | none                   | The addresses of the minds it takes on when they bring their bundle, separated by commas                               |
| `OPEN`, `MAX_MINDS`                   | `false`, `1000`        | Whether it takes on any mind that brings its bundle, and the most it then serves                                       |
| `RESOLVERS`                           | none                   | The origins of the resolvers it asks for the log of a sender it has not met, separated by commas                       |
| `FETCH_ALLOW`                         | none                   | Address ranges it may fetch from besides the public ones, as `address/bits`: a test network, and nothing in production |
| `MAX_RECORD_BYTES`                    | `8388608`              | The most bytes of a record, or of a message on a socket, that are read                                                 |
| `READ_BURST`, `READ_PER_MINUTE`       | `120`, `600`           | What one address may read                                                                                              |
| `DELIVER_BURST`, `DELIVER_PER_MINUTE` | `60`, `600`            | What one address may deliver, over HTTP and over sockets together                                                      |
| `OWNER_BURST`, `OWNER_PER_MINUTE`     | `60`, `600`            | How many signed requests one address may make, and how many sockets it may open                                        |
| `MAILBOX_ITEMS`, `MAILBOX_BYTES`      | `1000`, `67108864`     | The most a mailbox holds                                                                                               |
| `RETENTION_DAYS`                      | `30`                   | How long an item stays in a mailbox. Layer 1, 13.5 asks for 30 days at least, and the host takes no less               |
| `OBJECT_BYTES`, `FEED_ENTRIES`        | `268435456`, `1000000` | The most records, in bytes, and feed entries it serves for one mind                                                    |
| `MAX_SOCKETS`                         | `1024`                 | The most WebSocket connections open at once                                                                            |
| `TRUSTED_PROXIES`                     | `0`                    | How many proxies stand in front, each adding the address it was asked from to `X-Forwarded-For`                        |
| `UNDERSTOOD`                          | none                   | The extension namespaces it implements (core 8.3), separated by commas                                                 |
| `LOG_LEVEL`                           | `info`                 | `debug`, `info`, `warn` or `error`                                                                                     |
| `SHUTDOWN_GRACE_MS`                   | `10000`                | How long it may take to stop                                                                                           |

It stops in order on `SIGTERM` or `SIGINT`: its sockets close with code 1001, what is in flight is answered, and the database is closed last.

## What it serves

A mind `M` whose genesis has the content ID `m` (its address without `did:oip:`) is served at these URLs. Errors are RFC 9457 problem details with the types of core 10.2.

| Request                                                  | Answer                                                                                                                                                                                                                         |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `GET /.well-known/oip/mind/m`                            | The mind's `Bundle`: its log, its current location record and profile, and `firstSeen` (13.1)                                                                                                                                  |
| `GET /.well-known/oip/mind/m/log?after=<seq>&limit=<n>`  | A `LogPage`                                                                                                                                                                                                                    |
| `GET /.well-known/oip/mind/m/feed?after=<seq>&limit=<n>` | A `FeedPage` of the mind's public feed                                                                                                                                                                                         |
| `GET /.well-known/oip/mind/m/obj/<contentId>`            | A record the mind's feed lists                                                                                                                                                                                                 |
| `POST /oip/v1/minds/m/inbox`                             | `202` with `{ "stored": true }`, or with the mind's `Ack` if the host signs for it (13.2). A packet addressed to a query is taken inside a `Forwarded` record from a broker (18.5). The same packet again gets the same answer |
| `GET /oip/v1/minds/m/ws`                                 | The WebSocket of 13.4, with the subprotocol `oip.v1`                                                                                                                                                                           |
| `POST /oip/v1/minds/m/mailbox`                           | `202` with `{ "stored": true }` (13.5). `507` if the mailbox is full                                                                                                                                                           |
| `GET /oip/v1/minds/m/mailbox?after=<cursor>&limit=<n>`   | `{ "items": [{ "cursor", "record" }], "next" }`, for a request the mind signed (13.3)                                                                                                                                          |
| `DELETE /oip/v1/minds/m/mailbox/<cursor>`                | `204`, for a request the mind signed                                                                                                                                                                                           |
| `GET /healthz`, `/readyz`, `/metrics`                    | Whether it runs, whether it can do its work, and its counts in the Prometheus text format                                                                                                                                      |

So in a location record (15.1), the `https` endpoint of a mind served here is `{origin}/oip/v1/minds/m`, and its `mailbox` endpoint is `{origin}/oip/v1/minds/m/mailbox`.

### How a mind hands the host what it serves

Layer 1 says what a host serves for a mind, and leaves open how the mind brings it. These three requests are this host's own. Each is signed by the mind itself as 13.3 describes.

| Request                                             | What it does                                                                                                                                                                                                                  |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT /oip/v1/minds/m` with a `Bundle`               | Brings the mind's log, location record and profile. `201` the first time, when the host takes the mind on; `200` after. The signature is judged against the log in the bundle, so a mind can bring its log for the first time |
| `PUT /oip/v1/minds/m/obj/<contentId>` with a record | Brings a record for the host to serve. A copy held already is replaced: a record gains proofs, and its content ID stays                                                                                                       |
| `POST /oip/v1/minds/m/feed` with a `FeedPage`       | Adds entries to the feed. All are taken or none. Each lists a record the host holds already (10.2)                                                                                                                            |

### Over a socket

The host speaks first, with `{ "type": "Challenge", "nonce", "domain" }`. The client answers with a `Hello` (13.3) and is welcomed, or the connection closes with code 4401. After that each message is one record.

- A `Packet`, a `Forwarded` record or a `Sealed` record is delivered as at the inbox. If the host signs for the mind, the `Ack` is sent back.
- The mind's own instance is sent what is in its mailbox, in order, and what arrives while the socket is open. A record stays in the mailbox until the mind says it has it: with its own `Ack` over the socket, or with `DELETE` over HTTP. A socket that drops loses nothing.
- A message that is refused closes the connection with code 1008 and the code of its problem as the reason, such as `invalid-proof`. Code 1013 means ask again later.

## Use it as a library

```ts
import { formatTimestamp, MEDIA_TYPE, mindId, type SyncSigner, utf8 } from "@oip/core";
import { signRequest } from "@oip/net";
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

import { Host, HOST_MIGRATIONS, hostApp } from "@oip/host";

const ORIGIN = "https://host.example";

/** A mind, as far as signing a request for it needs: its address, a key reference and the key. */
export interface Owner {
  readonly address: string;
  readonly keyRef: string;
  readonly signer: SyncSigner;
}

/**
 * A host in memory, asked as its clients would ask one over HTTP. A mind
 * brings its bundle and is taken on. A sender delivers a packet to its
 * inbox, twice. The mind drains its mailbox and removes what it has.
 *
 * @param bundle - The owner's `Bundle`.
 * @param sender - The sender's `Bundle`, which the host is given here as a resolver would give it.
 * @param packet - A `Packet` from the sender to the owner.
 */
export async function example(
  owner: Owner,
  bundle: unknown,
  sender: unknown,
  packet: unknown,
  clock: Clock & { at: bigint },
): Promise<string[]> {
  const db = Database.open({ path: ":memory:" }, HOST_MIGRATIONS, clock);
  const log = new Log({ service: "host", clock, sink: () => undefined });
  const archive = new LogArchive({ db, clock });
  const limiter = (): RateLimiter => new RateLimiter({ burst: 100, perMinute: 600 }, clock);
  const app = hostApp({
    host: new Host({ db, archive }),
    archive,
    clock,
    log,
    metrics: new Metrics(),
    origin: ORIGIN,
    nonces: new StoredNonces(db),
    // This host takes on one mind.
    admits: (mind) => mind === owner.address,
    limits: { read: limiter(), deliver: limiter(), owner: limiter() },
    shutdown: new Shutdown({ log }),
    ready: {},
  });
  const ask = (path: string, init?: RequestInit): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`${ORIGIN}${path}`, init), {}));
  let nonces = 0;
  /** A request the owner signs (Layer 1, 13.3). */
  const signed = async (method: string, path: string, record?: unknown): Promise<RequestInit> => {
    const body = record === undefined ? undefined : utf8(JSON.stringify(record));
    const headers: [string, string][] = body === undefined ? [] : [["Content-Type", MEDIA_TYPE]];
    const added = await signRequest(
      { method, url: `${ORIGIN}${path}`, headers, ...(body === undefined ? {} : { body }) },
      { keyRef: owner.keyRef, created: clock.now(), nonce: `example-nonce-${++nonces}` },
      owner.signer,
    );
    return { method, ...(body === undefined ? {} : { body }), headers: [...headers, ...added] };
  };

  const endpoint = `/oip/v1/minds/${mindId(owner.address) ?? ""}`;
  const lines: string[] = [];
  const brought = await ask(endpoint, await signed("PUT", endpoint, bundle));
  lines.push(`the mind brings its bundle at ${formatTimestamp(clock.now())}: ${brought.status}`);

  const { mind: from } = sender as { mind: string };
  archive.publish(mindId(from) ?? "", sender as never);
  for (const time of ["first", "again"]) {
    const delivered = await ask(`${endpoint}/inbox`, {
      method: "POST",
      headers: { "content-type": MEDIA_TYPE },
      body: JSON.stringify(packet),
    });
    lines.push(`the packet is delivered, ${time}: ${delivered.status} ${await delivered.text()}`);
  }

  const mailbox = `${endpoint}/mailbox`;
  const unsigned = await ask(mailbox);
  lines.push(`anyone asks for the mind's mail: ${unsigned.status}`);
  const drained = (await (await ask(mailbox, await signed("GET", mailbox))).json()) as {
    items: { cursor: string; record: unknown }[];
  };
  lines.push(
    `the mind drains its mailbox: ${drained.items.length} item, the packet: ${String(
      JSON.stringify(drained.items[0]?.record) === JSON.stringify(packet),
    )}`,
  );
  const item = `${mailbox}/${drained.items[0]?.cursor ?? ""}`;
  lines.push(`the mind removes it: ${(await ask(item, await signed("DELETE", item))).status}`);
  const after = (await (await ask(mailbox, await signed("GET", mailbox))).json()) as {
    items: unknown[];
  };
  lines.push(`left in the mailbox: ${after.items.length}`);
  db.close();
  return lines;
}
```

With a mind, its bundle, a sender's bundle and a packet from the sender to the mind, and a clock at two minutes past midnight on 1 January 2026, `example` gives:

```
the mind brings its bundle at 2026-01-01T00:02:00Z: 201
the packet is delivered, first: 202 {"stored":true}
the packet is delivered, again: 202 {"stored":true}
anyone asks for the mind's mail: 401
the mind drains its mailbox: 1 item, the packet: true
the mind removes it: 204
left in the mailbox: 0
```

## What it exports

| Export                                                                    | What it is                                                                                                                                                                              |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `start`, `Running`, `Edges`, `SETTINGS`, `PREFIX`                         | The host as a running service, and its settings                                                                                                                                         |
| `hostApp`, `HostAppOptions`                                               | Its HTTP interface, as a function from a request to a response                                                                                                                          |
| `Host`, `HostOptions`, `HostLimits`, `DEFAULT_HOST_LIMITS`, `Answer`      | What a host does with a record once it has been read: the inbox, the mailbox, the feed and the records served. Give it a `signer` and it acknowledges for the minds whose keys it holds |
| `Sockets`, `SocketsOptions`, `Wire`, `Connection`, `SUBPROTOCOL`, `CLOSE` | The WebSocket binding without the socket: what is said over a connection                                                                                                                |
| `attachSockets`, `UpgradeOptions`                                         | The binding on an HTTP server's upgrade requests, with the `ws` library                                                                                                                 |
| `deliverLearning`, `partiesOf`                                            | Judging a packet again once the log of its sender, or of its broker, has been learned from the resolvers (`Lookup` of `@oip/server`)                                                    |
| `HOST_MIGRATIONS`, `HostStore`, `MailboxItem`                             | Its database: an archive of identity logs (`LogArchive` of `@oip/server`), the nonces of signed requests, and the host's own tables                                                     |

## What to know

- **A host takes on the minds its operator names.** With `MINDS` empty and `OPEN` false it serves nobody new. An open host takes on any mind that brings its own bundle, up to `MAX_MINDS`.
- **An inbox judges before it keeps.** A packet is taken only if it is addressed to the mind, its dates allow it and its sender signed it (12.4). The first sight of its proofs is recorded only if it is kept, so a packet that is refused leaves nothing behind. A mailbox checks the form of what is posted and no more: the mind judges what it drains.
- **A host that holds no key of a mind acknowledges nothing.** It answers `{ "stored": true }`, and the mind may acknowledge later (13.2). The command `oip-host` holds no keys. A program that builds on `Host` can give it a `signer`, and must keep that key as it would any other.
- **Strangers can write to a mind only if the host can learn their log.** Set `RESOLVERS`. Without it an inbox takes packets only from minds whose logs the host holds already.
- **What is kept for a mind is bounded**: its mailbox in items and in bytes, the records it serves in bytes, its feed in entries. Beyond that the answer is `507`.
- **The host holds one feed entry at each position.** A second valid entry at a position is refused with `duplicity` (10.3), so a mind that runs several instances and publishes through its host has a single writer. After a key is declared compromised, the entries it signed from that time on are dropped when the mind continues its feed (10.4).
- **A record cannot be taken back.** There is no request that removes a record the host serves for a mind, or an entry of its feed: a host must serve every record a feed it serves lists (10.2).
- **Put it behind TLS.** The host speaks HTTP. A proxy in front of it terminates TLS, and `TRUSTED_PROXIES` says how many there are, so that limits apply to the client's address and not the proxy's.

The threats it is built against, and what it leaves to its operator, are in [the host's threat model](../../docs/threat-models/host.md).

## Tests

```
pnpm vitest run --project @oip/host
```

`test/host.test.ts` covers what the host does with a record, `test/app.test.ts` the HTTP interface, `test/sockets.test.ts` the binding without a socket, `test/lookup.test.ts` the asking of resolvers, and `test/main.test.ts` a host that runs, asked with `fetch` and a WebSocket client.
