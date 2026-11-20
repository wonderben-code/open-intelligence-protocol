# @oip/client

The library applications use for the [Open Intelligence Protocol](../../README.md): it makes and manages a mind, publishes, resolves, finds, sends and receives, and verifies everything it receives before it returns it ([BUILD.md](../../BUILD.md), M6).

It is being built in milestone M6, one part at a time. What is here is finished and tested; the rest of the list in BUILD.md follows.

## An example

[`examples/first-mind.ts`](examples/first-mind.ts) makes a mind from nothing, signs a record as it, and changes its identity:

```ts
import { type Clock, type Fetch, Lookup, Mind, systemClock } from "@oip/client";
import { formatTimestamp } from "@oip/core";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind from nothing: its keys in a keystore, its genesis with the
 * resolvers it trusts, a record it signs, and a change to its identity.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const clock = edges.clock ?? systemClock;

  // The keys are made in the keystore, and the genesis is published to every resolver.
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, ...edges },
    { kind: "agent", homes: ["https://home.example"] },
  );
  const took = mind.publications.filter(
    (publication) => publication.service === "resolver" && publication.taken,
  ).length;
  output.push(`a mind is made, and ${String(took)} resolvers have its genesis`);

  // The mind signs a record with its operational key.
  const intent = await mind.sign({
    oip: "1",
    type: "Intent",
    author: mind.address,
    created: formatTimestamp(clock.now()),
    want: "A lease translated into Portuguese.",
  });
  output.push(`it signs an ${intent.type} with ${String(intent.proof.length)} proof`);

  // Anyone resolves it from the same resolvers, and verifies its log.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  output.push(`another client verifies its log: ${String(resolved.log.entries.length)} event`);

  // A change of identity takes the control keys, which are unlocked for it alone.
  const state = await mind.update({ homes: ["https://new-home.example"] }, { control: lock });
  output.push(`after an update it is at event ${String(state.seq)}, at ${String(state.homes[0])}`);
  output.push(`a backup is due for: ${(await keystore.backupDue()).join(", ")}`);
  mind.close();
  return output;
}
```

It gives:

```
a mind is made, and 2 resolvers have its genesis
it signs an Intent with 1 proof
another client verifies its log: 1 event
after an update it is at event 1, at https://new-home.example
a backup is due for: control, operational, invocation, agreement
```

## Publishing

[`examples/publish.ts`](examples/publish.ts) publishes what a mind is, where it can be reached, and a record on its feed, to two resolvers and a host:

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * A mind that says what it is, where it can be reached, and what it stands
 * by in public.
 *
 * @param resolvers - The HTTPS origins of the resolvers the mind trusts.
 * @param home - The HTTPS origin of a host that takes the mind on.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  resolvers: readonly string[],
  home: string,
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  // What the client remembers of its own work. An application keeps it where it lasts.
  const memory = memoryStorage();
  const mind = await Mind.create(
    { keystore, lock, resolvers, memory, ...edges },
    { kind: "agent", homes: [home] },
  );

  // A profile, and with it a location record that names it and the mind's endpoints at its home.
  const profile = await mind.publishProfile({
    name: "Ada",
    summary: "Translates contracts between English and Portuguese.",
    capabilities: [
      { id: "translate", summary: "Translation of legal texts", tags: ["lang:en", "lang:pt"] },
    ],
  });
  output.push(`a profile is published: ${profile.name}, ${profile.kind}`);
  const took = mind.publications.filter((publication) => publication.taken);
  output.push(`taken by: ${took.map((publication) => publication.service).join(", ")}`);

  // A record the mind stands by in public goes on its feed, at its home.
  const entry = await mind.publishRecord(profile);
  output.push(`its feed has an entry at ${String(entry.seq)} for a ${entry.objectType}`);

  // The next location record says the mind is away, and keeps the rest of the one before.
  const location = await mind.publishLocation({ status: "paused" });
  output.push(
    `location record ${String(location.seq)}: ${location.status}, ` +
      `${String(location.endpoints.length)} endpoints, feed at ${String(location.feed?.seq)}`,
  );

  // Another client reads all of it from the resolvers and the home, verified.
  const other = new Lookup({ resolvers, ...edges });
  const resolved = await other.resolve(mind.address);
  output.push(
    `another client reads: ${String(resolved.participant?.record.name)}, ` +
      String(resolved.location?.record.status),
  );
  const { feed } = await other.feed(mind.address);
  output.push(`and its feed: ${String(feed.entries.length)} entry that verifies`);
  mind.close();
  return output;
}
```

It gives:

```
a profile is published: Ada, agent
taken by: resolver, resolver, home
its feed has an entry at 0 for a Participant
location record 1: paused, 2 endpoints, feed at 0
another client reads: Ada, paused
and its feed: 1 entry that verifies
```

## Finding

[`examples/find.ts`](examples/find.ts) lists a mind at an indexer, and finds it from another client:

```ts
import { type Clock, type Fetch, Lookup, Mind } from "@oip/client";
import { Keystore, type Lock, memoryStorage } from "@oip/keystore";

/**
 * One mind says what it can do, and another finds it by that.
 *
 * @param services - The HTTPS origins of the resolvers and the indexers the
 *   clients name, and of a host that takes the mind on.
 * @param lock - What the mind's keys are sealed under.
 * @param edges - What a test puts in the place of the network and the clock.
 */
export async function example(
  services: {
    readonly resolvers: readonly string[];
    readonly indexers: readonly string[];
    readonly home: string;
  },
  lock: Lock,
  edges: { readonly fetch?: Fetch; readonly clock?: Clock } = {},
): Promise<string[]> {
  const output: string[] = [];
  const { resolvers, indexers, home } = services;

  // A mind publishes its profile. The indexers the client names are brought it too.
  const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock });
  const mind = await Mind.create(
    { keystore, lock, resolvers, indexers, ...edges },
    { kind: "agent", homes: [home] },
  );
  await mind.publishProfile({
    name: "Ada",
    capabilities: [
      { id: "translate", summary: "Translation of legal texts", tags: ["lang:en", "lang:pt"] },
      { id: "review", summary: "Review of contracts", tags: ["domain:legal"] },
    ],
  });
  const listed = mind.publications.filter(
    (publication) => publication.service === "indexer" && publication.taken,
  );
  output.push(`listed by ${String(listed.length)} indexer`);
  mind.close();

  // Anyone asks the indexer, and gets back only what was fetched and verified.
  const seeker = new Lookup({ resolvers, indexers, ...edges });
  const { found, refused, sources } = await seeker.find({
    want: "translation",
    tags: ["lang:pt"],
  });
  output.push(`the indexer named ${String(sources[0]?.results)} record`);
  for (const { record, capability, by } of found) {
    const name = record.type === "Participant" ? record.name : record.type;
    output.push(
      `found: ${name}, for "${String(capability?.summary)}", score ${String(by[0]?.score)}`,
    );
  }
  output.push(`named and not returned: ${String(refused.length)}`);
  return output;
}
```

It gives:

```
listed by 1 indexer
the indexer named 1 record
found: Ada, for "Translation of legal texts", score 1
named and not returned: 0
```

## What it exports

| Export                                                                                                                        | What it does                                                                                                                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Mind`, `MindOptions`, `NewMind`                                                                                              | A mind of one's own: `create` makes one with its keys in a keystore and its genesis with every resolver; `open` opens it; `sign` signs a record as it; `refresh` resolves it afresh; `close` locks its keys                                                                                    |
| `LocationFields`, `ProfileFields`, `Endpoint`, `Publication`, `homeEndpoints`, `DEFAULT_TTL`                                  | What a mind publishes of itself: `Mind.publishLocation` (Layer 1, Section 15), `publishProfile` (16), `publishRecord` on its feed (10) and `bringHomes`. `publications` says what each resolver and each home answered                                                                         |
| `IdentityChanges`, `KeyEntry`, `ControlOptions`                                                                               | What changes with an identity event, and what opens the control keys for it: `Mind.update`, `addKey`, `revokeKey`, `fork`, `retire` (Layer 1, 3.7 to 3.10)                                                                                                                                     |
| `Lookup`, `LookupOptions`, `Resolved`, `ResolverAnswer`, `DEFAULT_MAX_LOGS`                                                   | Resolves a mind: fetches its identity log from the resolvers the client trusts, takes their first-seen times as evidence, and verifies the log with them (Layer 1, 17.1; core 9.4). With the log come the mind's current location record and profile, if a resolver served them and they count |
| `ReadFeed`, `HomeAnswer`, `DEFAULT_MAX_FEED_ENTRIES`                                                                          | `Lookup.feed` reads a mind's public feed from its homes and verifies it (Layer 1, 10 and 13.1)                                                                                                                                                                                                 |
| `Finding`, `Found`, `Listed`, `Ranking`, `NotFound`, `IndexerAnswer`, `MAX_RESULTS`                                           | `Lookup.find` asks the indexers the client names a capability query, and fetches and verifies every record they name before it returns it (Layer 1, 18.4). `Lookup.record` fetches a record a mind's homes serve, by its content ID                                                            |
| `AliasCheck`, `AliasOptions`, `DidLike`                                                                                       | `Lookup.aliases` checks the other names a mind gives itself: each is the mind's only if it points back (Layer 1, 5.3; Layer 0, Section 4)                                                                                                                                                      |
| `Clock`, `systemClock`                                                                                                        | The present, behind an interface: a test gives its own                                                                                                                                                                                                                                         |
| `exchange`, `askRecord`, `askJson`, `Asking`, `Answer`, `Fetch`, `TransportOptions`, `recordBody`, `refusalOf`, `httpsOrigin` | One request to a service over HTTPS, bounded in size and in time, and its answer read as a record or as JSON                                                                                                                                                                                   |
| `TransportError`, `TransportFailure`                                                                                          | Thrown when a service cannot be reached or does not speak the protocol                                                                                                                                                                                                                         |
| `DEFAULT_TIMEOUT_MS`, `DEFAULT_MAX_BYTES`, `MAX_DETAIL_LENGTH`                                                                | The bounds on an answer, unless a client gives its own                                                                                                                                                                                                                                         |

## What to know

### Resolving a mind

- **Name the resolvers you trust**, by their HTTPS origins: `new Lookup({ resolvers: ["https://resolver.example"] })`. A resolver is a witness (Layer 1, Section 17): its first-seen times are taken as evidence of when an identity event existed. Name more than one, run by different people. `resolve` asks them all, and a mind that showed one of them one event and another a different event for the same position is found out: `duplicitous` is `true`.
- **`resolve` applies the witness rule** (core 9.4). The time of each event comes from the resolver, never from the event's own date and never from the client's own first look. So a proof by a key that was since removed counts if it was seen before the resolver saw the removal, and does not count if it was seen after, whenever this client first met the log.
- **Resolve again before you judge something new.** A log held from an earlier fetch may lack the event that removed a key. `lookup.view` is what the judges of the other packages take (`ownSignedTime`, `receivePacket`, `countsFor`), and it knows each log up to the last time it was resolved.
- **Everything served is verified.** A resolver's copy of a log is verified by itself, every event of it, before it is held. A log that does not verify, a bundle of another mind, and a log served without times are each refused, with the resolver named. A collective's log is verified with its members' logs, which are fetched first: 64 logs at most for one mind, unless `maxLogs` says otherwise.
- **`sources` says what each resolver answered**: how many events it served, or why it served none.

### A mind of one's own

- **`Mind.create` needs a keystore that holds no mind yet**, a lock, and the resolvers the mind trusts. It makes the keys, signs the genesis and publishes it to every resolver. `publications` says which took it. One is enough for the mind to exist, and a mind SHOULD have two (Layer 1, 7.4). The homes the mind names are brought the genesis too.
- **The everyday keys stay unlocked while the mind is open**: the operational keys it signs with and the agreement keys records are sealed to. The control keys are unlocked for one identity change at a time, by the lock you pass to it, and locked again. Give them a lock of their own and the passphrase of everyday work cannot change the mind's identity.
- **Every identity change rotates the control keys.** An event reveals the keys the event before committed to, and commits to new ones (Layer 1, 3.4). `update({}, …)` does only that.
- **An identity change is made in an order that survives a process that stops.** The keystore binds the control keys to the event; the event is signed and verified here as any verifier would; it is published and read back from a resolver; then the keys that signed are destroyed (Layer 1, 3.11). The next change finishes one that stopped, with the same event, before it does anything else.
- **What is refused before it leaves costs nothing.** A change that cannot be signed, or that does not verify, is an `OipError` `invalid-record`. No key stays bound to it, and nothing was sent.
- **Two copies of a keystore must not both change the mind's identity.** The second to publish is told `duplicity`, or finds the log moved on to a key it does not hold: `forbidden`. A copy that signed an event and lost the position destroys the keys of that event and does not publish it.
- **After restoring a backup, change nothing until the mind is opened**: opening resolves it, and the first identity change destroys the control keys the log shows to be used. If the log has moved on to a key the backup does not hold, the mind's identity can no longer be changed from that keystore.
- **`revokeKey` with `compromisedSince`** withdraws what the key signed from that time on, for every verifier that learns of the event (Layer 1, 6.2). What it signed before stands.

### Publishing

- **A location record and a profile go to every resolver and to every home.** `publishLocation` signs the mind's next location record: its number is one more than the last, and what you leave out stays as the record before had it. With no record before, the endpoints are `homeEndpoints` of the mind's homes, the record is good for an hour, and the mind is `active`. `publishProfile` signs a profile, which supersedes the one before, and a location record that names it: that is what makes it current (Layer 1, 16.4).
- **`publications` says what each service answered.** Publishing succeeds when a resolver took the record. A home that could not be reached is brought the mind's records later, with `bringHomes`.
- **Every request is signed** by the mind's operational key, as Layer 1, 13.3 describes. A resolver that asks for authenticated publication takes it, and so does a host.
- **How a mind brings a host its records is the reference host's own interface.** Layer 1 says what a host serves, and leaves that open. A home that is not an [`@oip/host`](../host/README.md) answers these requests with something else, and `publications` says so.
- **The homes are brought every identity event**, since they serve the mind's log and judge its requests by it. A home takes a mind on when the mind first brings its bundle, if the host admits it.
- **A feed has one entry at each position, and two are equivocation** (Layer 1, 10.3). `publishRecord` remembers the entry before it leaves, and a call that failed is finished by the next one with the same entry. Calls are taken one after another.
- **Give the client a memory that lasts**: `memory` in the options, a storage of `@oip/keystore` of its own, not the keystore's. It holds where the feed stands and the number of the last location record. None of it is secret. Without it, or on a new device, the client reads the feed from the mind's homes and goes on from where it ends. It refuses to go on if the homes serve less than the mind's last location record says there is, or if none answers.
- **Two processes must not write one feed.** They find each other out in the memory, if they share it: the second to write is told `changed`, before its entry has left. If they do not share it, a home that holds another entry at the position answers `duplicity`. The client then forgets where it thought the feed stood, and the next call reads it afresh.
- **A location record says where the feed stood when it was signed.** Publish one after the entries that matter. A reader that finds less at a home than the record says knows the home is behind.
- **`Lookup.feed` reads every home and judges what they served together.** A home that withholds the end of a feed is made up for by one that serves it. It reads 10 000 entries of a feed from one home at most. An entry counts from when this client first saw it.

### Aliases

- **A name a mind lists is not its name until the name points back** (Layer 1, 5.3). `lookup.aliases(mind)` asks what answers for each alias, and says which are verified. Show no other as the mind's (Layer 0, 4.2). `resolve` verifies none, and its DID document lists none.
- **An HTTPS origin** serves the address, alone, as `text/plain` at `/.well-known/oip/did`. The alias is the origin itself: `https://ada.example`, and no page of it.
- **`dns:<name>`** has a TXT record at `_oip.<name>` with `did=<address>`. A client asks the DNS with what you give it: `dnsTxt: resolveTxt` of `node:dns/promises` in Node.js. A browser has no DNS to ask, and such an alias is `unsupported` there unless you give it a way.
- **Another DID** lists the address in its own `alsoKnownAs`. The client resolves `did:oip` and `did:web` itself. For another method, give it `resolveDid`. A `did:key` has no document that could list anything, and is never verified.
- **`at://<handle>`** is an AT Protocol handle whose DID lists the address. The handle's DID is asked of the DNS where the client can ask it, and of the handle's own site otherwise.
- **What answers for an alias is a stranger.** It is asked over HTTPS only, with no redirect followed, and a kilobyte of text or 64 KiB of document is read of it. That it fails, or lies, makes the alias not verified, with `reason`: it never fails the call.

### Finding

- **Name the indexers you ask**: `indexers` in the options, by their HTTPS origins. An indexer is not trusted as a resolver is. What it answers is advice, and `find` returns nothing on its word alone.
- **An indexer's answer is taken if it is its own**: a `QueryResult` to the query that was asked, signed by a mind your resolvers hold. Of an answer it looks at as many results as the query's `limit`, 100 at most.
- **Every record named is fetched and verified** (Layer 1, 18.4). A profile is returned if it counts for its mind (16.1) and carries every tag asked for. An Offer or an Intent is returned if its author's own authority signed it and it has not expired. They are fetched from the homes the author's own log names: an indexer's `hints` are not followed.
- **`current` says whether a profile is the mind's current one** (16.4). An indexer may still list one the mind has replaced. It is returned only if the mind's homes still serve it, and marked.
- **`refused` says what was named and is not returned**, each with why, and `sources` what each indexer answered. `by` gives each indexer's own score for what was found. Scores of two indexers do not compare: ranking is each indexer's own policy.
- **A mind that publishes is listed.** `publishProfile` and `publishLocation` submit the mind's bundle and its profile to the indexers the client names, and `publications` says which took them.
- **A client that fetches for strangers is asked to fetch from where they say.** The homes of a mind are URLs its controller chose. In a browser that is as any link. On a server inside a private network, give the client a `fetch` that reaches only public addresses.

### Failures

- **A keystore's own failures are `KeystoreError`s**: a lock that does not open, a role that is unlocked already. They pass through as they are.
- **A service that refuses says why.** Its answer is a problem of core 10.2, and the client throws `OipError` with the service's code: `not-found`, `rate-limited`, `invalid-proof`. The `detail` is the service's own words, cut to 256 printable characters. They are a stranger's words: show them as that.
- **A service that cannot be asked** is a `TransportError`: `unreachable`, `timeout`, `too-large`, or `not-oip` for an answer that is not the protocol's. It names the origin, never the path.
- **Only HTTPS is asked, and no redirect is followed.** A service that has moved says so in a record, which is signed.
- **An answer is bounded** before it is read: 8 MiB and 10 seconds, unless the client says otherwise.
