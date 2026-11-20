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
  const took = mind.publications.filter((publication) => publication.taken).length;
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

## What it exports

| Export                                                                                                                        | What it does                                                                                                                                                                                                |
| ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Mind`, `MindOptions`, `NewMind`, `Publication`                                                                               | A mind of one's own: `create` makes one with its keys in a keystore and its genesis with every resolver; `open` opens it; `sign` signs a record as it; `refresh` resolves it afresh; `close` locks its keys |
| `IdentityChanges`, `KeyEntry`, `ControlOptions`                                                                               | What changes with an identity event, and what opens the control keys for it: `Mind.update`, `addKey`, `revokeKey`, `fork`, `retire` (Layer 1, 3.7 to 3.10)                                                  |
| `Lookup`, `LookupOptions`, `Resolved`, `ResolverAnswer`, `DEFAULT_MAX_LOGS`                                                   | Resolves a mind: fetches its identity log from the resolvers the client trusts, takes their first-seen times as evidence, and verifies the log with them (Layer 1, 17.1; core 9.4)                          |
| `Clock`, `systemClock`                                                                                                        | The present, behind an interface: a test gives its own                                                                                                                                                      |
| `exchange`, `askRecord`, `askJson`, `Asking`, `Answer`, `Fetch`, `TransportOptions`, `recordBody`, `refusalOf`, `httpsOrigin` | One request to a service over HTTPS, bounded in size and in time, and its answer read as a record or as JSON                                                                                                |
| `TransportError`, `TransportFailure`                                                                                          | Thrown when a service cannot be reached or does not speak the protocol                                                                                                                                      |
| `DEFAULT_TIMEOUT_MS`, `DEFAULT_MAX_BYTES`, `MAX_DETAIL_LENGTH`                                                                | The bounds on an answer, unless a client gives its own                                                                                                                                                      |

## What to know

### Resolving a mind

- **Name the resolvers you trust**, by their HTTPS origins: `new Lookup({ resolvers: ["https://resolver.example"] })`. A resolver is a witness (Layer 1, Section 17): its first-seen times are taken as evidence of when an identity event existed. Name more than one, run by different people. `resolve` asks them all, and a mind that showed one of them one event and another a different event for the same position is found out: `duplicitous` is `true`.
- **`resolve` applies the witness rule** (core 9.4). The time of each event comes from the resolver, never from the event's own date and never from the client's own first look. So a proof by a key that was since removed counts if it was seen before the resolver saw the removal, and does not count if it was seen after, whenever this client first met the log.
- **Resolve again before you judge something new.** A log held from an earlier fetch may lack the event that removed a key. `lookup.view` is what the judges of the other packages take (`ownSignedTime`, `receivePacket`, `countsFor`), and it knows each log up to the last time it was resolved.
- **Everything served is verified.** A resolver's copy of a log is verified by itself, every event of it, before it is held. A log that does not verify, a bundle of another mind, and a log served without times are each refused, with the resolver named. A collective's log is verified with its members' logs, which are fetched first: 64 logs at most for one mind, unless `maxLogs` says otherwise.
- **`sources` says what each resolver answered**: how many events it served, or why it served none.

### A mind of one's own

- **`Mind.create` needs a keystore that holds no mind yet**, a lock, and the resolvers the mind trusts. It makes the keys, signs the genesis and publishes it to every resolver. `publications` says which took it. One is enough for the mind to exist, and a mind SHOULD have two (Layer 1, 7.4).
- **The everyday keys stay unlocked while the mind is open**: the operational keys it signs with and the agreement keys records are sealed to. The control keys are unlocked for one identity change at a time, by the lock you pass to it, and locked again. Give them a lock of their own and the passphrase of everyday work cannot change the mind's identity.
- **Every identity change rotates the control keys.** An event reveals the keys the event before committed to, and commits to new ones (Layer 1, 3.4). `update({}, …)` does only that.
- **An identity change is made in an order that survives a process that stops.** The keystore binds the control keys to the event; the event is signed and verified here as any verifier would; it is published and read back from a resolver; then the keys that signed are destroyed (Layer 1, 3.11). The next change finishes one that stopped, with the same event, before it does anything else.
- **What is refused before it leaves costs nothing.** A change that cannot be signed, or that does not verify, is an `OipError` `invalid-record`. No key stays bound to it, and nothing was sent.
- **Two copies of a keystore must not both change the mind's identity.** The second to publish is told `duplicity`, or finds the log moved on to a key it does not hold: `forbidden`. A copy that signed an event and lost the position destroys the keys of that event and does not publish it.
- **After restoring a backup, change nothing until the mind is opened**: opening resolves it, and the first identity change destroys the control keys the log shows to be used. If the log has moved on to a key the backup does not hold, the mind's identity can no longer be changed from that keystore.
- **`revokeKey` with `compromisedSince`** withdraws what the key signed from that time on, for every verifier that learns of the event (Layer 1, 6.2). What it signed before stands.

### Failures

- **A keystore's own failures are `KeystoreError`s**: a lock that does not open, a role that is unlocked already. They pass through as they are.
- **A service that refuses says why.** Its answer is a problem of core 10.2, and the client throws `OipError` with the service's code: `not-found`, `rate-limited`, `invalid-proof`. The `detail` is the service's own words, cut to 256 printable characters. They are a stranger's words: show them as that.
- **A service that cannot be asked** is a `TransportError`: `unreachable`, `timeout`, `too-large`, or `not-oip` for an answer that is not the protocol's. It names the origin, never the path.
- **Only HTTPS is asked, and no redirect is followed.** A service that has moved says so in a record, which is signed.
- **An answer is bounded** before it is read: 8 MiB and 10 seconds, unless the client says otherwise.
