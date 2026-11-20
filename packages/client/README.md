# @oip/client

The library applications use for the [Open Intelligence Protocol](../../README.md): it makes and manages a mind, publishes, resolves, finds, sends and receives, and verifies everything it receives before it returns it ([BUILD.md](../../BUILD.md), M6).

It is being built in milestone M6, one part at a time. What is here is finished and tested; the rest of the list in BUILD.md follows.

## What it exports

| Export                                                                                                                        | What it does                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Lookup`, `LookupOptions`, `Resolved`, `ResolverAnswer`, `DEFAULT_MAX_LOGS`                                                   | Resolves a mind: fetches its identity log from the resolvers the client trusts, takes their first-seen times as evidence, and verifies the log with them (Layer 1, 17.1; core 9.4) |
| `Clock`, `systemClock`                                                                                                        | The present, behind an interface: a test gives its own                                                                                                                             |
| `exchange`, `askRecord`, `askJson`, `Asking`, `Answer`, `Fetch`, `TransportOptions`, `recordBody`, `refusalOf`, `httpsOrigin` | One request to a service over HTTPS, bounded in size and in time, and its answer read as a record or as JSON                                                                       |
| `TransportError`, `TransportFailure`                                                                                          | Thrown when a service cannot be reached or does not speak the protocol                                                                                                             |
| `DEFAULT_TIMEOUT_MS`, `DEFAULT_MAX_BYTES`, `MAX_DETAIL_LENGTH`                                                                | The bounds on an answer, unless a client gives its own                                                                                                                             |

## What to know

### Resolving a mind

- **Name the resolvers you trust**, by their HTTPS origins: `new Lookup({ resolvers: ["https://resolver.example"] })`. A resolver is a witness (Layer 1, Section 17): its first-seen times are taken as evidence of when an identity event existed. Name more than one, run by different people. `resolve` asks them all, and a mind that showed one of them one event and another a different event for the same position is found out: `duplicitous` is `true`.
- **`resolve` applies the witness rule** (core 9.4). The time of each event comes from the resolver, never from the event's own date and never from the client's own first look. So a proof by a key that was since removed counts if it was seen before the resolver saw the removal, and does not count if it was seen after, whenever this client first met the log.
- **Resolve again before you judge something new.** A log held from an earlier fetch may lack the event that removed a key. `lookup.view` is what the judges of the other packages take (`ownSignedTime`, `receivePacket`, `countsFor`), and it knows each log up to the last time it was resolved.
- **Everything served is verified.** A resolver's copy of a log is verified by itself, every event of it, before it is held. A log that does not verify, a bundle of another mind, and a log served without times are each refused, with the resolver named. A collective's log is verified with its members' logs, which are fetched first: 64 logs at most for one mind, unless `maxLogs` says otherwise.
- **`sources` says what each resolver answered**: how many events it served, or why it served none.

### Failures

- **A service that refuses says why.** Its answer is a problem of core 10.2, and the client throws `OipError` with the service's code: `not-found`, `rate-limited`, `invalid-proof`. The `detail` is the service's own words, cut to 256 printable characters. They are a stranger's words: show them as that.
- **A service that cannot be asked** is a `TransportError`: `unreachable`, `timeout`, `too-large`, or `not-oip` for an answer that is not the protocol's. It names the origin, never the path.
- **Only HTTPS is asked, and no redirect is followed.** A service that has moved says so in a record, which is signed.
- **An answer is bounded** before it is read: 8 MiB and 10 seconds, unless the client says otherwise.
