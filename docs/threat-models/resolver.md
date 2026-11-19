# Threat model: the resolver

For `@oip/resolver` as built in M5: [README](../../packages/resolver/README.md), Layer 1, Sections 7 and 17, [OEP-0005](../../oeps/oep-0005-service-clarifications.md).

## Assets

1. **First-seen times.** Clients use them as evidence of when an event or a proof existed (core 9.4). A time that is wrong, or that changes, lets a removed key sign, or lets a rival event take a position.
2. **The log served for a mind.** At every position, the first valid event the resolver saw. A log that is short, or that holds another event, misleads every client that trusts the resolver.
3. **Duplicity evidence.** The pairs of conflicting valid events.
4. **Availability**: for the minds it holds, and for the clients that ask.

It holds no private key and no secret. Everything it stores is public.

## Who can reach it

| Entry point                                        | Caller                                                                       | Trusted with                                          |
| -------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------- |
| `GET /oip/v1/resolve`, `/duplicity`, `/stream`     | Anyone                                                                       | Nothing                                               |
| `PUT /oip/v1/resolve/<mindId>`                     | Anyone, or any mind with a valid key where `AUTHENTICATED_PUBLICATION` is on | Nothing: what is published is verified                |
| `/healthz`, `/readyz`, `/metrics`                  | Anyone who can reach the port                                                | Nothing. Put `/metrics` behind the operator's network |
| The environment, the database file                 | The operator                                                                 | Everything                                            |
| A proxy in front, where `TRUSTED_PROXIES` is not 0 | The operator's proxy                                                         | The client's address                                  |

## Threats

### Spoofing

| Threat                                                     | What stops it                                                                                                                                                                                                  | Left                                                                                                  |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| A stranger publishes events for a mind it does not control | Every event is verified by `@oip/identity` before it is stored (`intake.ts`). An event not signed as its place requires is invalid, and is not stored (`intake.test.ts`: "is not taken, and nothing after it") | None                                                                                                  |
| A request claims another mind's signature                  | `verifyRequest` of `@oip/net`, for the resolver's configured origin and not the request's `Host` (`@oip/server` `auth.ts`; `auth.test.ts`)                                                                     | None                                                                                                  |
| A signed request is sent again                             | The nonce is kept in the database for as long as the signature is valid, across restarts, and one of two processes takes it (`auth.test.ts`)                                                                   | None                                                                                                  |
| A client claims another address to escape its rate limit   | The address is the socket's. Behind proxies it is what the outermost trusted proxy was asked from, and nothing the sender wrote before that (`main.ts` `clientAddress`; `main.test.ts`)                        | An operator who sets `TRUSTED_PROXIES` higher than the proxies there lets a sender choose its address |

### Tampering

| Threat                                                                                                                       | What stops it                                                                                                                                                                                | Left                                                                                                                            |
| ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| A first-seen time is changed after it was recorded                                                                           | The tables are append-only: `UPDATE`, `DELETE`, `REPLACE` and `ON CONFLICT DO UPDATE` all fail (`@oip/server` `storage.test.ts`). A time is written in the transaction that stores the event | Whoever can write the database file can do anything. That is the operator                                                       |
| A later copy replaces an event the resolver holds                                                                            | A position goes to the event with strictly the earliest evidence, never the later or the longer (Layer 1, 7.3; `resolver.test.ts`: "are kept as evidence")                                   | None                                                                                                                            |
| Two events are first seen at one reading of the clock, so that neither is first                                              | A reading is always later than every time recorded (`resolver.ts` `#reading`; `resolver.test.ts`: "are never first seen at one reading")                                                     | None                                                                                                                            |
| A proof is put on a mind's event to push the event past what a record carries, here or at a client that merges two resolvers | Only proofs that can count are stored and served (`intake.ts`; OEP-0005, item 3; `intake.test.ts`: "the proofs kept for an event")                                                           | A member of a collective can sign as many proofs as it has invocation keys. That is the member's own doing, and is attributable |
| Memory and disk part after a failed write                                                                                    | The memory is rebuilt from the database (`resolver.test.ts`: "a resolver whose database fails")                                                                                              | None                                                                                                                            |

### Repudiation

| Threat                                                   | What stops it                                                                                        | Left                                                                                                                             |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| A mind denies that it signed two events for one position | Both events are kept with their proofs and served as `DuplicityEvidence`. Anyone can verify the pair | The evidence has no times: a client learns that the mind signed both, and which one this resolver serves, not when each was seen |
| The resolver denies a time it served                     | Nothing. A `Bundle` is not signed by the resolver                                                    | Open: see below                                                                                                                  |

### Information disclosure

| Threat                                             | What stops it                                                                                                                                                | Left                               |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- |
| An error tells a client what is inside the service | An error nobody expected is answered `500` with no detail (`@oip/server` `http.ts`; `app.test.ts`: "tells a client nothing")                                 | None                               |
| The log holds what it should not                   | A log line holds plain values only, and the message of an error that is not ours is withheld (ADR-0012; `log.test.ts`). The resolver holds no secret to leak | None                               |
| The stream or the metrics show who asks about whom | Metrics are labelled by route and status, never by mind or address (`app.test.ts`: "names no mind"). Reads are not logged                                    | The operator's proxy may log reads |

### Denial of service

| Threat                                                               | What stops it                                                                                                                                                           | Left                                                                                                                                  |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| A large or deep body                                                 | A body is bounded before it is read, and read no further (`http.ts`). Depth and size are the JSON profile's (core 1.6, 1.9)                                             | None                                                                                                                                  |
| Many requests from one client                                        | A burst and a steady rate for each address, IPv6 by its /64 (`rate.ts`); a bounded number of streams                                                                    | An attacker with many addresses is limited only by their number. Put a proxy or a network limit in front                              |
| A long log published again and again, to make the resolver verify it | The publication limit is lower than the read limit. A log is verified in full on each publication                                                                       | Open: verification is by the portable Ed25519, about 2 ms for each signature. The native one is planned for this milestone (ADR-0006) |
| An undecided event sent for a mind, so that its log stops there      | A resolver stores only what verifies. An event it cannot judge is not stored, and the log it holds stands (OEP-0005, item 2; `resolver.test.ts`: "is called undecided") | A mind's own event that the resolver cannot judge is not stored either: see below                                                     |
| Events stored without end                                            | Only events that verify are stored, each once. A mind can extend its own log without limit, at the rate the publication limit allows                                    | Old location records are never pruned. A quota for each mind is not yet built                                                         |
| Starting is slow                                                     | The resolver reads every log it holds when it starts                                                                                                                    | Open: measured with the load tests of this milestone                                                                                  |

### Elevation of privilege

| Threat                                      | What stops it                                                                                                                                    | Left      |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- |
| A record makes the resolver fetch a URL     | It fetches nothing yet. When it follows homes or other resolvers, it will do so only through `GuardedFetcher` (`@oip/server`; `fetcher.test.ts`) | Not built |
| A request reaches SQL                       | Every statement is prepared with parameters. No SQL is built from input                                                                          | None      |
| A dependency runs code when it is installed | The service adds two packages, neither with an install script, and the lock file is frozen (ADR-0012)                                            | None      |

## Left open

1. **A mind's own event that the resolver cannot judge**, because it lists a critical extension the resolver does not implement. The resolver serves the log up to the event before it, and cannot say that it was shown more. OEP-0005, open question 1.
2. **The resolver does not sign what it serves.** A client cannot later prove what a resolver told it. Not in the specification.
3. **Cost of verification** on a long log, until the native Ed25519 is in.
4. **No quota for each mind**, and no pruning of old location records.
5. **`401` carries no `WWW-Authenticate`.** OEP-0005, open question 2.
