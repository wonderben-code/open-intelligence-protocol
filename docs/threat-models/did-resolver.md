# Threat model: the DID resolver drivers

`@oip/did-resolver` resolves `did:oip` for other tools ([ADR-0030](../adr/0030-the-did-resolver-drivers.md)). It is a thin layer over the client's lookup ([client.md](client.md)), and what that model says of resolving holds here. This model is about what the package adds: a result in another shape, and an HTTP service that resolves for whoever asks.

## Assets

- **The truth of a document**: that the keys in it are the keys of the mind's verified log.
- **The service's reach**: which hosts it connects to.
- **The service's time and memory.**

It holds no key and stores nothing.

## Who can reach it

| Entry point                           | Caller                    | Trusted with                                               |
| ------------------------------------- | ------------------------- | ---------------------------------------------------------- |
| `getResolver` and `resolveDid`        | The program that calls it | Naming the resolvers that are asked                        |
| The environment of `oip-did-resolver` | The operator              | Naming the resolvers, and where the service listens        |
| `GET /1.0/identifiers/<did>`          | Anyone who can reach it   | Asking for the document of one address. Nothing else       |
| What a resolver answers               | The resolver              | Nothing. A log is verified before a document is made of it |

## Threats

### Spoofing

| Threat                                            | What stops it                                                                                                                                                                                                   |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A resolver serves a log with other keys in it     | The address is the hash of the log's first event, and every event is signed as the one before it allows. A log that does not verify gives no document (`driver.test.ts`: nothing is taken on a resolver's word) |
| A resolver serves a fork of a log to this service | Not stopped by one resolver. The operator names two, run by different people, and a mind that is duplicitous for them is said to be (`didDocumentMetadata.duplicitous`)                                         |
| A mind lists an alias it does not have            | A document shows no alias: the driver verifies none (`driver.test.ts`)                                                                                                                                          |

### Tampering

| Threat                                                 | What stops it                                                                          |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| A caller changes a result, and the next caller sees it | Each result is a copy of its own (`driver.ts`)                                         |
| One caller's question changes another's answer         | Each resolution has a lookup of its own, and nothing is kept between two (`driver.ts`) |

### Repudiation

Nothing is signed here, and nothing is stored. There is nothing to deny.

### Information disclosure

| Threat                                               | What stops it                                                                                                   |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| An error tells a caller what is inside the service   | A failure that is nobody's answer is answered with 500 and one fixed line, and logged (`main.test.ts`)          |
| The service is made to fetch from inside its network | It connects to the resolvers its operator named, and nowhere else. A name in a request is an address, not a URL |

### Denial of service

| Threat                                    | What stops it                                                                                                                                                                 |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A resolver answers slowly, or without end | The client's limits: 10 seconds and 8 MiB for an answer, and 64 logs for one mind ([client.md](client.md))                                                                    |
| A mind's log is very long                 | It is verified whole, within the client's limits. A log is as long as its controller made it                                                                                  |
| Many callers ask at once                  | Not stopped here. Each resolution costs a request to each resolver. Put the service behind the Universal Resolver or a proxy that limits callers. See [Left open](#left-open) |

### Elevation of privilege

The service does one thing for every caller, and holds nothing a caller could gain.

## Left open

- **One resolver can serve a fork.** A service set up with a single resolver believes it. The help text and the README say to name two.
- **The service has no rate limit of its own.** It is meant to stand behind something that has one.
- **A document is as fresh as the resolvers.** A resolver that withholds a mind's latest events serves an older, valid log, and the document is of that. Two resolvers make this harder, and do not make it impossible.
