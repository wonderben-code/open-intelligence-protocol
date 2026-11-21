# Threat model: the indexer

For `@oip/indexer` as built in M5: [README](../../packages/indexer/README.md), Layer 1, Section 18. Its archive of identity logs is the `LogArchive` of `@oip/server`, whose threats are in [the resolver's model](resolver.md). What is the indexer's own is what it lists and how it answers (`indexer.ts`, `store.ts`), brokered delivery (`broker.ts`), its HTTP interface (`app.ts`) and its process and key (`main.ts`).

## Assets

1. **The indexer's operational key.** It signs every `QueryResult` and every `Forwarded` record. Whoever holds it speaks as the indexer.
2. **What is listed, and how it is ranked.** A client reads a result as "this indexer found these, in this order".
3. **The reach of brokered delivery.** A packet goes to minds its sender never named. Used wrongly, that is spam with the indexer's signature on it.
4. **Availability**, for those who ask and for those who are listed.

Everything it stores is public. The key is the one secret.

## Who can reach it

| Entry point                                                   | Caller                          | Trusted with                                                                         |
| ------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------ |
| `POST /oip/v1/submit`                                         | Anyone                          | Nothing: a record is listed only if its author's own authority signed it             |
| `POST /oip/v1/query`                                          | Anyone                          | Nothing                                                                              |
| `POST /oip/v1/inbox`                                          | Anyone                          | Nothing: a packet is forwarded only if its sender signed it                          |
| `GET /.well-known/oip/mind/<id>`                              | Anyone                          | Nothing                                                                              |
| The inboxes it posts to                                       | Whoever a location record names | Nothing: an endpoint is a URL a stranger wrote                                       |
| A resolver in `RESOLVERS`                                     | The operator's choice           | Nothing: what it answers is verified. It learns which senders the indexer asks about |
| `/healthz`, `/readyz`, `/metrics`                             | Anyone who can reach the port   | Nothing. Put `/metrics` behind the operator's network                                |
| The environment, the database file, `BUNDLE_FILE`, `KEY_FILE` | The operator                    | Everything                                                                           |

## Threats

### Spoofing

| Threat                                                                                       | What stops it                                                                                                                                                                                                                      | Left                                           |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| A stranger lists a profile, an Offer or an Intent as another mind's                          | A record is listed only if its author's own authority signed it, by a log the indexer holds; a profile also only if its `kind` is the mind's (16.1) (`indexer.ts` `#own`; `indexer.test.ts`: "are refused, each with its problem") | None                                           |
| A stranger takes another mind's Offer down by superseding it                                 | What a record supersedes goes only if it was listed for the same author (`indexer.test.ts`: "Another mind's record is not taken down")                                                                                             | None                                           |
| A packet claims a sender that did not sign it, and is forwarded with the indexer's signature | The sender's proof is verified before anything is forwarded, by the sender's log (`broker.ts`; `broker.test.ts`: "is refused where the broker may not forward it")                                                                 | None                                           |
| An answer is forged in the indexer's name                                                    | A `QueryResult` is signed with an operational key of the indexer's mind, and the indexer serves its own log. A client verifies it                                                                                                  | A client that does not verify is not protected |
| The indexer starts with a key that is not its mind's                                         | It does not start: the key must be an operational key of the latest state of the log in its own bundle (`main.test.ts`: "The key of another mind")                                                                                 | None                                           |

### Tampering

| Threat                                  | What stops it                                                                                                                                                                                                                                                                                      | Left                                                                                                                                                    |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A query changes what FTS5 does          | Each word of `want` is given to FTS5 between quotes, made of letters and digits only. Tags and kinds are parameters of a prepared statement, and a tag's `%` and `_` are escaped (`indexer.test.ts`: "what is no word is not read as anything", "what a pattern would read as anything is itself") | None                                                                                                                                                    |
| A broker widens a packet's reach        | `brokers` and `maxFanout` are inside what the sender signed. The indexer refuses a packet that names other brokers, and forwards to no more minds than the packet says, and never more than fifty (`broker.test.ts`)                                                                               | None                                                                                                                                                    |
| A mind stuffs its profile to rank first | Ranking is FTS5's BM25 over the text a mind wrote about itself. A mind can write whatever it likes                                                                                                                                                                                                 | Open: a mind can game a text ranking. Results are what a mind claims, and the README says so. Evidence, which would weigh claims, is not weighed at all |
| A refused record leaves evidence behind | The first sight of a record's proofs is recorded in one transaction with its listing, and not otherwise (`indexer.test.ts`: "Nothing is kept of what was refused")                                                                                                                                 | None                                                                                                                                                    |

### Repudiation

| Threat                                       | What stops it                                                | Left                                                                      |
| -------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------- |
| The indexer denies an answer it gave         | A `QueryResult` is signed, with the query in it and the time | None                                                                      |
| The indexer denies having forwarded a packet | Each `Forwarded` record is signed, and names the recipient   | The sender is not given the wrappers: it learns how many minds, not which |

### Information disclosure

| Threat                                     | What stops it                                                                                                                                                                                                                                                                         | Left                                                                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| The key leaks                              | It is read from a file that only its owner can read, or the indexer does not start. It goes into the signer and nowhere else: what is wrong with the file is said without anything the file holds, and it is in no log line and no metric (`main.test.ts`: "keeps the key to itself") | The key is in the process's memory, and in a file. An operator who needs more keeps the key in a keystore (M6) |
| A record meant for a few is listed for all | An Offer or an Intent whose `audience` is not `public` is refused (`indexer.test.ts`)                                                                                                                                                                                                 | None                                                                                                           |
| A query, or who asked it, is kept          | Queries are not stored or logged. Metrics are labelled by route and outcome                                                                                                                                                                                                           | The operator's proxy may log requests. A `QueryResult` carries the query, and is the client's to keep or share |
| A sender's packet is read by the indexer   | It is, as by any broker: a packet addressed to a query cannot be sealed to recipients nobody has chosen yet                                                                                                                                                                           | A sender that minds that asks with a packet that says little, and follows up directly                          |

### Denial of service

| Threat                                                 | What stops it                                                                                                                                                                                                                     | Left                                                                                                                                                                                       |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Many submissions, each verified                        | A limit for each address, and a bound on the records in one submission and on its bytes. A signature that verified is remembered (`@oip/core`), so a record submitted again is not verified again                                 | A record seen for the first time costs its signature, as for the resolver: a tenth of a millisecond with OpenSSL doing the arithmetic ([ADR-0016](../adr/0016-native-ed25519.md))          |
| A mind lists without end                               | One profile for a mind; a bound on its Offers and on its Intents; what has expired is taken out every minute                                                                                                                      | A profile may carry 256 capabilities, each listed                                                                                                                                          |
| The indexer is used to flood minds with packets        | A packet is forwarded once. Each sender is limited whatever address it sends from, and each address is limited. Fan-out is ten unless the packet says, and never more than fifty (`broker.test.ts`: "is limited for each sender") | A sender with many minds, each with its own log, is limited only by their number and by the limit for each address. A recipient that wants none of it has no way to say so to this indexer |
| The indexer is made to fetch from places it should not | Deliveries go through `GuardedFetcher`: HTTPS, public addresses, a connection to an address that was checked, no redirect followed, ten seconds, a bounded answer (`fetcher.test.ts`: "a body posted for a stranger")             | None                                                                                                                                                                                       |
| Slow inboxes hold deliveries up                        | A few deliveries are under way at once, each with a time limit. When too many wait, new packets are refused for now (`broker.test.ts`: "is made a few at a time")                                                                 | Deliveries that wait are in memory: a restart loses them. A packet taken and not delivered is not tried again                                                                              |
| A query that costs much                                | A query's text and its number of tags are bounded, and at most a hundred results are read                                                                                                                                         | None measured yet: the load tests of this milestone                                                                                                                                        |

### Elevation of privilege

| Threat                                                   | What stops it                                                                            | Left                                                                                                                                                       |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A location record points the indexer at an inner address | `GuardedFetcher` refuses it. The operator's `FETCH_ALLOW` is for a test network only     | An operator who allows a range allows it for every mind's location record                                                                                  |
| A request reaches SQL                                    | Every statement is prepared with parameters. The one text built for SQL is a list of `?` | None                                                                                                                                                       |
| A record is listed for a mind whose key was removed      | A record is judged under the current-state rule when it is submitted                     | It is not judged again: a profile listed before a key was removed stays listed until the mind brings another. A client verifies what a result names (18.4) |

## Left open

1. **`constraints` and `evidence` are not weighed.** A query that uses either finds nothing.
2. **A text ranking can be gamed**, and nothing here weighs a mind's claims against evidence.
3. **Deliveries are not retried and do not survive a restart.**
4. **A listed record is not judged again** when its author's log changes.
5. **A mind cannot ask not to be forwarded to.**
6. **The key is a file.** A keystore is M6's work.
7. **The indexer does not crawl homes or follow resolver streams** (18.1 lets it). It lists what is submitted.
