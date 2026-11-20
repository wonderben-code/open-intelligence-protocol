# Threat model: the client

`@oip/client` is the library an application uses to act as a mind. It runs inside the application, holds the mind's keys through a keystore ([keystore.md](keystore.md)), and talks to resolvers, hosts, indexers and other minds. This model follows STRIDE. [ADR-0021](../adr/0021-the-client.md) has the design it rests on.

## Assets

- **The mind's keys**, in the keystore. The client asks the keystore to sign and to open, and never holds a private key.
- **The mind's single voice.** One identity event for each position of its log, one entry for each position of its feed.
- **What the client tells the application is true**: that a log verified, that a packet was signed by its sender, that a record counts for a mind, that a Commitment is accepted.
- **What the mind says in private**: the content of the packets it seals.
- **The client's memory**: where the feed stands, the number of the last location record, the packets accepted.

## Who can reach it

| Entry point                        | Caller                                   | Trusted with                                                                                                         |
| ---------------------------------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| The client's interface             | The application in the same process      | Everything the mind can do. It is the mind                                                                           |
| A resolver the application named   | Whoever runs it                          | The times it first saw identity events and location records. Not the logs themselves, which are verified             |
| A home of a mind                   | Whoever runs it, and whoever the mind is | Nothing. What it serves is verified, and what it is asked to store is public or sealed                               |
| An indexer the application named   | Whoever runs it                          | Nothing. Its answers are advice                                                                                      |
| Another mind                       | Anyone                                   | Nothing. What it sends is judged, and its content is data                                                            |
| What answers for an alias          | Anyone the alias names                   | Whether it names the mind, and nothing else                                                                          |
| The client's memory                | Whoever can read or write its storage    | Nothing secret is there. Whoever can write it can make the mind repeat itself, and could as well delete its keystore |
| The clock and the randomness given | The application                          | To be right. Tests give their own                                                                                    |

## Threats

### Spoofing

| Threat                                                                             | What stops it                                                                                                                                                                                                           |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A resolver serves another mind's log, or a log that does not verify                | A bundle must be of the mind asked for, and each resolver's copy is verified by itself, every event of it, before it is held. A log that does not verify is refused with the resolver named                             |
| A resolver serves a log it made up for an address                                  | An address is the hash of its genesis, and every event is signed by keys the event before committed to                                                                                                                  |
| A packet claims a sender that did not sign it                                      | `receive` returns a packet only if its sender's own authority signed it, by the sender's log as the resolvers serve it after the packet was first seen                                                                  |
| A packet says it is sent for another mind                                          | It is marked `sentFor` only if its proof carries a chain of delegations from that mind that covers `/oip/send` and holds. Otherwise it is its sender's alone                                                            |
| A host answers a packet with an acknowledgement of its own making                  | An acknowledgement is kept only if the recipient's own authority signed it, for this packet, and for the sealed record that was sent                                                                                    |
| An indexer names a record that is not its author's, or answers for another indexer | Its answer must be signed by a mind the resolvers hold, for the query asked. Each record it names is fetched from its author's homes and verified as its author's                                                       |
| A mind lists a name that is not its own                                            | `aliases` verifies each alias by asking what answers for it. `resolve` presents none as verified                                                                                                                        |
| A delegate signs for a principal beyond what it was granted                        | `countsFor` and `statusOf` are the judges of `@oip/delegation` and `@oip/web`: the chain is checked as given, link by link, and its policies against the record                                                         |
| A mind that is no participant sends in a session                                   | A packet of a session is placed only if its sender is a participant by the `Session` record, which the session's ID is the hash of (Layer 1, 14.3)                                                                      |
| A stolen operational key signs after the mind has removed it                       | The signer's log is fetched afresh after a proof is first seen. A proof first seen after the removal does not count. One seen before it does, as core 9.4 says: `revokeKey` with `compromisedSince` withdraws those too |
| A service at a URL a stranger chose is taken for one the application trusts        | Trust is by what the application named: its resolvers and indexers, by origin. A home is trusted with nothing                                                                                                           |

### Tampering

| Threat                                                                  | What stops it                                                                                                                                                                                                            |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A home serves another record under a content ID                         | The content ID of what is served is worked out, and a home that serves another record has failed                                                                                                                         |
| A home alters, reorders or invents entries of a feed                    | `verifyFeed`: each entry is signed by the mind and names the one before it. Every home is read, and what they serve is judged together                                                                                   |
| A home withholds the end of a feed                                      | Another home that serves it makes up for it. A writer that remembers the feed is not misled. A writer that does not goes by its own last location record, and stops where the homes serve less than it says              |
| A sealed packet is altered on its way                                   | HPKE authenticates it. A record that does not open, or opens to anything but one packet, is refused                                                                                                                      |
| The client's memory is put back to an earlier state                     | The mind may then sign a second entry for a position. A home that holds the first refuses it, and the client reads the feed afresh. Where no home holds it, nothing stops it: keep the memory where the keystore is kept |
| A participant signs two packets for one place of its chain              | Both are told, with their content IDs, and nothing of that chain is returned after (14.3). The client's own chain is written down before a packet leaves, so it does not do so itself                                    |
| A packet of a session arrives out of order, twice, or not at all        | `receive` returns each chain in order and each packet once. One ahead of a gap waits in the mailbox, and a `Resume` asks for what is missing ([ADR-0023](../adr/0023-sessions-in-the-client.md))                         |
| Two processes act as one mind                                           | Every write to the memory names the version it replaces: the second is told before its entry leaves. For identity events the keystore does the same, and a resolver refuses the second event                             |
| A service answers with more than the client can hold, or never finishes | An answer is bounded in bytes and in time before it is read. A feed, a mailbox and an indexer's results are each read up to a stated number                                                                              |
| A redirect sends a request, with its signature, elsewhere               | No redirect is followed. A signature covers the method and the URL it was made for                                                                                                                                       |

### Repudiation

| Threat                                                   | What stops it                                                                                                                                                                            |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A recipient denies having received a packet              | An acknowledgement the recipient signed is returned with the delivery, where its endpoint gives one. A host that holds no key of the recipient gives none: the sender keeps what it sent |
| A principal denies what its delegate committed it to     | The delegate's proof carries the chain of delegations, each signed by its author. A proof that only names them counts only for a verifier that held them                                 |
| A mind denies an entry of its feed, or an identity event | Both are signed, and resolvers witness identity events. The client signs one for each position                                                                                           |

### Information disclosure

| Threat                                                                 | What stops it                                                                                                                                                                   |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A host or a mailbox reads a packet it carries                          | A packet is sealed to the recipient unless the sender says otherwise. It is never sent in the clear because sealing failed                                                      |
| Someone who later gets the recipient's agreement key reads old packets | Nothing: sealing in this revision gives no forward secrecy (Layer 1, 12.6). The recipient rotates its agreement keys                                                            |
| A service learns whom a mind deals with                                | A resolver is asked for each mind whose proof is judged, and a host sees who posts to whom. This revision hides neither. A sealed record names its recipient and not its sender |
| A private key reaches the client's memory, a log line or an error      | The client never holds one. It asks the keystore for signatures and for plaintexts sealed to the mind                                                                           |
| A stranger's words are shown as the client's own                       | A service's `detail` is cut to 256 printable characters and prefixed with the origin that said it. An indexer's `why` is returned as its own                                    |
| An error names a mind the application was asking about, to a log       | A `TransportError` names the origin, never the path                                                                                                                             |
| A packet for a query is read by the indexers it passes                 | It has to be: nobody yet knows whom it is for. The README says so, and such a packet may be delivered for an hour at most                                                       |

### Denial of service

| Threat                                                       | What stops it                                                                                                                                                               |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A resolver, a host or an indexer does not answer, or refuses | Each of several is asked. A call succeeds when enough answered, and says which did not                                                                                      |
| A resolver serves logs whose members name each other         | A mind is fetched once in one resolution, and 64 logs at most are fetched for one mind                                                                                      |
| A home serves a page that says more follows, for ever        | A page that does not go forward ends the reading                                                                                                                            |
| Junk fills a mailbox                                         | A host bounds a mailbox. The client judges each item, removes what is refused, and reads 1000 items in one call                                                             |
| A stranger names the mind in session after session           | The client follows 1,024 sessions at most, each a small document in its memory, and `leaveSession` forgets one. Only a mind whose packets are accepted can open one         |
| A participant asks again and again for a whole chain         | A `Resume` is a packet of the session: signed by a participant, placed in its chain and taken once. Each costs its sender a packet, and the packets go to that sender alone |
| A sender never sends a missing packet again                  | The packets after it wait in the mailbox, which the host bounds, until the mind leaves the session                                                                          |
| A packet is replayed                                         | A packet accepted is remembered, in the client's memory, for as long as it could arrive again, and is returned once                                                         |
| A resolver cannot be asked for a sender's log                | The packet waits in the mailbox, and is judged when the resolver answers. It is not refused for a failure that is not its own                                               |
| One lying resolver among several makes a mind unresolvable   | It does: a log one trusted resolver serves that does not verify fails the resolution, with that resolver named. The application decides whether to go on trusting it        |

### Elevation of privilege

| Threat                                                                         | What stops it                                                                                                                                                         |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The content of a packet is acted on as an instruction                          | The client returns content as data and acts on none of it (Layer 1, 12.5). A record a packet carries is held to be judged, and binds nobody by being carried          |
| A model that drives the client is persuaded to sign                            | Not the client's to stop. Keys stay in the keystore, the control keys under a lock of their own, and an application asks a person before a binding act (Layer 0, 2.2) |
| A host that held a key of the mind keeps publishing for it after the mind left | `moveHomes` with `revoke` removes the key in the event that names the new homes. What the host signs counts no longer, however high the number it gives a record      |
| A delegate passes on more than it was given                                    | `subDelegate` refuses a command the chain does not cover and a later expiry, and a verifier would not count a proof that relied on such a link                        |
| A request the client fetches for a stranger reaches a service inside a network | The client asks only HTTPS and follows no redirect. It does not know which addresses are private: on a server, give it a `fetch` that reaches only public ones        |
| An application takes a status for a fact                                       | A status is computed from the records the mind holds, at a time. The README says another verifier may compute another                                                 |

## Left open

- **A client's memory that is lost or put back** lets the mind repeat itself where no service holds what it said. Keep it where the keystore is kept, and back it up no less often.
- **A memory that is lost breaks the mind's sessions**: it would begin each chain again, which is two packets for one place to everyone else.
- **Who talks to whom is visible** to the resolvers and hosts involved.
- **Sealing gives no forward secrecy.**
- **Records are held in the process only.** An application that does not keep an acknowledgement or a delegation has no evidence of it after it stops.
- **A home learns that its mind has retired only if the mind brings it the event.** If the home could not be reached then, it serves the log as it was until someone brings it more. A host that follows the resolvers for the minds it serves would close this, and none does yet.
