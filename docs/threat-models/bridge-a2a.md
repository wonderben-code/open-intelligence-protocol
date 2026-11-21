# Threat model: the A2A gateway

`@oip/bridge-a2a` joins the network to A2A in two directions ([ADR-0029](../adr/0029-the-a2a-gateway.md)). It is a layer over the client ([client.md](client.md)), the keystore ([keystore.md](keystore.md)) and a mind's directory ([cli.md](cli.md)), and everything in those models holds here. This model is about what the gateway adds.

The gateway is a custodian and a translator. It holds the keys of every mind it makes for an A2A agent, and what those minds sign is the gateway's word about a system it does not control. It also speaks to minds for A2A clients, which are whoever sends a request. On both sides it reads what a stranger wrote and writes something in its own name.

## Assets

- **The gateway's own keys**, and its feed: an entry there is what makes a mind `bridged`.
- **The keys of every bridged mind**, each in a directory under the gateway's.
- **What a Receipt of a bridged mind says**: that the gateway observed an agent report a task as done, failed or cancelled.
- **What a bridged mind's profile says**: which agent it stands for, and the digest of the card that was read.
- **A task of a served mind**: what an A2A client asked, what the mind answered, and who may read it.
- **The use of the gateway's address**: which hosts it connects to, at a stranger's word.
- **A served mind's own name**: nobody speaks A2A as a mind that did not ask for it.

## Who can reach it

| Entry point                                       | Caller                                       | Trusted with                                                                                                |
| ------------------------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| The arguments and environment of `oip-bridge-a2a` | The operator                                 | Which agents are bridged, which keys verify a card, the URL the interface is served under, the passphrase   |
| An Agent Card, and the key set an agent serves    | The agent's origin, or whoever answers there | Nothing. Read within limits and member by member. Its skills become capabilities of the bridged mind        |
| An agent's answer to `SendMessage` and `GetTask`  | The agent                                    | Saying what became of its own task. Its words are quoted, and its files are attested and not believed       |
| A packet in a bridged mind's mailbox              | Any mind                                     | Being passed on to the agent if its verb is `request`. Going on with a task only if the task is that mind's |
| A request at the A2A interface                    | Anyone who can reach the port                | Sending a message to a served mind. Reading and cancelling a task whose ID it knows                         |
| A packet in the gateway's own mailbox             | Any mind                                     | Nothing, unless it is from the mind a task is asked of, and answers that task                               |
| A packet carried in an A2A message (Layer 0, 3.3) | Anyone                                       | Being brought to the served mind, if it verifies as a packet for that mind (Layer 1, 12.4)                  |
| A served mind's profile                           | The mind                                     | Asking to be served: listing the card's URL under `interfaces.a2a`                                          |
| The gateway's directory                           | Whoever can write it                         | Everything: it holds the keys, the tasks, and what waits                                                    |

## Threats

### Spoofing

| Threat                                                                                         | What stops it                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A mind says a gateway bridges it, and no gateway does                                          | Its level is `claimed` until an entry of the gateway's own feed names its `Genesis` (`assurance.ts` in `@oip/web`; vectors `bridge-*`)                                                                                                |
| An agent names its task, or words its answer, so that a Receipt reads as the gateway's finding | The statement quotes both as strings of JSON, which no text can end early, with control characters and the controls of bidirectional text escaped (`relay.test.ts`: an agent's name for a task and its words are never the gateway's) |
| An agent returns a part it calls an OIP record                                                 | A bridged agent signs nothing. The part is carried as JSON, with media type `application/json` (`relay.test.ts`: what it calls a record is none)                                                                                      |
| A card is signed with a key set its signer hosts somewhere                                     | A key set counts only at the card's own origin, or from the operator's file (`main.test.ts`: none that another origin serves)                                                                                                         |
| A signed card is altered                                                                       | A signature that does not verify refuses the card. One that names an algorithm the gateway does not take refuses it too (`signature.test.ts`)                                                                                         |
| A mind answers in a task that is asked of another mind                                         | An answer counts only from the mind the task is asked of (`server.test.ts`: is answered in by the mind it is asked of alone)                                                                                                          |
| Another mind replies to a question an agent put to a requester                                 | A reply goes on with a task only if it is from the mind the task is for (`relay.test.ts`: another mind that answers does not go on with a task that is not its own)                                                                   |
| A client sends a packet it says is someone's                                                   | The packet is verified by its sender's log before it is brought, and the mind verifies it again (`server.test.ts`: is not brought where it does not verify)                                                                           |
| A gateway serves an A2A card for a mind that never asked                                       | A mind is served only while its own signed profile lists the card's URL (`server.test.ts`: is served for no mind that does not list it)                                                                                               |
| A served mind takes a client's words for the gateway's                                         | The packet's goal says that it carries the words of an A2A client, and its references name the A2A message (`server.test.ts`: the gateway says whose words it carries)                                                                |

### Tampering

| Threat                                                     | What stops it                                                                                                                                             |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| An agent changes a file after the gateway attested it      | The evidence item holds the digest of the bytes the gateway fetched. A verifier that fetches the file checks it (Layer 2, Section 9)                      |
| A card changes after the mind was bridged                  | The profile records the digest of the card that was read. `bridge` done again brings the profile up to the new card, with its digest                      |
| A task's name is used as a file name                       | What the gateway keeps is in files named by a digest of the key, never by the key (`store.test.ts` in `@oip/local`: a key is any text a stranger chooses) |
| A header of a request to an agent is made to carry another | The fetcher refuses a header value with a line end, and any header that frames the request or says where it goes (`fetcher.test.ts` in `@oip/server`)     |

### Repudiation

| Threat                                                         | What stops it                                                                                                                                                  |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A gateway denies a Receipt of a mind it made                   | The Receipt is signed by the bridged mind and published on its feed, and the gateway's feed names that mind's `Genesis`. Both are public and signed            |
| A pass that stops signs a second, different Receipt for a task | A Receipt is written down as soon as it is signed, and the next pass finishes with that one (`relay.test.ts`: signs one Receipt for a task, whatever stops it) |
| An agent denies what it reported                               | Not stopped: an A2A agent signs nothing. The Receipt is the gateway's word, and says so. See [Left open](#left-open)                                           |
| A client denies a cancellation                                 | Not stopped: a client is nobody. The gateway's Receipt says that an A2A client cancelled, which is all that is known                                           |

### Information disclosure

| Threat                                                           | What stops it                                                                                                                                                                      |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A client lists every task of a served mind                       | `ListTasks` shows the tasks of a context the client names, and nothing where it names none (`server.test.ts`: shows a client that names no context nothing)                        |
| A client reads another mind's task through this mind's interface | A task is found only under the mind it is asked of (`front.ts`: `get`)                                                                                                             |
| A client guesses a task's ID                                     | The IDs are random UUIDs, of 122 random bits                                                                                                                                       |
| An error tells a client what is inside the gateway               | A failure that is not the client's is answered as an internal error with no detail, and logged (`server.test.ts`: says nothing of its inside)                                      |
| A host on the way reads what a client sent a mind                | Every packet is sealed to its recipient, a packet the gateway only carries too (`messages.test.ts` in `@oip/client`: is passed on by a courier, sealed)                            |
| The gateway is made to fetch from inside its own network         | Cards, key sets, interfaces and files are reached through the guarded fetcher: HTTPS only, public addresses only, the address checked again on the connection ([host.md](host.md)) |

### Denial of service

| Threat                                              | What stops it                                                                                                                                                                     |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A card, an answer or a request is very large        | A card is read to 256 KiB, an answer to the fetcher's limit, and a request to 1 MiB and then let go (`card.test.ts`; `listen.test.ts`)                                            |
| An answer holds a great many parts or artifacts     | 32 parts and 64 artifacts are read. More is no answer (`a2a.test.ts`)                                                                                                             |
| An agent's content does not fit a packet            | A quarter of a megabyte is carried. The rest is attested and left out, and the requester is told (`relay.test.ts`: is carried as far as a packet has room)                        |
| An agent names many files to fetch                  | Eight are fetched for a task (`relay.test.ts`)                                                                                                                                    |
| An agent never ends its tasks                       | 256 tasks of one agent are followed at a time, each for thirty days. Beyond that the requester is told (`relay.test.ts`)                                                          |
| One packet that cannot be dealt with stops the rest | What stops one piece of a pass is noted, and the pass goes on (`relay.test.ts`: a pass that cannot do all of its work)                                                            |
| A mind never answers, and a client waits            | A client waits a minute at most, and is given the task as it stands (`server.test.ts`)                                                                                            |
| Clients make tasks without end                      | Not stopped here. A task that ended is forgotten after thirty days, and one no client was told of after a day. Put a rate limit in the reverse proxy. See [Left open](#left-open) |

### Elevation of privilege

| Threat                                                        | What stops it                                                                                                                                                         |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| An agent's text makes a bridged mind sign more than a Receipt | The relay signs Receipts and packets, and nothing else. No answer of an agent is read as a command                                                                    |
| A Receipt claims more than the gateway saw                    | Its statement is one sentence of the gateway's, about what the agent reported (Layer 0, 1.4). The agent's words are quoted beside it, as the agent's                  |
| A packet a client hands over is taken for the gateway's       | The gateway is its courier. The packet is its sender's, and nothing of it is signed by the gateway (`server.test.ts`: its sender's own, and no task of the gateway's) |
| A mind's answer makes the gateway act beyond a task           | An answer changes the state of the task it answers, and nothing else                                                                                                  |
| A Receipt in a mind's packet ends a task it is not about      | Only a Receipt by the mind the task is asked of, about the request that began the task, ends it (`server.test.ts`: is not answered for a Receipt that is another's)   |

## Left open

- **The gateway can sign anything as any mind it made.** That is what custody means, and what `bridged` tells a verifier. Whoever relies on a bridged mind relies on its gateway. Keep the gateway's directory as you would keep a keystore.
- **An unsigned card is taken on the word of TLS.** A2A lets a card have no signature. The profile then says which card was read, by its digest, and no more.
- **A key set at the agent's own origin proves no more than the card.** It shows that the card and the keys came from one place, not who is behind that place.
- **A Receipt is the gateway's word, not the agent's.** An A2A agent signs nothing. If an agent reports a task as completed and has not done it, the Receipt says truly what was reported.
- **A2A clients are not authenticated.** A task's ID is its key. An operator that needs to know its clients puts authentication in the reverse proxy.
- **A client can make a served mind receive a request from the gateway at any time.** The mind asked to be served, and treats the content as data (Layer 1, 12.5). A rate limit belongs in the reverse proxy.
- **Fetching a file an agent names touches that URL once.** A link that works once, or that does something when fetched, is used up or set off by the gateway's fetch.
- **What the gateway keeps grows with use.** Packets that were read are kept, as the command keeps them. Tasks are forgotten on a schedule, packets are not.
