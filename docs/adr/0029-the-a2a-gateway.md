# ADR-0029: The A2A gateway

**Status:** Accepted, 20 November 2026 (M9). Decision 5 is superseded by [ADR-0034](0034-what-the-gateway-reviews-changed.md), which also adds to this one.

## Context

M9 joins the network to A2A ([BUILD.md](../../BUILD.md), M9; Layer 0, Sections 1 and 3). A2A is a protocol between agents: an agent publishes an Agent Card, a client sends it messages, and the agent answers with a message or with a task that has a state. Version 1.0 is spoken over JSON-RPC, gRPC or HTTP with JSON.

The gateway works in two directions, and they are not mirror images.

- **An A2A agent becomes a participant.** The agent has no keys of this network. The gateway makes a mind for it and holds that mind's keys. Everything such a mind signs is the gateway's word about the agent, and Layer 0, 1.4 limits that word to what the gateway observed.
- **A mind becomes an A2A agent.** An A2A client has no mind either, and here nothing is made for it: the client is whoever sends a request. The gateway's own mind speaks to the served mind for all of them.

Both directions read what strangers send: an Agent Card, an agent's answers, a client's requests.

## Decision

1. **A2A is spoken here, without a library.** The JSON-RPC binding is JSON over HTTP POST, and the gateway uses four of its methods in each direction. The package has no runtime dependency outside this repository. A reader of its own lets the gateway read a stranger's JSON within limits and member by member, on both sides, with the same code (`readMessage`). Two checks stand in for the trust a library would have asked for. The tests hold every result the gateway gives, and every card it serves, against the A2A project's own JSON Schema, which is kept beside them unchanged (`test/a2a/`). And the A2A project's TCK is run against a served mind in CI.

2. **JSON-RPC only, with no streaming and no push notifications.** A mind answers by packet, in its own time: there is nothing to stream. The cards the gateway serves say so, and the methods answer with the errors A2A gives for an agent that does not have them. A client follows a task with `GetTask`.

3. **A bridged mind is made in three steps, each done once.** The mind's `Genesis` names the gateway. An entry of the gateway's feed names that `Genesis`. The mind's profile names both and carries the digest of the card. A run that stops is gone on with by the next, with the same keys: no second mind is made for an agent. The mind is in a directory of its own under the gateway's, named by a digest of the agent's origin and not by the origin.

4. **A signed card must verify. An unsigned card is taken.** A2A lets a card have no signature. Where it has signatures, at least one must verify and none may be wrong, or the agent is not bridged. The keys are the operator's (`--keys`), or the key set the agent serves at its own origin. A key set at the card's own origin says no more than the card it comes with, which arrived over the same TLS, and no less. A key set at another origin is the signer's word about a third party, and gives no key. Signatures are verified with WebCrypto: no primitive is written here.

5. **A Receipt quotes the agent.** The statement of a Receipt is the gateway's sentence around two strings of JSON: the agent's name for the task, and the agent's words. No text an agent chooses can end such a string, so no agent can put words into the gateway's mouth. Control characters and the controls of bidirectional text are written as escapes.

6. **Artifacts are attested, and bytes are not carried.** Each part of an artifact is an evidence item of kind `hash` over the bytes the gateway was shown. A file named by its URL is fetched under the guard, eight of them at most for a task, and is then evidence of kind `uri` and is carried as a reference with its digest (Layer 1, 12.2). A file that cannot be fetched is passed on as a URL, and nothing is said of its bytes. A packet has no place for bytes, and Layer 1 has no convention for them: inline bytes are attested and left out, and the requester is told that they were.

7. **What a pass of the relay does, it does once.** A packet is written down before anything is done with it, and is not sent to the agent again once the agent has answered: an agent may charge for what it does. If a pass stops before the answer, the message is sent again under the same ID, which is the packet's own content ID, so that the agent can tell. A Receipt is written down as soon as it is signed, and a pass that stops after that is finished with the same Receipt. The client's `publishRecord` was changed for this: a record asked for again after a failed call is listed once.

8. **Only the mind a task is for goes on with it.** A reply to a question of the agent's continues the task only if it comes from the mind the task is for. Two requesters that name the same session share no A2A context.

9. **A mind is served only if it asks.** The gateway serves a card for a mind whose current profile lists that card's URL under `interfaces.a2a`. No list of minds is configured, and the gateway cannot be made to speak for a mind that did not sign for it. Each mind has a base URL of its own, `<base>/<the mind's ID>`, with its card under `/.well-known/agent-card.json` there, since A2A has one well-known card for each origin (Layer 0, 3.2).

10. **The gateway's own mind speaks for A2A clients, and says so.** A message is a packet of the gateway's with verb `request`. Its goal says that it carries the words of an A2A client, its thread is the task's ID, and its references name the A2A message. Each A2A context is a session between the gateway and the mind (Layer 0, 3.1).

11. **The gateway keeps the tasks.** A mind has packets, not tasks. The gateway keeps each task's state, artifacts and history, and reads the mind's answers as the table of 3.1 the other way round. A packet with verb `inform` is an answer: a message where no client was told of a task yet, and the end of the task otherwise. A Receipt of the mind's about the request decides, whatever the packet's verb.

12. **A client is nobody, so a name is a key.** The gateway does not authenticate A2A clients. A task's ID and a context's ID are the only handles: whoever knows a task's ID can read and cancel it, and `ListTasks` shows the tasks of a context the client names and nothing else. The IDs the gateway makes are random. A client may choose its own context ID, because A2A lets it and the TCK requires it, and then chooses how hard that ID is to guess.

13. **A client waits a minute at most.** A2A says a client that does not ask to be answered at once waits until the task ends or needs input. A mind may take a day. The gateway answers after a minute with the task as it stands.

14. **`serve` is plain HTTP on this machine.** TLS, and who may connect, belong to a reverse proxy. `--base` is the URL the proxy serves, which is the URL the cards name.

15. **A packet in a message is carried, not translated.** A client that knows the OIP extension may put a whole signed packet in a message (Layer 0, 3.3). The gateway verifies it as the mind it is for will (Layer 1, 12.4, with `receivePacket` of `@oip/net`), and brings it to that mind as it is, sealed, with the client's new `Mind.pass`. It makes no task of it and signs nothing: the packet is its sender's, and the mind answers its sender. A packet that was brought once is not brought again. A packet of a session is refused, since its place in the session is its sender's to keep.

16. **Agents are reached through the guarded fetcher of `@oip/server`.** A card's URL, the URL of an agent's interface, a key set and an artifact's file are all a stranger's choice of where the gateway connects. `GuardedFetcher.post` was given further headers for this, since A2A asks for its version in a header.

## Consequences

- An A2A agent can be found, asked and held to account on the network with nothing changed on its side. What it is held to is a Receipt by the gateway: its weight is the gateway's reputation, and a verifier can see that from the mind's assurance level (`bridged`).
- A mind can be reached by any A2A client with nothing changed on its side either. It needs no A2A code: the mind the TCK is run against only answers packets.
- The gateway is a custodian. It holds the keys of every mind it makes. Its directory is as sensitive as a keystore, and its operator can sign anything as any bridged mind. This is what `bridged` means, and why a native mind is another level.
- An A2A client that learns a task's ID can read that task. The IDs are 122 random bits. An operator that needs more puts authentication in the reverse proxy.
- The relay polls. An agent's task is noticed within one rest of the loop after it ends, five seconds by default.
- Inline bytes do not cross the gateway in either direction. A requester that needs a file asks the agent for a URL.

## Alternatives

- **The A2A project's JavaScript SDK as a dependency.** It would bring its own server and client, and their dependencies, into a package that holds keys. The gateway needs four methods and its own strict reader. The TCK gives the assurance without the dependency.
- **A mind for each A2A client.** It would let a served mind tell clients apart. But a client proves nothing about who it is, so the mind would tell apart only what the gateway made up. One mind that says "an A2A client said this" claims no more than is known.
- **Carrying bytes as base64 in a packet body.** It would work between two gateways of this kind and mean nothing to anyone else. A convention for bytes belongs in Layer 1, and is noted for an OEP.
- **Listing all tasks for a caller.** A2A's `ListTasks` assumes an authenticated caller. Without one, a listing of everything would show every client's tasks to every other.
- **Trusting any `jku`.** A signature that names its own key set anywhere verifies for anyone who can host a file. Only the card's own origin, or the operator's keys, count.
