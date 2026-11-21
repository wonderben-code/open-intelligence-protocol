# @oip/bridge-a2a

A gateway between the Open Intelligence Protocol and [A2A](https://a2a-protocol.org/) 1.0 ([Layer 0](../../spec/layer-0-bridge.md), Sections 1 and 3).

It works in two directions.

- **An A2A agent becomes a mind.** The gateway reads the agent's Agent Card, makes a _bridged mind_ for it, and attests that mind in its own feed. Any mind can then find the agent, send it a request, and get back packets and Receipts.
- **A mind becomes an A2A agent.** The gateway serves an Agent Card and an A2A interface for a mind that asks for it. An A2A client sends messages and follows tasks. The mind receives packets and answers with packets.

The gateway is a mind of its own. What it signs for an agent says what the gateway observed, and no more (Layer 0, 1.4).

## Run it

The gateway's mind is made with [`oip init`](../cli/README.md), with a home: its feed is where it attests the minds it makes. Its keys, and the keys of the minds it makes, are opened by `OIP_PASSPHRASE` or by the machine's keychain.

```sh
oip init --kind service --resolver https://resolver.example --host https://host.example
oip-bridge-a2a bridge https://agent.example
oip-bridge-a2a agents
oip-bridge-a2a serve --base https://gateway.example/a2a
```

### What the program takes

| Setting             |                                                                                                                  |
| ------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `bridge <origin>`   | Reads the card of the A2A agent at an HTTPS origin and makes its bridged mind, or brings the mind up to the card |
| `agents`            | Lists the agents the gateway bridges                                                                             |
| `serve`             | Relays for every bridged agent. With `--base`, serves minds as A2A agents as well                                |
| `--dir <path>`      | The directory of the gateway's own mind. Default: `OIP_DIR`, or `~/.oip`                                         |
| `--keys <file>`     | A JSON Web Key Set: keys that may verify the signatures on a card                                                |
| `--base <url>`      | The public URL the A2A interface is reached under: `https://gateway.example/a2a`                                 |
| `--port <port>`     | The port `serve` listens on. Default: 8780                                                                       |
| `--host <address>`  | The address `serve` listens on. Default: `127.0.0.1`                                                             |
| `--every <seconds>` | The rest between two readings of the mailboxes. Default: 5                                                       |
| `OIP_PASSPHRASE`    | Opens the keys, where the minds are not kept under the machine's keychain                                        |
| `--help`            | Shows what the program takes                                                                                     |
| `--version`         | Prints the version                                                                                               |

`serve` speaks plain HTTP on this machine. Put a reverse proxy in front of it for TLS, and give `--base` the URL the proxy serves.

## An A2A agent as a mind

`bridge` fetches `/.well-known/agent-card.json` from the agent's origin and reads it as a stranger's data: within limits, member by member. It then makes three things, each once.

1. A mind for the agent, of kind `service`, whose `Genesis` names the gateway in an `oip.bridge` block.
2. An entry of the gateway's own feed that names that `Genesis`. This is the attestation: nobody but the gateway can sign it.
3. The mind's profile. It carries the block again with a reference to the attestation, a capability for each skill of the card, the card's URL under `interfaces.a2a`, and the digest of the card under `ext["oip.a2a"].cardDigest`.

Anyone can check the result. [`Lookup.assurance`](../client/README.md) answers `bridged` for such a mind, and `claimed` for a mind that only says it is bridged (Layer 0, 1.3).

If the card is signed, a signature must verify before the agent is bridged. The keys are the operator's own (`--keys`), or the key set the agent serves at its own origin. A key set at another origin gives no key. For a name the operator has a key of, the operator's key decides, and no key the agent serves under that name is asked for. `--keys` does not ask that a card be signed by the operator's keys: a card signed by a key the agent serves itself is taken too, and says no more than the card. At most eight signatures of a card are verified. A card with no signature is taken: A2A lets a card have none, and the gateway then says only that it read the card over HTTPS.

### What the relay does

`serve` reads each bridged mind's mailbox and speaks A2A to its agent. The mapping is the table of Layer 0, 3.1.

| On the network                            | To the agent, and back                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------- |
| A packet with verb `request`              | `SendMessage`. The message's ID is the packet's content ID                            |
| A session                                 | One A2A context                                                                       |
| A task that is `completed`                | A Receipt with outcome `fulfilled`, in a packet with verb `deliver` and the artifacts |
| A task that is `failed`                   | A Receipt with outcome `broken`, in a packet with verb `inform`                       |
| A task that is `canceled`                 | A Receipt with outcome `cancelled`, in a packet with verb `inform`                    |
| A task that is `rejected`                 | A packet with verb `decline`                                                          |
| A task that needs input, or authorisation | A packet with verb `request` to the requester. The reply goes on with the task        |
| An answer that is a message, and no task  | A packet with verb `inform`                                                           |
| An error from the agent                   | A packet with verb `error`                                                            |

A Receipt is signed by the bridged mind and published on its feed. Its statement reads, for example:

```text
The gateway observed the A2A agent at https://agent.example report task "7f3c" as completed.
```

The agent's name for the task and the agent's own words are quoted as strings of JSON, so that neither can be read as words of the gateway. Each part of an artifact is an evidence item of kind `hash`. A file the agent names by its URL is fetched, under the gateway's guard, and is an evidence item of kind `uri` with the digest of the bytes that were there.

What a pass does, it does once. A packet is written down before anything is done with it, and is not sent to the agent again once the agent has answered. A Receipt is written down as soon as it is signed, and a pass that stops after that is finished with the same Receipt. Only the mind a task is for can go on with it.

## A mind as an A2A agent

A mind asks to be served by listing its card in its profile:

```json
{
  "interfaces": { "a2a": "https://gateway.example/a2a/<the mind's ID>/.well-known/agent-card.json" }
}
```

The mind's ID is its address without `did:oip:`. The gateway serves no mind that has not asked. For a mind that has, it serves two things under `https://gateway.example/a2a/<the mind's ID>`:

- the Agent Card, made of the mind's profile: each capability is a skill, and the gateway supplies the version, the interface and the media types (Layer 0, 3.2);
- the JSON-RPC binding of A2A 1.0: `SendMessage`, `GetTask`, `ListTasks` and `CancelTask`.

An A2A client has no mind, so the gateway's own mind speaks for it. Each message is a packet of the gateway's with verb `request`, in a session the gateway opens with the mind for each A2A context. The packet's goal says that it carries the words of an A2A client, its thread is the task's ID, and its references name the A2A message. The mind answers as it answers any packet.

| The mind answers with                  | The A2A client sees                                                 |
| -------------------------------------- | ------------------------------------------------------------------- |
| A packet with verb `deliver`           | The task `completed`, with the content as an artifact               |
| A packet with verb `decline`           | The task `rejected`                                                 |
| A packet with verb `request`           | The task waiting for input. The client's next message answers it    |
| A packet with verb `error`             | The task `failed`                                                   |
| A packet with verb `ack`               | The task at work                                                    |
| A packet with verb `inform`            | A message, and no task. If a task was told of already, it completes |
| A Receipt of its own about the request | The task `completed`, `failed` or `canceled`, as the outcome says   |

`CancelTask` tells the mind with a Receipt of the gateway's, with outcome `cancelled`, that says what the gateway observed.

A client waits for the mind for a minute at most. After that it is given the task as it stands, and asks again with `GetTask`.

### What a client can see

The gateway does not know who a client is. So the names it gives are the only keys: a client that knows a task's ID can read and cancel that task, and `ListTasks` shows the tasks of a context the client names and no others. Task and context IDs that the gateway makes are random. A client that chooses its own context ID chooses how hard it is to guess.

## The OIP extension for A2A

An agent that declares the extension `https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/layer-0-bridge.md#a2a-extension` is sent the whole packet, signed, as a data part of media type `application/oip+json`, beside the plain parts (Layer 0, 3.3). Such an agent can verify who asked for itself. Every card the gateway serves for a mind declares the extension.

It works the other way too. A client that has a mind of its own may put a whole signed packet in a message to a served mind, as a data part of the same media type. The gateway then translates nothing. It verifies the packet as the mind it is for will verify it (Layer 1, 12.4), brings it to that mind as it is, sealed, and answers the client with a message that says so. No task comes of it: the packet is its sender's, and the mind answers its sender, as a packet. A packet that does not verify, is not for the mind, or is out of its time is refused, and the client is told why.

## What it does not do

- It does not stream and sends no push notifications. The cards it serves say so, and those methods answer with the errors A2A gives for them.
- It speaks the JSON-RPC binding only: no gRPC, and no HTTP+JSON.
- It does not carry bytes. A packet has no place for them: bytes an agent returns are attested by their digest in the Receipt and left out of the packet, and bytes a client sends are taken only if they are a text.
- It does not authenticate A2A clients. See [What a client can see](#what-a-client-can-see).

## Limits

| Limit                                         |          |
| --------------------------------------------- | -------- |
| An Agent Card                                 | 256 KiB  |
| An agent's content carried in one packet      | 256 KiB  |
| Files of one task fetched for their digest    | 8        |
| Tasks of one agent followed at a time         | 256      |
| How long a task that does not end is followed | 30 days  |
| A request of an A2A client                    | 1 MiB    |
| How long a client waits for a mind            | 1 minute |
| How long a task that has ended is kept        | 30 days  |

## Conformance

`pnpm a2a:tck` runs the A2A project's own [TCK](https://github.com/a2aproject/a2a-tck) against a mind served by the gateway, with a real resolver, host and indexer behind it. The mind that is tested is an ordinary OIP mind that answers packets: see [`test/tck/sut.ts`](test/tck/sut.ts).

## In a program

```ts
import { Front, A2aServer, Gateway, listen } from "@oip/bridge-a2a";
```

The program is made of these, and each can be used alone. A `Gateway` bridges agents and relays. A `Front` holds the tasks of the minds that are served, an `A2aServer` is the JSON-RPC binding as a function from a request to an answer, and `listen` puts both on a port.

## What it exports

| Export                                                                                                                                                           |                                                                                    |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `main`, `Host`, `Reach`, `Serving`, `VERSION`                                                                                                                    | The program `oip-bridge-a2a`                                                       |
| `Gateway`, `GatewayEdges`, `Bridged`, `BridgeError`, `PROTOCOL`                                                                                                  | Bridges A2A agents, and relays between each bridged mind and its agent             |
| `Relayed`, `MAX_OPEN_TASKS`, `MAX_FOLLOWED_SECONDS`, `MAX_CARRIED_BYTES`, `MAX_FETCHED`                                                                          | What one pass of the relay did, and the relay's limits                             |
| `readCard`, `ReadCard`, `AgentCard`, `AgentInterface`, `AgentSkill`, `AgentExtension`, `CardSignature`, `interfaceOf`, `supports`                                | Reads an Agent Card as a stranger's data                                           |
| `CARD_PATH`, `A2A_VERSION`, `MAX_CARD_BYTES`, `MAX_CARD_ITEMS`, `MAX_CARD_TEXT`                                                                                  | Where a card is, the version of A2A that is spoken, and how much of a card is read |
| `verifySignatures`, `CardSignatures`, `KeySource`, `PublicJwk`                                                                                                   | Verifies the signatures on a card (A2A, 8.4)                                       |
| `capabilitiesOf`, `cardFor`, `Served`, `saidOf`, `Said`, `isTerminal`, `TASK_STATES`, `TaskState`, `OIP_EXTENSION`, `OIP_MEDIA_TYPE`, `TAG_NAMESPACE`            | The mapping of Layer 0, 3.1 and 3.2, as functions                                  |
| `sendMessage`, `getTask`, `cancelTask`, `readMessage`, `A2aError`, `Malformed`, `Agent`, `Ask`, `Get`, `Answered`                                                | Speaks A2A to an agent, and reads what a stranger answers                          |
| `A2aMessage`, `Part`, `Task`, `Artifact`, `MAX_PARTS`, `MAX_ARTIFACTS`, `MAX_ID`                                                                                 | The things of A2A as far as the gateway reads them, and how much of them it reads  |
| `Front`, `FrontOptions`, `ServedMind`, `Taking`, `Held`, `Asked`, `Page`, `MAX_KEPT_SECONDS`, `MAX_UNANNOUNCED_SECONDS`, `MAX_IDLE_CONTEXT_SECONDS`, `MAX_TASKS` | Minds as A2A agents: the tasks the gateway keeps for them                          |
| `A2aServer`, `Asking`, `Answer`, `Fault`, `MAX_REQUEST_BYTES`                                                                                                    | The JSON-RPC binding of A2A 1.0, as a function from a request to an answer         |
| `listen`, `Listening`, `ServedInterface`                                                                                                                         | The interface on a port, and the reading of the gateway's mailbox                  |
