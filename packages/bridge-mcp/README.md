# @oip/bridge-mcp

A gateway that makes MCP servers participants of the Open Intelligence Protocol (Layer 0, 2.1).

An MCP server has tools and no keys. The gateway makes a mind for it, a **bridged mind**, and holds that mind's keys. Each tool of the server is a capability of the mind. A mind that wants a tool sends the bridged mind a request, and the gateway calls the tool and answers with the result.

Everything a bridged mind signs is the gateway's word about the server. A verifier sees that from the mind's assurance level, `bridged` (Layer 0, 1.3).

The other direction, a mind for an MCP host such as an assistant, is [`@oip/mcp-server`](../mcp-server).

## Run it

The gateway's mind is made with [`oip init`](../cli/README.md), with a home: its feed is where it attests the minds it makes. Its keys, and the keys of the minds it makes, are opened by `OIP_PASSPHRASE` or by the machine's keychain.

```sh
oip init --kind service --resolver https://resolver.example --host https://host.example
oip-bridge-mcp bridge https://tools.example/mcp
oip-bridge-mcp bridge --stdio files -- npx a-files-server /srv/files
oip-bridge-mcp servers
oip-bridge-mcp serve
```

`bridge` lists the server's tools and makes its mind. `serve` reads each bridged mind's mailbox and answers what is asked of it, until it is told to stop.

### What the program takes

| Setting                  | What it is                                                                                                |
| ------------------------ | --------------------------------------------------------------------------------------------------------- |
| `bridge <url>`           | Lists the tools of the MCP server at a URL and makes its bridged mind, or brings the mind up to the tools |
| `bridge --stdio <label>` | The same for a server that is a command on this machine, given after `--`. The label names it in records  |
| `servers`                | Lists the servers the gateway bridges, each with its mind and its directory                               |
| `serve`                  | Relays for every bridged server                                                                           |
| `--dir <path>`           | The directory of the gateway's own mind. Default: `OIP_DIR`, or `~/.oip`                                  |
| `--name <name>`          | The name the bridged mind's profile gives. Default: what the server calls itself                          |
| `--credentials <file>`   | What the server asks of whoever calls it. The gateway takes a copy into the bridged mind's directory      |
| `--every <seconds>`      | The rest between two readings of the mailboxes. Default: 5                                                |
| `OIP_PASSPHRASE`         | Opens the keys, where the minds are not kept under the machine's keychain                                 |
| `--help`                 | Shows what the program takes                                                                              |
| `--version`              | Prints the version                                                                                        |

A server at a URL is reached over HTTPS. Plain HTTP is for a server on this machine alone: `localhost`, `127.0.0.1` or `[::1]`.

## An MCP server as a mind

`bridge` connects to the server, asks for its tools (`tools/list`), and makes the bridged mind in three steps, each done once:

1. The mind's `Genesis` names the gateway, the protocol (`mcp`) and the server, in an `oip.bridge` block.
2. An entry of the gateway's own feed names that `Genesis`. This is the attestation.
3. The mind's profile carries the block with the reference to that entry, and a capability for each tool.

A capability has the tool's name as its `id`, the tool's description as its `summary`, and the tool's input schema under `ext["oip.mcp"].inputSchema`. A tool without a description is summarised by its title, or else by its name.

A server at a URL is named by that URL, and the profile lists it under `interfaces.mcp`. A server that is a command is named `stdio:<label>`. The command and its arguments stay on the machine: nothing of them is published.

Done again, `bridge` makes no second mind. It publishes a new profile if the tools have changed.

### What a profile does not hold

- A tool whose name is longer than 128 characters, or is the name of a tool before it, is no capability. `bridge` says which.
- A profile has 256 capabilities at most.
- An input schema larger than 16 KiB is left out, and so is any schema once those of one profile fill 128 KiB. The tool is a capability all the same.

## Asking for a tool

A request is a packet with verb `request` whose content is a call (Layer 0, 2.1):

```json
{
  "mediaType": "application/json",
  "body": { "tool": "search", "arguments": { "query": "leases" } }
}
```

The gateway answers with a packet whose `replyTo` is the request's content ID:

| Verb      | When                                                                            | Content                                          |
| --------- | ------------------------------------------------------------------------------- | ------------------------------------------------ |
| `deliver` | The tool returned a result                                                      | The result, as the body of `application/json`    |
| `error`   | The tool failed: the server marked its result as an error                       | That result, in the same form                    |
| `error`   | No result: the content is no call, the server refused it, or the call broke off | Why, as `text/plain`, in the gateway's own words |
| `decline` | The operator's policy does not cover the requester. No tool was called          | That it is so, as `text/plain`                   |

The result is the server's own `tools/call` result, whole: its `content`, and its `structuredContent` if it has one.

A packet with any other verb is read and not answered.

### JSON that a record cannot hold

A record has no number with a fraction (core 1.2). MCP's JSON has. So a body is carried in one of two forms:

- as it is, where a record can hold it;
- as its JSON text, a string, where it cannot.

A requester whose arguments hold a fraction writes the whole body as text:

```json
{ "mediaType": "application/json", "body": "{\"tool\":\"scale\",\"arguments\":{\"by\":0.25}}" }
```

The gateway takes either form. It answers in whichever form the result needs, so a requester reads a `body` that is a string as JSON text. An input schema in a profile follows the same rule.

### Who may ask

The gateway holds the server's credentials, so whoever it calls a tool for uses them. It calls a tool only for a mind its operator has named. The operator's checks are a file in the bridged mind's directory, `policy.json`:

```json
{ "allow": { "search": "anyone", "send_email": ["did:oip:…"], "*": ["did:oip:…"] } }
```

- A tool's own entry decides for it. `*` decides for every tool that has none.
- `"anyone"` opens a tool to every mind. A list opens it to the minds it names.
- A request has the authority of its sender. A request sent for another mind has that mind's authority too, where the sender's proof carries a chain of delegations that lets it send for that mind (Layer 1, 11.2).

`bridge` writes the file with nobody in it. Until the operator names a mind, the gateway calls no tool for anybody. A policy that cannot be read stops the relay for that server: the requests wait, and no tool is called on a guess.

### Credentials

What the server asks of whoever calls it is in `credentials.json`, in the bridged mind's directory, readable by its owner alone:

```json
{ "headers": { "Authorization": "Bearer …" } }
```

for a server at a URL, or `{ "env": { "API_KEY": "…" } }` for a command. `bridge --credentials <file>` takes a copy of a file into place. The gateway refuses a file that others on the machine can read.

Headers go with each request to the server's own origin, and nowhere else: a redirect is an error. A command is started with the operator's variables and without the gateway's own environment, where the passphrase is. The gateway writes no value of a credential anywhere: not in a log, an error or a packet.

### A tool is called at most once

A tool may do something in the world. The gateway writes down that it is about to call before it calls, and what came of the call before it answers.

- A request that waits because the server cannot be reached is tried again by the next pass: nothing was called.
- A pass that stops in the middle of a call is not made good by calling again. The requester gets an `error` that says the gateway does not know whether the tool ran.
- A request has one answer. A pass that stops after the answer was written down sends that answer.

## Receipts

A gateway signs a Receipt about a Commitment the bridged mind entered into, with the digest of the tool's result as evidence (Layer 0, 2.1).

The gateway enters into nothing by itself. Its operator signs for the bridged mind, in the mind's own directory, which is a directory as the `oip` command keeps one:

```sh
oip commit <commitment.json> --dir <the bridged mind's directory>
```

A request names the Commitment it is made under in `context.refs`. The gateway signs a Receipt for the call if:

- the bridged mind holds the Commitment, and owes under it (`debtor`);
- the requester, or the mind the request was sent for, is owed under it (`creditor`);
- the Commitment stands accepted and is not yet settled;
- the tool returned a result that is no error.

The Receipt has outcome `fulfilled`, and a statement of what the gateway saw: that the server returned a result for the tool, for that request (Layer 0, 1.4). Its evidence is one item of kind `hash`, whose `ref` is the request and whose `digest` is of the body that was returned: of the body's canonical form, or of its bytes where it is JSON text. The requester holds that body, so it can check the digest.

The Receipt is published in the bridged mind's feed, and comes with the result as a second part of the `deliver` packet.

## What it does not do

- **It enters into no Commitment by itself.** A stranger's words are not signed for the bridged mind. See [OEP-0006](../../oeps/oep-0006-bridge-clarifications.md), open question 2.
- **It maps tools only.** Resources and prompts, which Layer 0, 2.1 says a gateway MAY map, are not mapped.
- **It answers nothing a tool asks.** The gateway has no person and no model. A tool that asks for input, or to sample from a model, does not get it: the call ends, and the requester is told.
- **It does not sign in to a server.** Credentials are what the operator puts in the file. An OAuth flow is not run.
- **It is no proxy for bytes.** A result larger than 192 KiB is not carried. The requester is told that the tool ran, and how large the result was.

## Limits

| Limit                                 | Value  |
| ------------------------------------- | ------ |
| Capabilities of one profile           | 256    |
| Characters of a tool's name           | 128    |
| Characters of a capability's summary  | 1024   |
| Bytes of one input schema             | 16384  |
| Bytes of all the schemas of a profile | 131072 |
| Bytes of a result a packet carries    | 196608 |
| Depth of JSON text in a request       | 64     |

## Conformance

The tests cite the clauses they test, Layer 0, 2.1 above all (`pnpm spec:coverage`). The connection is tested against a server made with the MCP project's own library, over HTTP and as a command.

## In a program

```ts
import { connector, Gateway, VERSION } from "@oip/bridge-mcp";

const gateway = new Gateway(where, { connect: connector({ version: VERSION }) });
const bridged = await gateway.bridge({ kind: "http", url: "https://tools.example/mcp" });
const did = await gateway.relay(bridged.endpoint);
```

`where` is the machine and the directory of the gateway's own mind, as `@oip/local` has them.

## What it exports

| Export                                                                                 | What it is                                                                                         |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `main`, `Host`, `Reach`, `Serving`, `VERSION`                                          | The program, and what it has of the process it runs in                                             |
| `Gateway`, `GatewayEdges`, `Bridged`, `BridgedNow`, `BridgeError`, `PROTOCOL`          | The gateway: bridges a server, lists what it bridges, and relays once                              |
| `Relay`, `Relayed`, `RelayEdges`, `readCall`, `MAX_RESULT_BYTES`                       | One pass of relaying for one bridged mind, what it did, and how a request is read as a call        |
| `connector`, `Connect`, `Server`, `Target`, `endpointOf`, `Refused`                    | The connection to an MCP server, with the MCP project's client, and how a mind names its server    |
| `capabilitiesOf`, `Mapped`, `ToolCapability`, `MCP_NAMESPACE`                          | The tools a server lists, as capabilities                                                          |
| `MAX_CAPABILITIES`, `MAX_NAME`, `MAX_SUMMARY`, `MAX_SCHEMA_BYTES`, `MAX_SCHEMAS_BYTES` | The limits of that mapping                                                                         |
| `holds`, `carriedJson`, `jsonText`, `readJsonText`, `digestOf`                         | JSON as MCP has it, in a record: as it is or as its text, and the digest a Receipt gives of a body |
| `readPolicy`, `allows`, `Policy`, `POLICY_FILE`, `ANYONE`, `EVERY_TOOL`, `NOBODY`      | The operator's checks: who may call which tool                                                     |
| `readCredentials`, `credentialsIn`, `Credentials`, `CREDENTIALS_FILE`, `NONE`          | What the server asks of whoever calls it, from a file that is its owner's alone                    |

## Notes

- The design, and what was decided against, is in [ADR-0031](../../docs/adr/0031-the-mcp-gateway.md).
- What the gateway defends, and what it leaves open, is in its [threat model](../../docs/threat-models/bridge-mcp.md).
- The gateway's directory holds the keys of every mind it made, and the credentials of every server it bridges. Keep it as you would keep a keystore.
