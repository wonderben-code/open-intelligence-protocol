# Threat model: the gateway for MCP servers

`@oip/bridge-mcp` makes MCP servers participants of the network ([ADR-0031](../adr/0031-the-mcp-gateway.md)). It is a layer over the client ([client.md](client.md)), the keystore ([keystore.md](keystore.md)) and a mind's directory ([cli.md](cli.md)), and everything in those models holds here. It shares the custody of bridged minds with the A2A gateway ([bridge-a2a.md](bridge-a2a.md)). This model is about what this gateway adds.

The gateway is a custodian twice over. It holds the keys of every mind it makes for a server, and it holds what each server asks of whoever calls it. A mind on the network asks it to call a tool, and a tool acts: the call spends the operator's credential, and may do something that cannot be undone.

## Assets

- **The keys of every bridged mind**, each in a directory under the gateway's, and the gateway's own.
- **The credentials of every bridged server**: a header or a variable that the server takes for the operator.
- **The use of each tool**: who may have it called, and how often a call is made.
- **What a Receipt of a bridged mind says**: that the gateway observed the server return a result.
- **What a bridged mind's profile says**: which server it stands for, and what the server can do.
- **The operator's machine**: for a server that is a command, the command, its arguments and its files.

## Who can reach it

| Entry point                                       | Caller                               | Trusted with                                                                                                   |
| ------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| The arguments and environment of `oip-bridge-mcp` | The operator                         | Which servers are bridged, where each is, the command that is one, the passphrase                              |
| `policy.json`, in a bridged mind's directory      | The operator                         | Who may call which tool                                                                                        |
| `credentials.json`, in a bridged mind's directory | The operator                         | What the server is sent with each request, or started with                                                     |
| A packet in a bridged mind's mailbox              | Any mind                             | Nothing, unless the policy names it, or names the mind it was sent for. Then: one call of one tool it may have |
| The list of a server's tools                      | The server, or whoever answers there | Naming capabilities of the bridged mind. Read member by member, within limits                                  |
| The result of a tool, and a server's refusal      | The server                           | Being carried to the requester as data. Its words are quoted, and are never the gateway's                      |
| A redirect, or a URL in what a server answers     | The server                           | Nothing. The gateway goes to the server's own origin alone                                                     |
| A Commitment in the bridged mind's records        | The operator, who signed it          | Being what a Receipt is about, if a request names it                                                           |
| The gateway's directory                           | Whoever can write it                 | Everything: it holds the keys, the credentials, the policies, and what was written down of each request        |

## Threats

### Spoofing

| Threat                                                                     | What stops it                                                                                                                                                                                                       |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A mind says a gateway bridges it, and no gateway does                      | Its level is `claimed` until an entry of the gateway's own feed names its `Genesis` (`bridged.test.ts` in `@oip/local`; `gateway.test.ts`: is found `bridged`)                                                      |
| A requester says it asks for a mind the policy names                       | A packet counts as sent for a mind only where its sender's proof carries a chain of delegations from that mind that covers sending (`relay.test.ts`: cover a requester by delegation)                               |
| A server's refusal is worded so that it reads as the gateway's finding     | The server's words are quoted as a string of JSON, which no text can end early, with the controls of bidirectional text escaped (`relay.test.ts`: is answered with `error` and why)                                 |
| A requester names a tool so that the gateway's sentence says more          | The tool's name is quoted the same way, in a refusal and in the statement of a Receipt                                                                                                                              |
| A server lists a tool whose name or schema makes the profile say another's | A name is a capability's `id` and nothing else. A schema is under the capability's own `oip.mcp` block, and is data (`tools.test.ts`)                                                                               |
| A requester names a Commitment that is another's, to get a Receipt         | A Receipt is signed only where the bridged mind owes under the Commitment and the requester is owed under it (`relay.test.ts`: gets no Receipt … where the request names no promise of the mind's to its requester) |

### Tampering

| Threat                                                         | What stops it                                                                                                                                                                     |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A result is changed between the server and the requester       | The requester receives it in a packet the bridged mind signed and sealed. Under a Commitment, the Receipt holds the digest of the body the requester received                     |
| A request's arguments are changed on the way to the server     | The call is made with the arguments of a packet that verified as its sender's (Layer 1, 12.4), over the connection to the server's own origin                                     |
| A file under the gateway's directory is named by a stranger    | What the gateway keeps of a request is in files named by a digest of the packet's ID. A server's directory is named by a digest of its endpoint (`store.test.ts` in `@oip/local`) |
| A record of a server is moved under another server's directory | A record counts only in the directory its own endpoint names (`gateway.test.ts`: takes for a server only what its own directory records of it)                                    |
| The operator's header is made to carry another                 | A header's value is one line of visible characters, and a header that frames a request or is MCP's own is refused (`policy.test.ts`: are refused where they are none)             |

### Repudiation

| Threat                                              | What stops it                                                                                                                               |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| A gateway denies an answer of a mind it made        | The answer is a packet signed by the bridged mind, and the gateway's feed names that mind's `Genesis`                                       |
| A gateway denies a Receipt                          | The Receipt is signed by the bridged mind and published in its feed (`relay.test.ts`: gets a Receipt for the call a request makes under it) |
| A pass that stops signs a second Receipt for a call | A Receipt is written down as soon as it is signed, and the next pass finishes with that one (`relay.test.ts`: signs one Receipt for a call) |
| A server denies what it returned                    | Not stopped: an MCP server signs nothing. The Receipt is the gateway's word, and says so. See [Left open](#left-open)                       |
| A requester denies a request                        | The request is a packet the requester signed. The gateway keeps the packets it received                                                     |

### Information disclosure

| Threat                                                         | What stops it                                                                                                                                                                                                    |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A credential is read by another user of the machine            | The file is taken only if it is its owner's alone, and the gateway's copy is written so (`gateway.test.ts`: holds the credentials the server asks for)                                                           |
| A credential appears in a log, an error or a packet            | The gateway writes no value of the file anywhere. An error about the file names a member and quotes nothing, not what a parser says of the text either (`policy.test.ts`: in words that hold no value of theirs) |
| A credential is sent to a host the server names                | Requests go to the server's own origin alone, and a redirect is an error (`connect.test.ts`: makes no request of another origin; reaches one origin)                                                             |
| A command reads what opens the gateway's keys                  | A command is started without the gateway's environment: it has the variables any command needs, and the operator's (`connect.test.ts`: without the gateway's own)                                                |
| The command, or a path on the operator's machine, is published | A server that is a command is named by the operator's label. Nothing of the command is in a record (`gateway.test.ts`: publishes no command)                                                                     |
| A mind that may not call a tool learns what the tool returns   | No call is made for it, and it is told only that the tool is not open to it (`relay.test.ts`: keep the gateway from calling a tool)                                                                              |
| A Receipt publishes who called which tool                      | A Receipt is signed only under a Commitment the request names. A plain request leaves no public record                                                                                                           |
| A result goes to more minds than asked for it                  | An answer goes to the requester. A request made in a session is answered in the session, to its participants, as the requester chose (Layer 1, 14.3)                                                             |

### Denial of service

| Threat                                              | What stops it                                                                                                                                                      |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A server lists tools without end                    | 32 pages and 4,096 tools are read, and 256 are capabilities (`connect.test.ts`: is read within bounds; `tools.test.ts`)                                            |
| A schema, a name or a description is very large     | A name over 128 characters is no capability, a summary is cut at 1,024, and schemas are carried within 16 KiB each and 128 KiB together (`tools.test.ts`)          |
| A result is very large                              | A result over 192 KiB is not carried. The requester is told that the tool ran (`relay.test.ts`: more than a packet carries)                                        |
| A request's JSON text nests without end             | Text that nests more than 64 deep is not parsed (`json.test.ts`: is not read where it is no JSON, or nests deeper than a record)                                   |
| A tool never returns                                | The client's timeout ends the call. The requester is told that the call broke off, and it is not made again (`relay.test.ts`: where it did not end as a call does) |
| One packet that cannot be dealt with stops the rest | What stops one packet is noted, and the pass goes on (`relay.test.ts`: is noted as not made)                                                                       |
| Minds the policy names ask without end              | Not stopped here. A pass makes its calls one after another. An operator that opens a tool to anyone opens it to this. See [Left open](#left-open)                  |
| Minds the policy does not name ask without end      | Each is answered with one small packet, and no tool is called. Mailboxes are the host's to limit ([host.md](host.md))                                              |

### Elevation of privilege

| Threat                                                          | What stops it                                                                                                                                                                                   |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A tool is called for a mind the operator did not name           | The policy is read before every pass, names nobody until the operator writes it, and decides tool by tool (`relay.test.ts`: the operator's checks; `gateway.test.ts`: opens no tool to anybody) |
| A policy that cannot be read is taken for an open one           | It stops the relay for that server. Nothing is called on a guess (`relay.test.ts`: are read before any tool is called)                                                                          |
| A tool named like a member of every object finds an entry       | Only an entry the operator wrote is one (`policy.test.ts`: find no entry that the operator did not write)                                                                                       |
| A call is made twice, and the tool acts twice                   | The gateway writes down that it is calling before it calls, and does not call again for that packet (`relay.test.ts`: is not made a second time)                                                |
| A packet's content makes the gateway do more than call one tool | A request is read as one call, and nothing in it is a command to the gateway (Layer 1, 12.5). Two calls in one packet are none (`relay.test.ts`: the form of a call)                            |
| A result makes the gateway act                                  | A result is carried, and is read by nobody here but for its `isError`                                                                                                                           |
| A tool asks the gateway for input, or to sample from a model    | The gateway declares neither. The call ends                                                                                                                                                     |
| A Receipt claims more than the gateway saw                      | Its statement is one sentence of the gateway's, about what the server returned (Layer 0, 1.4). It is signed for a result, and never for a failure                                               |
| A stranger makes the bridged mind promise something             | The gateway co-signs nothing. A Commitment counts only if the bridged mind holds it with its own proof, which its operator made                                                                 |
| A file in the gateway's directory names a target that is none   | A target is checked again when the gateway connects: HTTPS, or this machine (`connect.test.ts`: makes no request of another origin, whatever it is told)                                        |

## Left open

- **The gateway can sign anything as any mind it made, and can use every credential it holds.** That is what custody means. Whoever relies on a bridged mind relies on its gateway, and an operator relies on the machine the gateway runs on.
- **A command is the operator's program, run as the gateway's user.** It can read what that user can read, the gateway's directory included. Run a server you would not trust with that as another user, or bridge it over HTTP.
- **A Receipt is the gateway's word, not the server's.** An MCP server signs nothing. If a server returns a result that is wrong, the Receipt says truly that a result was returned.
- **The gateway cannot tell whether a result fulfils a promise.** It signs `fulfilled` for a result that is no error, under a Commitment its operator signed. An operator signs only a promise that one result of the tool keeps.
- **A call that broke off may have run.** The requester is told so. Whether to ask again is the requester's to decide.
- **The gateway does not limit how often a named mind asks.** A tool that costs money is opened to minds the operator trusts with the bill.
- **A tool's description and schema are a stranger's text in a public profile.** A model that reads a profile reads them as data (Layer 1, 12.5), as it reads any profile.
- **What the server sees of a requester is the arguments.** The gateway does not tell the server who asked.
