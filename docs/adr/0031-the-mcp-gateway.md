# ADR-0031: The gateway for MCP servers

**Status:** Accepted, 21 November 2026 (M9).

## Context

Layer 0, 2.1 says how an MCP server becomes a participant: a gateway maps its tools to capabilities, turns a request packet into a `tools/call`, returns the result, signs a Receipt about a Commitment it entered into, holds the server's credentials, and calls nothing for a requester whose authority does not cover it.

[BUILD.md](../../BUILD.md) names no package for this. The conformance plan gives Layer 0 to M9, and a clause without an implementation is a clause without a test. So M9 builds `@oip/bridge-mcp` beside the A2A gateway ([ADR-0029](0029-the-a2a-gateway.md)).

The other direction, a mind for an MCP host, is `@oip/mcp-server` ([ADR-0028](0028-the-mcp-server.md)).

A gateway for MCP servers differs from one for A2A agents in three ways that decide its design.

- **A tool acts.** An A2A agent is sent a message and decides what to do. A tool is called and does it: sends the email, makes the payment. A call made twice is a thing done twice.
- **The gateway holds credentials.** An MCP server often wants a key. Whoever the gateway calls a tool for uses the operator's key.
- **The JSON is not a record's.** A tool's schema, its arguments and its result are JSON as MCP has it, with fractions. A record has none.

Writing it found three gaps in 2.1, which [OEP-0006](../../oeps/oep-0006-bridge-clarifications.md) (items 4 to 6) settles.

## Decision

1. **MCP is spoken by the MCP project's own client.** `@modelcontextprotocol/client`, pinned to the exact version `@oip/mcp-server` pins its counterpart to. MCP has two eras, with a handshake and without, two transports, and a version negotiation between them. The client speaks all of it, and the A2A gateway's reason for writing its own reader does not hold here: A2A's JSON-RPC binding is four methods over POST. The library is reached through one small interface (`Connect`, `Server`), which is what the tests replace.

2. **The gateway is a client that is nobody.** It declares no capability: no person to ask, no model to lend, no files to show. A tool that asks for input is not answered. The call ends, and the requester is told.

3. **A server is the operator's choice, and its answers are its own.** The operator names the URL, so the gateway does not guard against the operator's own network as the A2A gateway guards against a stranger's card. What the server answers is another matter. Each request goes to the server's own origin and no other, and a redirect is an error, so the operator's headers go nowhere the operator did not send them. Plain HTTP reaches this machine alone.

4. **A server may be a command.** Most MCP servers are programs that speak over their standard streams. The gateway starts one with the variables the SDK gives any command, and the operator's. It does not pass on its own environment, where the passphrase of its keys is. Such a server is named `stdio:<label>` in the mind's records. The command and its arguments are not published: they say where things are on the operator's machine.

5. **The bridged mind is made as any gateway makes one.** `withBridged` of `@oip/local`, which the A2A gateway now uses too: the genesis names the gateway, an entry of the gateway's feed names the genesis, and the profile carries both. Custody of a mind's keys is written once.

6. **The policy is closed until the operator opens it.** 2.1 forbids a call the requester's authority does not cover "where the gateway's operator has configured such checks". This gateway is never without checks. `bridge` writes a policy that names nobody, and a tool is called only for a mind the operator has named, or for anyone where the operator wrote `"anyone"`. A gateway that holds a key and calls for whoever asks is an open relay for that key, and it should take a decision to make one.

7. **Authority is the sender's, and that of the mind it was sent for.** A packet sent for another mind counts as that mind's where the sender's proof carries a chain of delegations that covers `/oip/send` (Layer 1, 11.2). Nothing a packet says of itself in words counts.

8. **A policy that cannot be read stops the relay for that server.** The requests wait. A gateway that fell back to "nobody" would decline requests that the operator meant to allow, and one that fell back to anything wider would be wrong in the dangerous direction.

9. **A tool is called at most once.** The gateway writes down that it is about to call before it calls, and the answer before it sends it. A pass that stops mid-call is not made good by calling again: the requester is told that nobody knows whether the tool ran. A request that waited because the server could not be reached is tried again, since nothing was called. An answer may be sent twice if a pass stops between the sending and the note of it. A call may not.

10. **The result is carried whole, as the server gave it.** The `tools/call` result is the `body` of `application/json` content: its `content` blocks, its `structuredContent`, its `isError`. The gateway does not translate content blocks into parts. A requester that called a tool by its schema reads the tool's own result, and nothing is lost between them.

11. **JSON that a record cannot hold is carried as its text.** A body, or a schema, is carried as it is where the parser for records takes it, and otherwise as its JSON text. A noncharacter, which no string of a record may hold, is written as its escape in that text. The gateway takes a request's body in either form (OEP-0006, item 5).

12. **A failed tool is an `error` packet with the server's result. A call that gave no result is an `error` packet with the gateway's words.** The server's words are quoted as a string of JSON, as the A2A gateway quotes an agent, so that nothing in them reads as the gateway's (OEP-0006, item 6).

13. **A Receipt is signed only about a Commitment, and only for a result.** 2.1 asks for a Receipt "about any Commitment it entered into". The gateway signs one where the request names a Commitment the bridged mind holds and owes under, the requester is owed under it, it stands accepted, and the tool returned a result that is no error. The statement says what the gateway saw (1.4). No Receipt is signed for a plain request: a Receipt is public (Layer 2, 10.2), and would publish who called which tool. None is signed for a failure: a `broken` Receipt would be the mind's own word against itself, on the strength of one call that might be made again.

14. **The gateway enters into no Commitment by itself.** A Commitment's promise is plain language. A gateway that co-signed what a requester sent would sign a stranger's words in the bridged mind's name. The operator signs, in the mind's own directory, with the `oip` command. A convention for a promise the gateway could check is left to a later proposal (OEP-0006, open question 2).

15. **The digest is of what the requester holds.** The evidence item's digest is of the body returned: of its canonical form, or of its bytes where it is text. Its `ref` is the request. A requester can check it against the packet it received.

16. **Credentials are a file that is its owner's alone.** `credentials.json`, in the bridged mind's directory. A file that others on the machine can read is refused. No value of it is written anywhere: an error about the file names a member, and quotes nothing, not even what a JSON parser would say of the text.

17. **Tools only.** Resources and prompts MAY be mapped (2.1), and are not. A resource is read, not called, and has no place in the request form 2.1 defines.

## Consequences

- An MCP server can be found on the network by what it can do, asked by any mind its operator allows, and held to a Receipt, with nothing changed on its side.
- The gateway is a custodian twice over: of the bridged minds' keys, and of the servers' credentials. Its directory is as sensitive as a keystore.
- A new runtime dependency, with its own: `@modelcontextprotocol/client` 2.4.0, and through it `@modelcontextprotocol/core`, `zod`, `jose`, `eventsource`, `eventsource-parser`, `pkce-challenge` and `cross-spawn`. The gateway uses none of the client's OAuth code. The package is Apache-2.0, as this repository is.
- A requester must read a `body` in two forms. Most never see the second.
- A request whose call broke off is answered with an error and not retried. A requester that knows its tool is safe to repeat asks again.
- The relay polls, as the A2A gateway's does. It connects to a server only when a tool is to be called.

## Alternatives

- **A client of our own, as for A2A.** Four methods would be enough for one era and one transport. MCP has two of each, and its newest revision changed how a connection opens. The official client is the reference for all of it, and `@oip/mcp-server` already rests on the same project's server.
- **Open by default.** It is what 2.1 allows, and it makes the first run easier. It also hands the operator's credentials to the network until the operator notices.
- **Content blocks as packet parts.** It would read more like the A2A gateway. But the blocks are MCP's, with types that grow, and a requester that speaks to a tool already speaks MCP's result. A mapping would lose what it did not foresee.
- **Fractions as decimal strings.** A record writes a price as a string (core 1.3). A tool sent `"0.7"` for a number refuses it, and the gateway cannot know which strings to turn back.
- **A Receipt for every call.** It would give every call a public, signed trace, which is accountability and also a log of who asked what. 2.1 asks for it where there is a Commitment, and that is where a requester has said it wants one.
- **Retrying a call that broke off.** At-least-once is the easier promise to keep, and the wrong one for a tool that pays.
