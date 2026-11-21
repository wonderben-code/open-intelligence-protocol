# ADR-0028: The MCP server

**Status:** Accepted, 20 November 2026 (M8).

## Context

M8 gives an MCP host a mind ([BUILD.md](../../BUILD.md), M8; Layer 0, 2.2). The host is an application such as Claude Desktop or Claude Code. Its model is given tools, and with them it finds other minds, reads and sends packets, and makes and settles commitments for the person the mind belongs to.

Two things make this package unlike the others.

- **It holds keys and is driven by a model.** The model reads what strangers wrote: packets, profiles, offers. A packet cannot grant authority (Layer 1, 12.5), but its text can try to persuade the model to use the authority the model already has. Layer 0, 2.2 answers with three rules: the keys stay outside the model's context, packet content is presented as untrusted data, and a Commitment or a Delegation is confirmed by the person unless a policy of theirs permits it.
- **MCP has two shapes.** The revisions up to 2025-11-25 open with an `initialize` handshake, and a server asks the person something by sending a request of its own (`elicitation/create`). The revision of 2026-07-28 has no handshake and no request from the server: a call that needs the person comes back with `resultType: "input_required"`, and the client makes the call again with the answer and with a `requestState` the server handed out. Hosts of both kinds are in use.

## Decision

1. **The official library is the one new runtime dependency**: `@modelcontextprotocol/server`, pinned to an exact version. It brings `@modelcontextprotocol/core` and `zod`, and nothing else. It is maintained by the protocol's stewards, it serves both shapes of the protocol from one definition of a tool, and it turns one way of asking the person into what each shape needs. Writing both shapes here would be more code to get wrong, in a process that holds keys. The older `@modelcontextprotocol/sdk` is not used: it brings an HTTP stack this server has no use for. `@modelcontextprotocol/client` is a dependency of the tests alone.

2. **The server speaks over standard input and output, and nothing else.** A host starts `oip-mcp` as a child process. There is no listener on a port: a mind's keys behind a network port is another threat model, and no host needs it. The standard output carries the protocol's messages alone. The log goes to the standard error.

3. **A tool is written apart from the protocol.** A `Tool` is a name, a description, a JSON Schema and a function `run(work, given, confirming)`. The tools are tested without MCP, and `server.ts` is the one module that knows it. The arguments are checked twice: by the library against the schema, and by the tool's own readers, which do not rely on that.

4. **The mind is opened for each call and closed after it.** The mind's directory is the `oip` command's too ([ADR-0027](0027-a-mind-on-one-machine.md)): what one writes the other must see, and the routes of a local network change when it starts again. So the server holds nothing of the mind between calls. The keys are unlocked while a call is at work, and no longer. Calls are done one after another.

5. **A record is named by its content ID alone.** The command takes a record by the ID of one the mind holds or by a file. A tool takes the ID only. An assistant that could name a file could be talked into sending one.

6. **Everything the server did not write is under `untrusted`.** A result keeps apart what the server found out for itself, such as who signed a packet and when, and what another party said: a packet's verb, goal and content, a profile's name and summary, an offer's terms, an indexer's reasons, and the detail of an error. The second kind is a copy under a member named `untrusted`: control characters and the controls of bidirectional text are written as escapes, long texts are cut with a note of how much is missing, and the copy is bounded in depth and size. A result with such a member begins with a fixed sentence of the server's that says what the member means. The descriptions of the tools and the server's instructions say the same.

7. **The person confirms a Commitment, and a Receipt.** Before either is signed the tool comes back with a question. The question is written by the server from the record that would be signed, word for word and with every control character shown: never from anything the model says of it. The promise is on one line of it, so that no promise can forge the lines that follow. Layer 0, 2.2 asked this for a Commitment and a Delegation. The server asks it for a Receipt too, and 2.2 now does (OEP-0006): a Receipt is the person's public word on what became of a promise, and a party that is owed something gives its claim up by saying it was fulfilled.

8. **An answer counts for the question it was given to.** Everything in the call that brings the answer comes from outside: the arguments, the answer, and the state. So the server signs only if the state is its own, unaltered and less than ten minutes old; if the state names the digest of exactly what the call would sign now; and if that state has not been used. The digest is a content ID over the members the call chose, or over the ID of the Commitment another wrote. The state is sealed by the library's codec (HMAC-SHA256, from the platform) with a key made of the platform's randomness when the process starts, kept in memory alone. No primitive is implemented here. A call that brings an answer nobody asked for is a call without one.

9. **A host that cannot ask gets no signature.** Where the client does not state the elicitation capability, the tool refuses and says what the person can do instead: sign with the command, or write a policy.

10. **A policy is the person's file.** `policy.json` in the mind's directory says which Commitments and which Receipts need not be asked about, in the policy language of a delegation (Layer 1, 11.3). It is read once, when the server starts. A file that is no policy stops the server from starting. The server never writes it.

11. **No tool signs a Delegation.** An assistant is given the use of a mind, and no way to hand that use on. Delegating stays with the command.

12. **A failure says what helps and carries nothing else.** A message of this package or of the mind's directory is passed on. A refusal of the protocol is given by its code, with its detail under `untrusted`, since a service may have written it. A failure of the keystore is given by its code alone. Anything else is logged, and the model is told only that the tool failed.

## Consequences

- **A call costs a key derivation and a resolution of the mind**, about a second on an ordinary machine. A conversation makes a few calls a minute, and the directory stays consistent with the command.
- **The host is trusted to put the question to the person.** A host that answers every question with yes by itself removes the confirmation. MCP asks hosts to show an elicitation to the user. The model cannot answer: it has no way to reach the answer or the state.
- **A policy is a standing yes.** Whoever learns it can write a Commitment that stays under it, and an assistant that is talked into signing that one signs it unasked. Policies should be narrow: a small amount, a currency, named counterparties.
- **Whoever can write the mind's directory can write the policy.** A model that has a tool for writing files, under the same user, can do so, and the server reads it when it next starts. The threat model says to keep the directory out of the reach of other tools ([mcp-server.md](../threat-models/mcp-server.md)).
- **An assistant can still be talked into sending a packet, or publishing an Intent or an Offer.** These bind nobody, and the server does not ask about them. They are the host's to approve, and the prompt-injection suite states this limit as a test.
- **Confirming a Receipt went beyond Layer 0, 2.2 as it stood.** [OEP-0006](../../oeps/oep-0006-bridge-clarifications.md) proposes it for the specification, and 2.2 now names a Receipt.
- **Acting for another mind is not in the server.** The tools sign as the mind itself. A mind that signs for its principal through a chain of delegations does so with the command or the client.
- **There is no output schema yet.** A result is JSON as text and the same JSON as structured content. Its shape is described in the README and held by the tests.

## Alternatives

- **An implementation of MCP of our own** would avoid the dependency. It would have to serve two shapes of the protocol and the step between them, and would be the least-tested part of a process that holds keys.
- **A mind that stays open for the server's life** would save a second on each call. Its records, routes and keys would go stale whenever the command ran, and the keys would be unlocked for as long as the host is.
- **A summary from the model in the question** ("the user asked me to…") would read well. An assistant that was talked into a Commitment would describe it kindly, so the person would be confirming the attacker's words.
- **Asking about every tool that writes** would close the limit above. The person would be asked about every message, and would learn to say yes without reading. Hosts already ask before a tool that is not read-only.
- **A listener over HTTP** would let one server serve many hosts. Nothing here needs it, and it would put a mind's keys behind a port.
