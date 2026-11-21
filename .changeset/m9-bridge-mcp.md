---
"@oip/bridge-mcp": minor
---

A gateway that makes MCP servers participants (Layer 0, 2.1).

- `oip-bridge-mcp bridge <url>` lists the tools of an MCP server and makes the server a bridged mind, attested in the gateway's feed, with a capability for each tool: the tool's name as its `id`, its description as its `summary`, and its input schema under `ext["oip.mcp"].inputSchema`. `bridge --stdio <label> -- <command>` does the same for a server that is a command on this machine.
- `oip-bridge-mcp serve` relays. A packet with verb `request` whose body is `{ "tool", "arguments" }` is a call of the tool. The result comes back in a `deliver` packet, a tool's failure in an `error` packet with the server's own result, and a refusal by the operator's policy in a `decline` packet.
- JSON that a record cannot hold, a number with a fraction for one, is carried as its JSON text: in a request, in a result and in an input schema (OEP-0006, item 5).
- A tool is called only for a mind the operator's `policy.json` names, by its own identity or by a delegation to send for a mind it names. The policy names nobody until the operator writes it.
- A tool is called at most once for a request. A pass that stops in the middle of a call tells the requester so, and does not call again.
- The server's credentials are a file that is its owner's alone. Headers go to the server's own origin and nowhere else, and no value of the file is written anywhere.
- A Receipt, with the digest of the result as evidence, is signed for a call made under a Commitment that the bridged mind has entered into and the request names.
- `Gateway`, `Relay`, `connector`, `capabilitiesOf`, `readPolicy` and the rest are exported for a program that is its own gateway.

What the independent review of the gateway changed ([ADR-0034](../docs/adr/0034-what-the-gateway-reviews-changed.md)):

- One pass at a time relays for a bridged mind (`relay.hold`), and one `serve` runs from a gateway's directory (`serve.hold`).
- A delegation must stand when the gateway acts. Before a tool is called for a request sent for another mind, the feeds of the delegations' authors are read for Revocations (OEP-0006, item 9).
- A server's words are searched for the operator's credentials before any are passed on. A result that repeats one is not passed on, and nothing a transport says of a failure is.
- A Receipt has outcome `progress`, is written down when it is signed, and is published once. The gateway looks at the first eight references of a request for the Commitment.
- A URL with a query is refused: it is published in the mind's records. What a server wants in its query goes in `credentials.json`, under `query`.
- JSON text with a member name twice, or a number that is not finite, is no call. A value is carried as the parser for records read it.
- A request is not acted on past its `expires`, or after a day where it names none. `Relayed.lost` names the answers that no endpoint took.
- All that a server wrote takes 224 KiB of a profile at most. The list of tools is read through the MCP client library's own paging, 32 pages at most.
- The gateway's minds ask under the guard of `@oip/server`. `OIP_BRIDGE_FETCH_ALLOW` names further address ranges for a test network.
