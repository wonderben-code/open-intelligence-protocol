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
