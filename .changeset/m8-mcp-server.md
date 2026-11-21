---
"@oip/mcp-server": minor
---

First version: the OIP MCP server, `oip-mcp` (Layer 0, 2.2).

- A host such as Claude Desktop or Claude Code starts it, and its model is given nine tools: `oip_whoami`, `oip_find`, `oip_send`, `oip_inbox`, `oip_publish_intent`, `oip_make_offer`, `oip_commit`, `oip_receipt`, `oip_status`. Each is described for a model.
- It speaks MCP over standard input and output, in the revisions up to 2025-11-25 and in that of 2026-07-28, through the official library.
- The keys stay in the server. No tool returns one, and no tool reads a file: a record is named by its content ID.
- What other minds wrote reaches the model as data, under a member named `untrusted`, with control characters written as escapes and long texts cut. What the server verified is apart from it.
- A Commitment or a Receipt is signed only once the person has confirmed it through MCP elicitation, or a policy of theirs (`policy.json`, in the policy language of Layer 1, 11.3) permits it. The question is written by the server from the record. An answer counts for the question it was given to, once. A host that cannot ask gets no signature.
- No tool signs a Delegation.
- A prompt-injection suite sets a model that does whatever it reads against a mind that writes calls for it in packets, a profile, an Offer and the promise of a Commitment.
