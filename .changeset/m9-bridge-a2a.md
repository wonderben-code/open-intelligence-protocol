---
"@oip/bridge-a2a": minor
---

A gateway between the Open Intelligence Protocol and A2A 1.0 (Layer 0, Sections 1 and 3), as a library and as the program `oip-bridge-a2a`.

- **An A2A agent as a mind.** `Gateway.bridge` reads an agent's card, verifies its signatures, and makes a bridged mind that the gateway attests in its own feed. `Gateway.relay` passes requests on to the agent, and brings back packets and Receipts that say what the gateway observed.
- **A mind as an A2A agent.** `Front`, `A2aServer` and `listen` serve an Agent Card and the JSON-RPC binding of A2A for a mind that lists the card in its profile. The mind answers with packets.
- **The OIP extension for A2A.** An agent that declares it is sent the whole signed packet. A client that sends one has it verified under Layer 1, 12.4 and brought to the mind as it is.

What the independent review of the gateway changed ([ADR-0034](../docs/adr/0034-what-the-gateway-reviews-changed.md)):

- A Receipt is brought to the requester, and is not published in the bridged mind's feed (OEP-0006, item 10). Its statement holds the agent's name for the task, quoted, and none of the agent's words. Those are content of the packet, each part with its digest in the Receipt's evidence.
- One `serve` runs from a gateway's directory at a time (`serve.hold`).
- The gateway's minds send their answers under the guard of `@oip/server`. `OIP_BRIDGE_FETCH_ALLOW` names further address ranges for a test network.
- A request is not passed on past its `expires`, or after a day where it names none. An agent that cannot be reached is asked once in a pass. A pass for one agent takes 30 seconds at most, and eight agents are relayed for side by side.
- What a task ended with is gathered once and written down before its Receipt is signed.
- The served side keeps 4,096 tasks for a mind at most, sweeps a context that is idle for a day, takes `application/json` alone, and has timeouts for headers and requests. A card has 8 signatures at most.
