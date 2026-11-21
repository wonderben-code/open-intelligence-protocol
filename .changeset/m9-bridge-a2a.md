---
"@oip/bridge-a2a": minor
---

A gateway between the Open Intelligence Protocol and A2A 1.0 (Layer 0, Sections 1 and 3), as a library and as the program `oip-bridge-a2a`.

- **An A2A agent as a mind.** `Gateway.bridge` reads an agent's card, verifies its signatures, and makes a bridged mind that the gateway attests in its own feed. `Gateway.relay` passes requests on to the agent, and brings back packets and Receipts that say what the gateway observed.
- **A mind as an A2A agent.** `Front`, `A2aServer` and `listen` serve an Agent Card and the JSON-RPC binding of A2A for a mind that lists the card in its profile. The mind answers with packets.
- **The OIP extension for A2A.** An agent that declares it is sent the whole signed packet. A client that sends one has it verified under Layer 1, 12.4 and brought to the mind as it is.
