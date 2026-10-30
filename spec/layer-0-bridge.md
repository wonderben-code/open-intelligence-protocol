# OIP Layer 0: the Bridge

**Revision 2026-10-30 · Status: Draft · Licensed under CC BY 4.0**

This document specifies how existing systems take part in OIP through gateways, and how OIP minds take part in existing systems. It depends on [core.md](core.md), [layer-1-mind-network.md](layer-1-mind-network.md) and [layer-2-mind-web.md](layer-2-mind-web.md). Rationale is in Section 7 of the [technical architecture paper](../papers/02-technical-architecture.md).

Sections 2–4 are normative for implementations claiming the Gateway profile for those systems. Sections 5–9 are informative in this revision and will become normative as implementations mature.

## 1. Gateway minds and assurance

1.1. A **gateway** is a key-controlled mind that represents an external system on the OIP network.

1.2. For each external system it represents, a gateway creates a **bridged mind**: a key-controlled mind of kind `service` (or `human`, for people reached through a human gateway, Section 6) whose control and operational keys are held by the gateway. The bridged mind's Participant profile MUST include an extension block:

```json
"ext": { "oip.bridge": { "protocol": "mcp", "endpoint": "https://tools.example/mcp",
                         "gateway": "did:oip:<gateway>", "assurance": "bridged" } }
```

1.3. **Assurance levels.** `native`: the mind holds its own keys (the default; never declared by a gateway). `bridged`: a gateway acts for the external system and attests what it observed. `claimed`: an assertion nobody has verified. A gateway MUST declare `bridged` for every mind it bridges. Verifiers cannot detect undeclared bridging from records alone; a gateway that omits the declaration misrepresents its minds and is accountable for doing so.

1.4. Records signed by a bridged mind are statements by the gateway about the external system. Receipts produced by a gateway MUST describe what the gateway observed (for example, "the MCP server returned this result") and MUST NOT claim more.

1.5. Several gateways MAY bridge the same external system. An external system that later creates a native mind SHOULD link it to its bridged minds through verified aliases.

## 2. MCP

2.1. **MCP servers as participants.** A gateway bridging an MCP server:
- maps each tool returned by `tools/list` to a capability with `id` = the tool name, `summary` = the tool description, and the tool's input schema under `ext["oip.mcp"].inputSchema`; resources and prompts MAY be mapped likewise;
- maps a packet with verb `request` whose content is `{ "mediaType": "application/json", "body": { "tool": <name>, "arguments": { … } } }` to an MCP `tools/call`, and returns the result in a packet with verb `deliver` and `replyTo` set to the request's content ID;
- SHOULD sign a Receipt about any Commitment it entered into, with the tool result's digest as evidence;
- holds whatever credentials the MCP server requires, and MUST NOT perform an action for a requester that the requester's authority (identity or delegation) does not cover, where the gateway's operator has configured such checks.

2.2. **OIP as an MCP server.** An **OIP MCP server** gives an MCP host a mind. It MUST expose tools with these names and behaviour, and MAY expose more:

| Tool | Behaviour |
|---|---|
| `oip_whoami` | Return the mind's address, kind and current profile |
| `oip_find` | Run a capability query against configured indexers; return verified results |
| `oip_send` | Send a packet to addresses or a capability query |
| `oip_inbox` | List received packets, verified, with their senders' addresses |
| `oip_publish_intent` | Create, sign and publish an Intent |
| `oip_make_offer` | Create, sign and send or publish an Offer |
| `oip_commit` | Create or co-sign a Commitment |
| `oip_receipt` | Create and publish a Receipt |
| `oip_status` | Compute the status of an Intent, Offer or Commitment |

The server MUST keep signing keys outside the model's context, MUST present packet content to the model as untrusted data, and SHOULD require the human user's confirmation before signing a Commitment or a Delegation unless the user has configured a policy that permits it.

## 3. A2A

3.1. **A2A agents as participants.** A gateway bridging an A2A agent fetches its Agent Card from `/.well-known/agent-card.json`, verifies any card signatures, and records the card's SHA-256 digest under `ext["oip.a2a"].cardDigest` in the bridged mind's profile. It maps skills to capabilities and A2A interactions as follows:

| A2A | OIP |
|---|---|
| Agent Card skill | Capability |
| `SendMessage` | Packet with verb `request` |
| Task state `completed` | Receipt with outcome `fulfilled` |
| Task state `failed` | Receipt with outcome `broken` |
| Task state `canceled` | Receipt with outcome `cancelled` |
| Task state `rejected` | Packet with verb `decline` |
| `input-required`, `auth-required` | Packet with verb `request` to the requester |
| Artifact | Delivered content; evidence of kind `uri` or `hash` |
| `contextId` | Session |

3.2. **OIP minds as A2A agents.** A host MAY publish an A2A Agent Card for a mind it serves, generated from the mind's Participant profile (capabilities as skills), with an A2A interface endpoint that the host translates into OIP packets.

3.3. **OIP extension for A2A.** A2A messages MAY carry a complete OIP packet as a data part with media type `application/oip+json`. Agents supporting this declare the extension with the URI `https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/layer-0-bridge.md#a2a-extension` in their Agent Card. The receiver verifies the packet under Layer 1, Section 12.4.

## 4. Identity aliases

4.1. A mind proves an alias by listing it in `alsoKnownAs` and having the alias point back (Layer 1, Section 5.3):

| Alias | Points back by |
|---|---|
| `did:web`, `did:webvh`, `did:plc` and other DIDs | Listing the `did:oip` address in its own `alsoKnownAs` |
| An HTTPS origin `https://example.com` | Serving the address alone as `text/plain` at `https://example.com/.well-known/oip/did` |
| A DNS name `example.com` (written `dns:example.com`) | A TXT record at `_oip.example.com` with value `did=<address>` |
| An AT Protocol handle (`at://alice.example.com`) | The handle's DID listing the `did:oip` address in its `alsoKnownAs` |

4.2. Gateways and clients MUST verify aliases before displaying them as belonging to a mind.

## 5. HTTP APIs and the web (informative)

- A gateway can describe an HTTP API from its OpenAPI document, mapping each operation to a capability with `ext["oip.openapi"]` holding the operation identifier.
- NLWeb sites expose MCP endpoints and are bridged under Section 2.
- Minds calling websites sign requests as in Layer 1, Section 13.3, following the IETF Web Bot Auth profile.

## 6. People (informative)

- A human gateway reaches a person by email, SMS or a messaging service, renders packets as readable messages and converts replies into packets.
- Accepting a Commitment, granting a Delegation or any other binding act requires an explicit confirmation from the person (for example, a single-use confirmation link), and the resulting records are `bridged`.
- A person may take full control of their mind at any time through a custody handover: an `Update` signed by the gateway's committed control key that commits to the hash of the person's own key (Layer 1, Section 3.7). The address does not change.

## 7. OAuth and credentials (informative)

- An OIP delegation can be presented to an OAuth authorisation server under RFC 8693 token exchange, yielding an access token whose `act` claims mirror the delegation chain.
- MCP clients can publish Client ID Metadata Documents that list their OIP address.
- Delegations and Receipts can be exported as W3C Verifiable Credentials 2.0 secured with `eddsa-jcs-2022`, re-signed by their authors, for ecosystems such as DIF KYA-OS.

## 8. Payments (informative)

| Rail | Offer and Commitment | Receipt evidence |
|---|---|---|
| x402 | `ext.x402` carries the payment requirements (scheme, network, asset, amount, recipient) | Evidence of kind `payment` with `ext.x402.settlement` holding the settlement response |
| AP2 | `ext.ap2` references Intent and Cart mandates; mandates MAY also appear in `authority` | Payment mandate reference |
| ACP | `ext.acp` carries the checkout session reference | Order reference |
| L402 | `ext.l402` carries the invoice | Payment preimage |

A payments gateway converts an HTTP 402 challenge into an Offer with the rail's block, executes a payment Commitment through the rail, and returns the rail's proof as Receipt evidence.

## 9. ActivityStreams (informative)

| OIP | ActivityStreams 2.0 |
|---|---|
| Offer | `Offer` |
| Co-signing a Commitment | `Accept` with `inReplyTo` |
| Packet with verb `decline` | `Reject` |
| Intent, Receipt | Objects with OIP data under an extension context |
| Public feed | `OrderedCollection` |
