# 01 — Landscape of AI Agent, Tool and Interoperability Protocols (as of 30 October 2026)

*Research input for the OIP technical architecture paper. Compiled 30 Oct 2026 from primary sources where possible (specs, foundation announcements, GitHub, IETF/W3C datatracker). Facts that could not be verified from a primary source are marked **[unverified]** or **[uncertain]**.*

---

## 1. Summary

1. **The field has consolidated around two Linux Foundation protocols under one roof.** The **Agentic AI Foundation (AAIF)**, formed 9 Dec 2025 under the Linux Foundation, now hosts both **MCP** (agent-to-tool/context) and **A2A** (agent-to-agent tasks; joined AAIF Aug 2026), plus AGENTS.md, goose, agentgateway, Agent Router, and (from 22 Oct 2026) Agent Skills, Open Responses, OpenEnv and OpenSandbox — ten projects in total. IBM's **ACP** merged into A2A in August 2025 and its repo is archived.
2. **MCP 2026-07-28 made MCP stateless.** It removed protocol-level sessions, the `initialize` handshake and SSE resumability; moved Tasks into an official extension; and deprecated Sampling, Roots and Logging. MCP is now an ordinary HTTP workload whose auth is OAuth 2.1 (protected-resource metadata, Client ID Metadata Documents). Agent identity, delegation and DPoP are **roadmap items, not shipped**.
3. **A2A v1.0 (12 Mar 2026)** is the first stable A2A. It defines Agent Cards at `/.well-known/agent-card.json`, optional JWS-signed cards (JCS canonicalisation), a Task/Message/Part/Artifact model with a defined state machine, and three equivalent bindings (JSON-RPC, gRPC, HTTP+JSON). It also adds multi-tenancy. Identity is still **domain/URL-bound**, and signatures prove card integrity, not who the operator is.
4. **The identity, discovery and trust layers are fragmented and unfinished.** Contenders include ANP/W3C AI Agent Protocol CG (`did:wba`), AGNTCY (OASF, a DHT-based Agent Directory, VC "Agent Badges", SLIM messaging), GoDaddy/OWASP **ANS v2** (DNS-anchored names plus a transparency log), the IETF **agentproto** WG (chartered 2026, dialog/context management; milestones run to 2028) and the deferred **DAWN** discovery BoF.
5. **No existing protocol provides the following.** OIP's Layer 1/2 thesis is still open territory:
   - a **permanent, self-certifying, hardware- and domain-independent address** for a mind
   - **capability-based routing across the whole network** (AGNTCY ADS is closest, but it is a lookup directory, not a router)
   - **session continuity across moves and forks**
   - **verifiable Commitments and Receipts** as general primitives (only payments-specific analogues exist: AP2 mandates, x402)
   - **Collectives** as first-class participants
   - **humans and institutions as peers** rather than "users behind a client"

**Strategic implication:** OIP should *bridge* MCP and A2A, since they are where adoption is. It should *reuse* their auth (OAuth/OIDC, WIMSE), DIDs/VCs, JCS+JWS and OASF-style capability schemas. It should *track and contribute to* IETF agentproto. It should differentiate on Layer 1 addressing/routing/continuity and on Layer 2 commitment and collective semantics.

---

## 2. Per-protocol analysis

### 2.1 Model Context Protocol (MCP)

- **Origin and governance:** Anthropic launched MCP in Nov 2024 and donated it to the **AAIF** (Linux Foundation) at the foundation's formation on 9 Dec 2025. Changes go through a SEP (Specification Enhancement Proposal) process; a PR-based SEP workflow was formalised in SEP-1850. Working and Interest Groups (Transports, Tasks & Events, SDK, File Uploads, Agents IG; Agent Identity and Core Primitives WGs forming) do the work, and Core Maintainers own the roadmap areas. A formal feature-lifecycle/deprecation policy sets a minimum 12-month deprecation window (SEP-2596).
- **Licence:** open source (spec and SDKs on GitHub under `modelcontextprotocol`). **[licence identifier not re-verified this session; historically MIT]**
- **Latest spec:** **2026-07-28**. RC 21 May 2026, final 28 Jul 2026. The previous revision was 2025-11-25.
- **Layer occupied:** agent/host ↔ tool/context server (client-server). It is **not** peer-to-peer and not agent-to-agent.
- **Core primitives:** Tools, Resources (and templates), Prompts (server side). Roots, Sampling and Logging (client side) are **deprecated** as of 2026-07-28. Elicitation is now delivered through the new **Multi Round-Trip Request (MRTR)** pattern: servers return `resultType: "input_required"` and the client retries with the answers. **Tasks** for long-running work is an official extension (`io.modelcontextprotocol/tasks`; poll via `tasks/get`, input via `tasks/update`). **MCP Apps** (server-rendered UI) is another official extension.
- **2026-07-28 key changes:**
  - Sessions and `Mcp-Session-Id` removed; the `initialize` handshake removed. Every request carries its protocol version and capabilities in `_meta`.
  - A new `server/discover` RPC for version and capability discovery.
  - `subscriptions/listen` replaces the GET/SSE stream.
  - SSE resumability removed.
  - Cacheable list results (`ttlMs`, `cacheScope`).
  - OpenTelemetry trace propagation in `_meta`.
  - Explicit server-minted handles replace implicit session state.
- **Transports:** stdio (local) and Streamable HTTP (remote). HTTP+SSE is formally deprecated. The roadmap proposes **HTTP over stdio** (HTTP/2) to unify to a single binding. Jennings' **MCP-over-MoQT** draft exists in the IETF.
- **Identity and auth:**
  - Authorisation is optional; when present, it is OAuth 2.1 at the transport level for HTTP.
  - The server is a resource server and MUST publish RFC 9728 Protected Resource Metadata.
  - RFC 8707 resource indicators are mandatory, and RFC 9207 `iss` validation is required.
  - Client ID Metadata Documents are preferred; Dynamic Client Registration is now deprecated.
  - Extensions repo `ext-auth` includes **Enterprise-Managed Authorization** (ID-JAG). The InfoQ conference report says it is live in Claude.
  - **On the roadmap but not shipped:** DPoP, Workload Identity Federation (SEP-1933), RFC 8693 token exchange for agent identity and sub-agent delegation, and human-presence attestation.
  - Server identity in effect equals its canonical HTTPS URL plus the OAuth audience.
- **Discovery:** The **MCP Registry** (registry.modelcontextprotocol.io) is still in **preview**. It holds `server.json` metadata and uses reverse-DNS namespaces (`io.github.user/server`, `com.example/server`) verified via GitHub, DNS or HTTP challenges. It defines an OpenAPI interface that sub-registries and aggregators implement. Within a connection, discovery is `server/discover` plus `tools/list` etc., with "progressive discovery" on the roadmap.
- **Adoption:** very high. AAIF reported **4.17 billion cumulative SDK downloads** at AGNTCon+MCPCon NA (22–23 Oct 2026; stage claim). MCP is supported across Claude, ChatGPT, Gemini, Copilot, AWS AgentCore and others.
- **Adjacent: WebMCP.** This is a W3C Web Machine Learning CG draft report (not on the Recommendation track) in which web pages register JS tools for in-browser agents (`document.modelContext.registerTool()`). Chrome runs an origin trial (v149–156). Third-party source; **[partially verified]**.
- **What MCP does NOT provide relative to OIP:**
  - Addresses are HTTPS URLs or local processes, so they are location-bound, not permanent or self-certifying.
  - There is no peer identity for the *client*/agent yet.
  - There is no routing; the client must already know the server.
  - Since 2026-07-28 there is deliberately **no session continuity**: state lives in opaque, server-minted handles.
  - It has no commitments or receipts, no collectives, and no model of humans or institutions as participants. The human is a "resource owner" consenting via browser.

### 2.2 Agent2Agent Protocol (A2A)

- **Origin and governance:**
  - Google announced A2A in Apr 2025 and donated it to the Linux Foundation in Jun 2025 (Linux Foundation "Agent2Agent Protocol Project").
  - It became an **AAIF hosted project on 17 Aug 2026**.
  - IBM's ACP merged into it in Aug 2025.
  - Repo: `github.com/a2aproject/A2A`. **[Apache-2.0, not re-verified this session]**
- **Version:** **v1.0.0 released 12 Mar 2026** (prior: 0.3.0, 0.2.6, 0.1.0). Clients send their version in an `A2A-Version` header. v1.0 had breaking changes from 0.3:
  - one unified `Part` type
  - prefixed enums
  - `supportedInterfaces[]` on Agent Cards
  - `google.rpc.Status` errors
  - PascalCase operations such as `SendMessage`
  - OAuth implicit and password flows removed
- **Layer occupied:** agent-to-agent RPC and task delegation between *opaque* agents, which do not share memory or tools.
- **Core primitives:**
  - **Agent Card:** JSON metadata covering identity, skills, endpoints, security schemes and capabilities. An authenticated **extended Agent Card** is also available.
  - **Message:** role `user` or `agent`, made of **Parts** (text, url, raw, data).
  - **Task:** a stateful unit of work with an ID and lifecycle. States: working, input-required, auth-required, completed, failed, canceled, rejected.
  - **Artifact:** task output.
  - A `contextId` groups related tasks.
  - Push notifications go to client webhooks, with at-least-once delivery.
  - Extensions are declared by URI and negotiated via the `A2A-Extensions` header.
  - Multi-tenancy via an opaque `tenant` field.
- **Transport:** three functionally equivalent bindings: JSON-RPC 2.0 over HTTP(S), gRPC, and HTTP+JSON/REST. Streaming uses SSE or gRPC streams. `a2a.proto` is normative.
- **Identity and auth:**
  - Security schemes are declared in the card and follow OpenAPI-style types: API key, HTTP auth, OAuth 2.0, OIDC, mTLS.
  - Credentials travel out of band.
  - **Signed Agent Cards** use JWS (RFC 7515) over a JCS-canonicalised (RFC 8785) card, with keys fetched via `jku`/`kid`.
  - The AAIF builder's guide stresses that signatures prove **integrity, not identity**: the verifier must still decide whether to trust the key's owner.
  - There is no DID or self-certifying identifier in core.
- **Discovery:** the well-known URI `/.well-known/agent-card.json`, plus curated registries or direct configuration. The roadmap mentions "consolidated registry efforts". There is no global directory in the spec.
- **Adoption:**
  - 150+ supporting organisations (LF, Apr 2026).
  - SDKs in Python, JS, Java, Go and .NET.
  - Integrated in Azure AI Foundry/Copilot Studio, Amazon Bedrock AgentCore and Google Agentspace/Vertex.
  - Spawned **AP2** (Agent Payments Protocol) as an extension with 60+ payment organisations.
  - Note: AAIF's project-health page shows declining GitHub star and fork *growth* year-on-year; interpret with caution.
- **What A2A does NOT provide relative to OIP:**
  - Identity is the URL or domain hosting the card, so moving hosts changes identity.
  - There is no capability-based routing, only lookup of a known card.
  - Tasks are server-scoped, with no portable session continuity across moves or forks of either party.
  - There are no first-class Commitments or Receipts. A completed Task plus Artifact is the closest analogue, but it is unsigned and non-portable.
  - There are no Collectives.
  - Humans appear only as the "user" role behind a client agent.

### 2.3 Agent Communication Protocol (ACP) — IBM / BeeAI

- **Status:** **merged into A2A**. The `i-am-bee/acp` repo was **archived on 27 Aug 2025** with a migration guide to A2A. IBM Research's project page states "ACP is now part of A2A under the Linux Foundation."
- **What it was:** a REST/OpenAPI protocol for agent-to-agent calls. Primitives were the Agent manifest, Runs (sync or streamed), Messages and MessageParts (MIME-typed), Await (pause for input) and Sessions. Licence Apache-2.0.
- **Naming collision:** "ACP" now also commonly means OpenAI/Stripe's **Agentic Commerce Protocol** (Sep 2025, Apache-2.0, Shared Payment Tokens). There is also Zed's Agent *Client* Protocol (editor to coding agent) **[not researched in depth]**. OIP documentation should disambiguate.
- **Relevance to OIP:** none as a live target. Bridge via A2A.

### 2.4 Agent Network Protocol (ANP)

- **Origin and governance:** open-source community started in 2024 by Gaowei Chang (also founder of AWiki). Chang co-chairs the **W3C AI Agent Protocol Community Group**, which incubates a CG draft built on ANP. The draft is not a W3C standard; its "Protocol (Tentative)" document is undated and many sections are still TODO. Repo `agent-network-protocol/AgentNetworkProtocol` (541+ commits). The licence is inconsistent: the README says MIT and the repo metadata says Apache-2.0 **[uncertain]**.
- **Layer occupied:** identity plus discovery plus agent-to-agent messaging for an "agentic web". It is explicitly peer-to-peer in intent.
- **Architecture:**
  1. **Identity and encrypted communication:** W3C DIDs using the **`did:wba`** method (web-based: the DID document is hosted on HTTPS under a domain; Ed25519 path binding in v1.1). The CG draft also accepts `did:web` and `did:webvh`. Authentication uses HTTP Message Signatures with replay protection, and E2E-encrypted messaging is being drafted (Messaging 1.2).
  2. **Meta-protocol** (ANP-06, still draft): natural-language/LLM negotiation of which application protocol two agents will use.
  3. **Application layer:** Agent Description documents in JSON-LD (ANP-07) list name, DID and interfaces (natural-language or structured: OpenAPI, JSON-RPC, GraphQL). Discovery (ANP-08) is active via `/.well-known/agent-descriptions` or passive via search-agent registration. AP2 payments have been added.
- **Adoption:** smaller and mainly in the Chinese ecosystem (AWiki, PyPI and Rust SDKs). It is academically prominent: it is one of the four protocols in the 2025 arXiv survey (Ehtesham et al.).
- **CG status (Jul 2026):** discussions on DID-WBA flows, DID lifecycle, discovery before connection, relay messaging, E2E encryption and IETF coordination. No final decisions.
- **What ANP does NOT provide relative to OIP:**
  - `did:wba` is still **domain-anchored**. Losing the domain loses or forks the identity, so it is not hardware- *and* host-independent. `did:webvh` mitigates this partly with a verifiable history.
  - There is no capability routing beyond crawl/search.
  - There are no commitments, receipts or collectives, and no session continuity across moves or forks.
- **Reuse value for OIP:** high on concepts. OIP can use DID method plurality, JSON-LD descriptions and meta-protocol negotiation as a Bridge pattern.

### 2.5 AGNTCY / "Internet of Agents" (Cisco-led, Linux Foundation)

- **Origin and governance:** Cisco (Outshift) launched it in Mar 2025. It joined the **Linux Foundation in Jul/Aug 2025** with formative members Cisco, Dell, Google Cloud, Oracle and Red Hat, and 75+ supporting companies. It is "a Series of LF Projects, LLC", separate from AAIF. **[Per-component licences not re-verified; most repos are Apache-2.0 per historical knowledge.]**
- **Layer occupied:** infrastructure *around* agent protocols: discovery, identity, messaging, observability. It is protocol-agnostic and describes A2A and MCP agents alike.
- **Components:**
  - **OASF (Open Agentic Schema Framework):** a versioned, extensible record schema for agents covering skills, domains, features and extensions. It includes MCP descriptors and A2A cards.
  - **Agent Directory Service (ADS):**
    - Records are stored as content-addressed **OCI artifacts** (SHA-256 / CIDs).
    - A **Kademlia DHT** maps skill, domain and feature keys to record CIDs, and CIDs to serving endpoints. This is a two-level capability index and is the closest existing thing to capability routing.
    - Optional **Sigstore** signing with transparency-log inclusion.
    - Source: arXiv 2509.18787, Sep 2025.
  - **Identity:** IDs come from IdP accounts or well-known cards (conventions) or from **W3C DIDs + VCs** (standards). Each ID maps to many **Agent Badges**, which are VCs binding the ID to an OASF schema plus locators and auth metadata. MCP servers, agents and multi-agent systems share the same identity structure.
  - **SLIM (Secure Low-Latency Interactive Messaging):** network-level pub/sub and streaming with **MLS** group encryption, described as quantum-safe. A2A can run over SLIM. **[the A2A-over-SLIM claim is from prior knowledge; docs list SLIM as A2A-compatible transport — verify]**
  - **SHADI:** hardened agent runtime. Also Observability and Evaluation, CSIT testing, and the CoffeeAGNTCY reference app.
- **Adoption:** moderate, enterprise and Cisco-centric.
- **What AGNTCY does NOT provide relative to OIP:**
  - The directory finds agents, but there is no message routing by capability. You still connect to an endpoint.
  - Identity is a framework that admits non-permanent IDs.
  - There is no session continuity across moves or forks.
  - There are no commitment or receipt primitives.
  - "Multi-agent systems" are described as records, not as Collectives with governance and membership semantics.
- **Reuse value for OIP:** **very high.** OASF as a capability vocabulary, the ADS DHT design, Agent Badges (VCs) and SLIM/MLS for group (Collective) channels.

### 2.6 NLWeb (Microsoft)

- **Origin:** Microsoft announced it at Build 2025, designed by R.V. Guha (creator of RSS and Schema.org). The MIT-licensed reference implementation is on GitHub (about 6.3k stars). No formal standards body or governance is described.
- **Layer occupied:** website-as-agent. It is a natural-language query interface over a site's Schema.org and RSS data.
- **Primitives and transport:** an `/ask` endpoint (HTTP) returns Schema.org-typed JSON. **Every NLWeb instance is also an MCP server** at `/mcp`.
- **Identity, auth and discovery:** none specific. It relies on the site's domain and has no standard discovery location.
- **Adoption:** launch partners included Tripadvisor, Shopify, Eventbrite, O'Reilly, Hearst and Allrecipes. Cloudflare offers a one-click deploy (AI Search). The total deployment count is unknown.
- **What NLWeb does NOT provide:** it lacks everything at Layers 1 and 2. It is purely an endpoint convention.
- **Reuse value for OIP:** bridge it automatically through MCP. Schema.org typing is a good model for Layer 2 Offer descriptions.

### 2.7 Agent Protocol (AI Engineer Foundation / AGI, Inc.)

- **Origin:** a 2023 effort associated with the AI Engineer Foundation and AutoGPT. The README now says it is **maintained by AGI, Inc.**
- **Primitives and transport:** a minimal REST/OpenAPI interface: `POST /ap/v1/agent/tasks` (create a task) and `.../tasks/{id}/steps` (execute a step), plus artifacts upload and download. RFC-based changes.
- **Identity, auth and discovery:** none specified.
- **Adoption:** early adopters were AutoGPT, AutoGPT Forge and smol developer. It is effectively **legacy and superseded by A2A** for inter-agent use. Licence not stated on the README **[uncertain]**.
- **Relevance to OIP:** low. A thin Bridge adapter is trivial if needed.

### 2.8 Open Cognition Protocol (OCP)

- **Status:** **[low confidence]**. A website (opencognitionprotocol.org, ©2026) describes an "OCP Foundation" but gives no named organisations, version, release date, repository or licence. No independent adoption evidence was found. Note also an unrelated "Open Commerce Protocol (OCP)" by Deeplumen (Mar 2026).
- **Claimed design:**
  - A 5-layer stack: transport, identity, knowledge exchange, collaboration, application.
  - DID-based identities with Ed25519 signing, AES-256-GCM and SHA-3.
  - Shamir key recovery (3-of-5).
  - Five trust levels with bilateral "bonds".
  - Knowledge types: embeddings, insight packages with provenance, and federated model deltas.
  - Weighted BFT consensus.
  - A mandatory privacy-validation layer.
- **Relevance to OIP:** conceptually the closest to OIP's ambitions: provenance-carrying knowledge packets, trust levels and consensus. However, it appears to be a vision document. Cite it as related work, not as an interop target.

### 2.9 ANTS

- **Status:** "day zero" (GitHub `Ants-Community/ants`). It has specs, a manifesto and RFCs only, **no code**. Code and spec are Apache-2.0, the manifesto and governance are CC0, and future network services are planned as AGPL-3.0.
- **Design:** a P2P network for "AI as shared infrastructure", with three layers:
  - BitTorrent-style transport with DHT routing.
  - A distributed semantic cache of **signed answers** retrieved by embedding similarity.
  - A minimal reputation chain that records only misbehaviour, under "Proof-of-Unique-Hardware" consensus.
  - Hardware-attested identity: one CPU counts as one peer. No token.
- **Relevance to OIP:** related work for decentralised routing and signed outputs. Its identity is **hardware-bound**, which is the opposite of OIP's hardware-independent mind addresses.

### 2.10 OpenPond

- **Status:** small, early. GitHub `openpond/protocol` has about 19 commits and 2 stars; the site is protocol.duckai.ai. Licence not stated.
- **Design:** layered network, identity, registry and message layers. Registration and permissions are **on-chain**. It has its own improvement-proposal process, also abbreviated "OIPs", which is a naming collision OIP should be aware of.
- **Relevance to OIP:** low. Related work only.

### 2.11 Standards bodies: IETF and W3C

**IETF**

- **agentproto WG (Applications and Real-Time area):**
  - The BoF at IETF 126 Vienna (23 Jul 2026) showed strong support for forming a WG (154–51). The initial scope was rejected (38–124) and has been rewritten.
  - The charter is listed as approved: it defines an **agentic dialog management protocol** (dialog IDs, lifecycle, context propagation) with bindings over existing IETF protocols. It explicitly does *not* replace MCP or A2A or define a new transport.
  - Chairs: Leslie Daigle and Orie Steele. Proponents: Jonathan Rosenberg and Cullen Jennings.
  - Milestones: use-cases draft Dec 2026; architecture Feb 2027; protocol adoption Mar 2027; to the IESG Mar 2028.
  - Coordinates with OAuth, WIMSE, webbotauth, MoQ, SCITT, RATS and vCon.
  - **This is the most relevant standards activity for OIP's "session continuity" and "context packets".**
- **CATALIST BoF (IETF 125, Mar 2026):** a coordination BoF. Its problem-space draft (draft-yao-catalist-problem-space-analysis) lists four gaps in A2A and MCP:
  1. inter-domain discovery
  2. end-to-end session state
  3. fine-grained, cross-domain authorisation and delegation
  4. multimodal transport
- **DAWN BoF (Discovery of Agents, Workloads, and Named entities):** held at IETF 126 and **deferred**, according to a third-party report.
- **DMSC BoF (Dynamic Multi-agent Secured Collaboration via agent gateways):** non-WG-forming.
- **Individual drafts (not IETF-endorsed):**
  - **ANS v2** (draft-narajala-courtney-ansv2-02, 26 Oct 2026; GoDaddy, OWASP, Cisco): versioned names `ans://v1.4.2.agent.example.com`. Domain control is checked with ACME-style challenges, discovery uses DNS SVCB (DNS-AID), and there is an optional RA-issued identity certificate. A Merkle **transparency log** issues receipts and status tokens, and a card-hash pin is available.
  - Agent-identity and authorisation drafts: AAuth (Hardt), the agent-native authorisation extension to OAuth First-Party Apps, the Delegated AI Agent Authorization profile, and an agent SD-JWT draft (Nandakumar).
  - **WIMSE** (workload identity) and **OAuth** WGs are the venues MCP is coordinating with for agent identity.

**W3C**

- **AI Agent Protocol Community Group:** ANP-based (see 2.4). A Community Group, so not standards track.
- **Web Machine Learning CG:** WebMCP draft report (see 2.1).
- **DID Core and Verifiable Credentials 2.0:** W3C Recommendations. These are the obvious substrate for OIP self-certifying identity and attestations.

### 2.12 Agentic AI Foundation (AAIF)

- **Formed** 9 Dec 2025 by the Linux Foundation.
  - Founding projects: MCP (Anthropic), goose (Block), AGENTS.md (OpenAI).
  - Platinum members: AWS, Anthropic, Block, Bloomberg, Cloudflare, Google, Microsoft, OpenAI.
  - Gold members include Cisco, IBM, Salesforce, SAP, Okta, Shopify and others.
- **Projects (10, as of 22 Oct 2026):**

  | Project | What it is | Joined AAIF |
  |---|---|---|
  | MCP | Agent-to-tool protocol | Dec 2025 |
  | goose | Agent runtime | Dec 2025 |
  | AGENTS.md | Guidance file for coding agents | Dec 2025 |
  | agentgateway | MCP/A2A/LLM gateway, Apache-2.0 | Jun 2026 |
  | A2A | Agent-to-agent protocol | 17 Aug 2026 |
  | Agent Router | Formerly Envoy AI Gateway; model/MCP traffic routing, *not* agent-to-agent routing | 9 Sep 2026 |
  | Agent Skills | Contributed by Anthropic | 22 Oct 2026 |
  | Open Responses | Contributed by OpenAI | 22 Oct 2026 |
  | OpenEnv | Contributed by Hugging Face | 22 Oct 2026 |
  | OpenSandbox | Contributed by Alibaba | 22 Oct 2026 |

- Three governance committees were formed in 2026. Events: AGNTCon + MCPCon (NA Oct 2026; SF Apr 2027; London Sep 2027).
- **Implication:** AAIF is the de facto centre of gravity. OIP should position as *complementary* (a coordination layer above and around AAIF protocols) and consider eventually engaging AAIF or the IETF rather than competing.

### 2.13 Other 2025–2026 entrants worth noting

- **Agent Payments Protocol (AP2, Google, Sep/Oct 2025):** an A2A/MCP extension in which **user-signed mandates** (intent and cart mandates, based on VCs) give verifiable proof of user authorisation. It has 60+ partners, including PayPal. This is the nearest existing analogue to OIP **Commitment** objects, though payment-specific.
- **x402 (Coinbase → x402 Foundation, LF; operational 14 Jul 2026):** HTTP 402-based in-request payments. 40 members including Visa, Mastercard, Stripe, Google, AWS and Cloudflare. It produces payment proofs that resemble **Receipts**.
- **Agentic Commerce Protocol (OpenAI + Stripe, Sep 2025)** and **Universal Commerce Protocol (UCP, Google, Jan 2026):** commerce flows with merchant capability profiles (UCP) and scoped payment tokens (ACP).
- **WebMCP** (see 2.1). **Block "Buzz"**: an agent workspace with per-agent identity and attestation, shown at AGNTCon, v1.0 due mid-Nov 2026 **[stage claim]**.
- **Open Responses (OpenAI → AAIF):** an open model-API format. Model-layer, not coordination.

---

## 3. Comparison table

| Protocol | Primary layer | Core primitives | Transport | Identity / auth | Discovery | Governance / licence | Adoption (late 2026) |
|---|---|---|---|---|---|---|---|
| **MCP** (2026-07-28) | Agent ↔ tool/context | Tools, Resources, Prompts; MRTR; Tasks ext; Apps ext | stdio, Streamable HTTP (stateless) | OAuth 2.1 resource server, RFC 9728/8707/9207, CIMD; agent identity on roadmap | MCP Registry (preview, reverse-DNS namespaces); `server/discover` | AAIF / LF; open source | Very high (4.17B SDK downloads claimed) |
| **A2A** (v1.0) | Agent ↔ agent task RPC | Agent Card, Task, Message, Part, Artifact, contextId | JSON-RPC, gRPC, HTTP+JSON; SSE; webhooks | OpenAPI-style schemes (OAuth/OIDC/mTLS/API key); JWS-signed cards | `/.well-known/agent-card.json`; registries | AAIF / LF (since Aug 2026); Apache-2.0 [unverified] | High (150+ orgs; Azure, AWS, GCP) |
| **ACP (IBM)** | Agent ↔ agent REST | Manifest, Run, Message, Await, Session | HTTP REST | Bearer/mTLS | Manifest endpoints | Merged into A2A; archived Aug 2025 | Legacy |
| **ANP** / W3C AI Agent Protocol CG | Identity + discovery + A2A messaging | DID doc, Agent Description (JSON-LD), meta-protocol | HTTPS; E2E messaging draft | `did:wba` (also did:web, did:webvh), HTTP Message Signatures | `.well-known/agent-descriptions`; search agents | Community + W3C CG (not standards track); MIT/Apache [uncertain] | Low–moderate (China-centric) |
| **AGNTCY** | Discovery, identity, messaging infra | OASF record, ADS, Agent Badge (VC), SLIM | SLIM (pub/sub, MLS); OCI for records | DIDs + VCs, or IdP accounts | Kademlia DHT capability index + OCI | LF Projects; Apache-2.0 [mostly, unverified] | Moderate (enterprise) |
| **NLWeb** | Website NL query | `/ask` → Schema.org JSON; `/mcp` | HTTP | Site-level | None standard | Microsoft; MIT | Moderate (publishers) |
| **Agent Protocol** | Agent control API | Task, Step, Artifact | HTTP REST (OpenAPI) | None | None | AGI Inc.; licence unstated | Low / legacy |
| **OCP (Open Cognition)** | Full stack (claimed) | Insight packages, trust bonds, consensus | Unspecified | DIDs, Ed25519 | Unspecified | "OCP Foundation"; unverified | Unverified |
| **ANTS** | P2P AI-serving network | Signed answers, semantic cache, misbehaviour chain | BitTorrent-style + DHT | Hardware-attested (1 CPU = 1 peer) | DHT | Apache-2.0 / CC0; no code yet | None (spec stage) |
| **OpenPond** | Agent network | Identity, registry, message layers | Unspecified | On-chain registration | On-chain registry | Unstated | Minimal |
| **IETF agentproto** | Dialog/context mgmt over existing protocols | Dialog ID, lifecycle, context propagation | Bindings to HTTP/QUIC/MoQ | Via OAuth/WIMSE | Out of scope (DAWN) | IETF WG; standards track by 2028 | Pre-draft |
| **ANS v2** (draft) | Naming + identity registry | ANSName, RA, transparency log, receipts | DNS (SVCB), TLS | X.509 + RA identity certs, DNSSEC/DANE | DNS-AID | Individual I-D | Early (GoDaddy registry) |
| **AP2 / x402** | Payments authorisation / settlement | Signed mandates / HTTP 402 payment proofs | Over A2A/MCP / HTTP | User-signed VCs / wallet sigs | n/a | Google-led / x402 Foundation (LF) | Growing |

### 3.1 Coverage against OIP capabilities

● = provided, ◐ = partial, ○ = absent

| OIP capability | MCP | A2A | ANP | AGNTCY | ANS v2 | agentproto | AP2/x402 |
|---|---|---|---|---|---|---|---|
| Permanent, self-certifying, host/hardware-independent address | ○ (URL) | ○ (URL/domain) | ◐ (DID, but domain-anchored `did:wba`) | ◐ (DID option) | ○ (DNS-anchored) | ○ | ○ |
| Capability routing (route by *what*, not *where*) | ○ | ○ | ○ (search) | ◐ (DHT lookup, no forwarding) | ○ | ○ | ○ |
| Signed context packets (intent + context + provenance) | ○ (`_meta` unsigned) | ◐ (signed card only; messages unsigned) | ◐ (HTTP msg sigs) | ◐ (Sigstore on records) | ○ | ◐ (context propagation, planned) | ◐ (signed mandates) |
| Session continuity across moves/forks | ○ (removed) | ◐ (contextId, server-bound) | ○ | ○ | ○ | ◐ (core aim, by 2028) | ○ |
| Native identity + delegation chains | ◐ (roadmap: WIF, ID-JAG, token exchange) | ◐ (OAuth scopes) | ◐ | ◐ (VCs, delegation governance) | ◐ | via OAuth/WIMSE | ◐ (user→agent mandate) |
| Verifiable Commitments / Receipts | ○ | ○ | ○ | ○ | ◐ (TL receipts for registrations) | ○ | ◐ (payment-only) |
| Collectives as first-class participants | ○ | ○ | ○ | ◐ (MAS records; MLS groups) | ○ | ○ | ○ |
| Humans & institutions as peer participants | ○ | ○ | ○ | ○ | ○ (orgs register agents) | ◐ (human-agent dialogs in use cases) | ◐ (humans sign mandates) |

---

## 4. Gaps OIP fills

1. **Permanent mind addresses.** Every deployed protocol identifies an agent by where it runs: an HTTPS URL, a domain, a DNS name or a hardware attestation. OIP's self-certifying address (key-derived, e.g. a hash of an inception key with pre-rotation, in the spirit of KERI) survives host, model, vendor and hardware changes. That is a property no surveyed protocol offers. Domain-anchored DIDs (`did:wba`, `did:web`) and ANS still die or fork with the domain.
2. **Capability routing.** Today, discovery and invocation are separate steps. You look up a card in a registry or DHT, then connect to an endpoint. OIP routes a request *by capability or intent* through the network: anycast to "any mind that can do X under constraints Y". AGNTCY's DHT capability index is the nearest precedent and should inform the design.
3. **Signed context packets with provenance.** MCP `_meta` and A2A Messages are unsigned and lose provenance across hops. The IETF CATALIST and agentproto work identifies context propagation as a gap but will only standardise dialog IDs and lifecycle (by 2028). OIP's signed, chain-able packets carrying intent, context and provenance fill this gap. Ideally they should be designed to be *carriable* inside agentproto dialogs.
4. **Continuity across moves and forks.** MCP deliberately removed sessions in 2026-07-28. A2A `contextId`s are bound to a server. No protocol models a mind migrating hosts or forking into copies while keeping (or explicitly splitting) conversational and contractual continuity.
5. **Commitments and Receipts as general primitives.** These exist only in payment silos: AP2 mandates, x402 payment proofs and ANS registration receipts. OIP generalises them into a protocol-wide, verifiable promise/fulfilment ledger usable for any work, data or service exchange.
6. **Collectives.** No protocol gives a group of minds its own address, membership rules, decision procedure and delegated authority. AGNTCY's "multi-agent system" records and SLIM/MLS groups are building blocks, not semantics.
7. **Humans and institutions as first-class participants.** In MCP and A2A the human is a resource owner or a "user" role behind a client. OIP makes a person, a company or a public body a Participant with the same addressing, offers and commitments as an AI.
8. **One coherent stack.** The ecosystem is a patchwork, with separate pieces for tools (MCP), tasks (A2A), discovery (AGNTCY/ANS/DAWN), identity (OAuth/WIMSE/DIDs) and payments (AP2/x402). OIP's three layers provide a unifying model and bridge to each piece.

---

## 5. What OIP should reuse or bridge (not reinvent)

### 5.1 Layer 0 Bridge targets (highest priority)

| External thing | Map to OIP | Notes |
|---|---|---|
| **MCP server** | Participant (kind: tool/service) with Offers derived from `tools/list`, `resources/list` and `prompts/list` | Use `server/discover` for capabilities and version. The address is assigned by the bridge and bound to the server's registry name (`com.example/server`) plus its canonical URI. Wrap tool calls as Intent → Commitment → Receipt, with the gateway signing receipts. Use MCP Tasks for long-running work and map MRTR `input_required` onto OIP clarifying exchanges. |
| **MCP client/host** | An OIP mind can *act as* an MCP client. Conversely, an OIP gateway can expose OIP Offers *as* an MCP server | The reverse bridge lets every MCP-capable assistant (Claude, ChatGPT, Copilot…) reach the OIP network on day one. |
| **A2A agent** | Participant (kind: agent). Agent Card skills become Offers. `SendMessage` becomes an Intent delivery. Task states map to the Commitment lifecycle; Artifacts are delivered under Receipts | Verify JWS-signed cards (JCS+JWS) and record the card hash in the OIP participant record. A2A `contextId` maps onto OIP session or continuity IDs. A2A extensions (URI-declared) offer a clean path to an **"OIP extension for A2A"** that carries OIP context packets natively. |
| **NLWeb sites** | Covered via the MCP bridge (`/mcp`). Schema.org types feed Offer descriptions | — |
| **ANP / DID-based agents** | Participant. Accept `did:wba`, `did:web` and `did:webvh` as *aliases* bound to an OIP permanent address | — |
| **AGNTCY OASF records / ADS** | Import OASF records as Participant plus Offer metadata. Optionally publish OIP participants *into* ADS | Two-way discovery federation. |
| **AP2 mandates / x402 / ACP-commerce** | Payment-bearing Commitments and Receipts | Don't build payment rails; reference them. |
| **ANS names** | Human-friendly, DNS-verified alias for an OIP address | ANS transparency-log receipts can serve as attestations. |

### 5.2 Standards and building blocks to reuse directly

- **Identity:** W3C **DID Core** and **VC 2.0** (attestations, Agent-Badge-style capability credentials). Consider **KERI**-style or `did:webvh` key event logs for rotation and pre-rotation. *[KERI not researched in this track; recommend a dedicated identity research note.]*
- **Signing and canonicalisation:** **JWS (RFC 7515) + JCS (RFC 8785)**, which keeps OIP signatures compatible with A2A signed cards. Use HTTP Message Signatures (RFC 9421) for HTTP bridge hops, and Sigstore and transparency logs (Sigstore, SCITT, the ANS TL model) for receipt anchoring.
- **Authorisation and delegation:** OAuth 2.1 plus RFC 8707/9728 (to interoperate with MCP-protected servers), RFC 8693 token exchange, the ID-JAG / enterprise-managed authorisation pattern, DPoP, and **WIMSE** workload identity. Express OIP delegation so it can be *down-converted* into these at the Bridge.
- **Group messaging:** **MLS (RFC 9420)**, as used by AGNTCY SLIM, for encrypted Collective channels.
- **Capability vocabulary:** **OASF** skills/domains taxonomy, plus Schema.org, rather than a new ontology.
- **Discovery substrate:** ideas from the AGNTCY ADS (content-addressed records plus a Kademlia capability index), DNS SVCB/DNS-AID (ANS), and `.well-known` conventions (A2A, ANP).
- **Observability:** OpenTelemetry trace context (`traceparent`), which is already the MCP convention, for cross-protocol tracing.
- **Transport:** Don't invent one. Run over HTTP/2-3, QUIC/WebTransport and MoQ as agentproto envisions, plus SLIM where present.

### 5.3 Engagement recommendations

- Publish an **"OIP context packet" A2A extension** and an **MCP extension** (via SEP-2133 experimental-ext repos). This lets OIP semantics ride on existing traffic: the fastest adoption route.
- Track and contribute to the **IETF agentproto** use-cases draft, due for adoption Dec 2026. OIP's continuity and context-packet ideas are squarely in scope, and an early contribution could shape the standard.
- Monitor **DAWN** (discovery), the **MCP Agent Identity WG**, and the **W3C AI Agent Protocol CG**.
- **Naming hygiene:** "OIP" is also used by OpenPond for its improvement proposals, and "ACP" and "OCP" each have multiple meanings. Disambiguate in the paper.

---

## 6. Uncertainties and verification notes

- Licence identifiers for MCP, A2A and AGNTCY components were not re-verified this session; GitHub API access was unavailable.
- AAIF adoption metrics (4.17B downloads, Block Buzz) are stage claims reported by InfoQ.
- The IETF agentproto charter is shown as "Approved" on the datatracker, but the page also carries a "Proposed Charter" header. Treat the WG as chartered in 2026, with the exact date unconfirmed.
- The DAWN "deferred" outcome comes from a third-party article (Forkast), not from minutes.
- OCP (Open Cognition Protocol) could not be tied to any named organisation, code or adopters.
- WebMCP details come from a third-party explainer (API moved to `document.modelContext`).
- The claim that A2A runs over SLIM is from prior knowledge and was not re-verified.

---

## 7. Sources

**MCP**
- MCP 2026-07-28 changelog — https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP authorization (2026-07-28) — https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP roadmap (updated 2026-08-22) — https://modelcontextprotocol.io/development/roadmap
- MCP Registry — https://modelcontextprotocol.io/registry/about
- MCP blog, protocol tag (release dates) — https://blog.modelcontextprotocol.io/tags/protocol/
- InfoQ, AGNTCon + MCPCon 2026 — https://www.infoq.com/news/2026/10/agntcon-mcpcon-2026/
- WebMCP status explainer — https://mcpplaygroundonline.com/blog/what-is-webmcp.md

**A2A / ACP**
- A2A specification (v1.0) — https://a2a-protocol.org/latest/specification/
- LF: A2A surpasses 150 organizations (Apr 2026) — https://linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year
- AAIF: A2A joins AAIF (17 Aug 2026) — https://aaif.io/blog/a2a-joins-aaif
- AAIF: A2A v1.0 builder's guide part 2 (security) — https://aaif.io/blog/a2a-v1-0-a-builder-s-guide-part-2-migration-security-and-production
- AAIF A2A project page — https://aaif.io/projects/agent2agent
- A2A v1.0 release summary — https://chatforest.com/guides/a2a-protocol-v1-production-ready/
- LF: A2A project launch (Jun 2025) — https://linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents
- IBM Research ACP page — https://research.ibm.com/projects/agent-communication-protocol
- ACP repo (archived) — https://github.com/i-am-bee/acp

**AAIF**
- LF: Formation of AAIF (9 Dec 2025) — https://linuxfoundation.org/press/linux-foundation-announces-the-formation-of-the-agentic-ai-foundation
- LF: AAIF four new projects (22 Oct 2026) — https://www.linuxfoundation.org/press/agentic-ai-foundation-announces-four-new-projects-agent-skills-open-responses-openenv-and-opensandbox
- AAIF: Agent Router joins — https://aaif.io/blog/agent-router-joins-aaif
- agentgateway joins AAIF — https://datacentrenews.uk/story/agentic-ai-foundation-adds-agentgateway-as-hosted-project

**ANP / W3C**
- ANP repo — https://github.com/agent-network-protocol/AgentNetworkProtocol
- W3C AI Agent Protocol CG draft — https://w3c-cg.github.io/ai-agent-protocol/protocol.html
- W3C CG minutes email (Jul 2026) — https://lists.w3.org/Archives/Public/public-agentprotocol/2026Jul/0010.html
- W3C WebEvolve 2026 talk (AWiki/ANP) — https://www.w3.org/2026/04/hangzhou-webevolve-chang-gaowei-en.pdf
- Survey of MCP/ACP/A2A/ANP (arXiv 2505.02279) — https://arxiv.org/pdf/2505.02279

**AGNTCY**
- AGNTCY docs — https://docs.agntcy.org
- AGNTCY identity spec — https://spec.identity.agntcy.org/docs/intro
- AGNTCY Agent Directory Service paper (arXiv 2509.18787) — https://arxiv.org/pdf/2509.18787
- NAND Research: AGNTCY moves to LF — https://nand-research.com/research-note-agntcy-moves-to-linux-foundation/

**Other protocols**
- NLWeb adoption 2026 — https://presenc.ai/research/nlweb-adoption-2026
- Agent Protocol README — https://raw.githubusercontent.com/agi-inc/agent-protocol/main/README.md
- Open Cognition Protocol — https://www.opencognitionprotocol.org/About-OCP
- ANTS — https://github.com/Ants-Community/ants
- OpenPond protocol — https://github.com/openpond/protocol
- Agent payment protocols compared (AP2/ACP/UCP/x402) — https://eco.com/support/en/articles/14839407-agent-payment-protocols-compared
- LF: x402 Foundation operational launch (14 Jul 2026) — https://www.linuxfoundation.org/press/linux-foundation-announces-operational-launch-of-x402-foundation-to-standardize-internet-native-payments-for-ai-agents-and-applications

**IETF**
- agentproto WG — https://datatracker.ietf.org/wg/agentproto/about/
- agentproto BoF minutes (IETF 126) — https://datatracker.ietf.org/meeting/126/materials/minutes-126-agentproto-202607230700-00
- IETF 126 BoFs (agentproto, DAWN, DMSC) — https://www.ietf.org/blog/ietf126-bofs/
- CATALIST problem-space draft — https://www.ietf.org/archive/id/draft-yao-catalist-problem-space-analysis-01.html
- ANS v2 draft — https://datatracker.ietf.org/doc/html/draft-narajala-courtney-ansv2
- Forkast: IETF agentproto outcome — https://forkast.news/ietf-bets-on-agent-interoperability-but-the-scope-fight-is-just-beginning/
- Forkast: IETF agent identity drafts — https://forkast.news/the-ietf-published-a-draft-for-agent-identity-the-market-already-shipped/
