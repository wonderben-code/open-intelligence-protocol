# Research 03 — Network, Resolution, Discovery and Routing

**Track:** building blocks and prior art for OIP Layer 1 (Mind Network) and the network side of Layer 0 (Bridge).
**Date of survey:** 30 October 2026.
**Status:** research input to the technical architecture paper. Not normative.

Conventions: facts verified against a primary source during this survey are cited in the Sources list. Points drawn from general background knowledge rather than re-verified today are marked *(background)*. Points we could not confirm are marked *(unverified)*.

---

## 1. Summary

Every requirement of Layer 1 already exists somewhere. Nothing combines them all. The closest models are:

- **Identity that does not depend on the host: AT Protocol.** A DID document names the current host (PDS) and signing key. Moving to another host means updating the DID document, and relays then announce an identity event. Account migration works in production, including "adversarial" migration when the old host will not cooperate. The AT Protocol Working Group at the IETF was approved in March 2026.
- **A self-certifying identifier with a verifiable history, served over plain HTTPS: did:webvh v1.0** (DIF, August 2025) and **did:plc**. Both use a hash-chained log of signed key and endpoint updates. Each identifier is derived from the hash of its first entry.
- **Dialling a key, not an IP address: libp2p** (peer IDs, Kademlia DHT, Circuit Relay v2, DCUtR hole punching) and **iroh 1.0** (June 2026: QUIC, relays and multipath, all addressed by public key).
- **Discovery by capability, without a central registry: AGNTCY Directory v1.0** (February 2026). Records are content-addressed (CIDs). A libp2p Kad-DHT maps OASF skill taxonomy entries to CIDs and then to the servers that hold them. Other designs: **A2A Agent Cards** at `/.well-known/agent-card.json` (A2A v1.0, March 2026, JWS-signed over RFC 8785 JCS); **DNS-AID** (SVCB records for agents, IETF draft); **NANDA** (a lean index plus AgentFacts); and embedding-based semantic routing research (**Federation of Agents**).
- **Signed messaging and routing through intermediaries: DIDComm v2.1.** It defines envelopes for DID-addressed messages, thread IDs (`thid`/`pthid`), and `forward` messages through mediators.
- **Continuity:** QUIC connection migration (RFC 9000), with Multipath QUIC approved and in the RFC Editor queue. Signal's Double Ratchet, extended in October 2025 to a post-quantum "Triple Ratchet". MLS (RFC 9420) for groups. CRDTs (Automerge 3) for state shared across moves.

**Recommendation for v1.** OIP should not invent a new transport or a new DHT. The weekend-sized v1:

1. A **self-certifying mind address**: the hash of a signed genesis record, plus an append-only signed **key and location log** in the style of did:webvh/did:plc. Each mind gets a DID-compatible form (`did:oip:…`).
2. **Signed location records** served at `/.well-known/oip/…` on any host. Anyone can run a resolver that caches them, and a DHT or Pkarr is optional.
3. **Signed capability descriptors** that are a superset of A2A Agent Cards and use OASF tags. Anyone can run an **open indexer** (AT-Proto relay/AppView pattern), and indexers answer structured and semantic capability queries with results the client can verify.
4. A **context packet**: a JCS-canonicalised, Ed25519-signed JSON envelope that maps onto DIDComm and A2A messages.
5. **HTTPS POST and WebSocket bindings** first. A libp2p or iroh binding comes later under the same packet format.
6. **Sessions** defined by a relationship ID plus a hash-linked packet chain, so either party can resume after a move, a pause or an upgrade.

The full design is in §5.

---

## 2. Requirements recap (from the founding paper)

| ID | Requirement | Implication for building blocks |
|---|---|---|
| R1 | Permanent address derived from keys, with no registry and no machine binding | Self-certifying identifier, plus key rotation that does not change the address |
| R2 | Resolve address to current location(s); mind moves, runs in many places, forks | Mutable, signed, versioned location records; multiple endpoints; fork lineage |
| R3 | Route by capability and track record | Capability descriptors, a query mechanism, links to evidence (Layer 2 receipts) |
| R4 | Signed context packets (content, intent, context, provenance, constraints) | Envelope format, canonicalisation, signatures, optional encryption |
| R5 | Continuity across moves, pauses and upgrades | Session identity separate from the transport connection; resumable logs |
| R6 | Transport-agnostic; today's internet first | HTTP and WebSocket bindings now; P2P later |
| R7 | Permissionless yet practical for v1 | Anyone can run any server role; nothing is required except a web host |

---

## 3. Survey of building blocks

### 3.1 libp2p

**What it is.** A modular peer-to-peer networking stack. It began inside IPFS and is now also used by Ethereum consensus clients, Filecoin and others. It is implemented in Go, Rust, JS, Nim, Java, Python and other languages.

- **Peer IDs:** a multihash of the peer's public key (Ed25519, secp256k1, RSA or ECDSA), so every peer has a self-certifying identity *(background)*.
- **Multiaddrs:** self-describing composable addresses, for example `/ip4/…/udp/…/quic-v1/p2p/<peerID>` *(background)*.
- **Transports:** TCP, QUIC, WebSockets, WebTransport and WebRTC (browser-to-server and browser-to-browser). js-libp2p is at the 3.x line, and packages for `@libp2p/webrtc`, `@libp2p/webtransport` and `@libp2p/websockets` were being released through 2026.
- **Kademlia DHT:** peer routing and provider records. IPFS's public "Amino" DHT returns at most 20 closest peers.
- **GossipSub:** pubsub over a mesh. v1.1 added peer scoring. v1.2 added `IDONTWANT` to cut duplicate large messages, and Ethereum adopted it on mainnet. v2.0 proposals are under discussion *(v2.0 status unverified)*.
- **NAT traversal:** AutoNAT checks whether a node can be dialled (the STUN analogue). AutoRelay finds relays. Circuit Relay v2 gives limited, reservation-based relaying (the TURN analogue) that any public node can provide. DCUtR then upgrades to a direct connection with a synchronised simultaneous dial. libp2p's docs do not publish a success rate.

**Maturity.** High. It has been in production for years at large scale.

**What OIP can reuse directly.**
- The peer-ID-from-public-key pattern. An OIP mind key can also serve as its libp2p peer key, or the location record can list peer IDs as endpoints.
- Multiaddrs as an endpoint encoding inside location records.
- Kad-DHT as an optional resolution backend (put/get a signed location record under hash(address)).
- GossipSub for capability-topic broadcast in a later decentralised phase.
- Circuit Relay v2 and DCUtR so minds running on laptops or phones can be reached.

**Limitations.** Heavy for a weekend v1. A peer ID identifies a *process/key*, not a mind that rotates keys, so OIP needs its own rotation layer. Browser support is improving but has rough edges. The public DHT is a poor fit for frequently changing records unless TTLs are tuned. Peer IDs carry no capability semantics.

### 3.2 iroh (n0)

**What it is.** A Rust library (with Python, Node.js, Swift and Kotlin bindings) for dialling a peer by its public key over QUIC. It handles relays, hole punching and its own QUIC multipath. **iroh 1.0 shipped on 15 June 2026** with stable wire and language APIs. n0 runs public relays and reports more than 200M endpoints created in 30 days. The relay code is open source. n0 says about 95% of connection data typically flows directly.

**Reuse.** A strong candidate for the **v2 P2P binding**: "dial the mind's current endpoint key". It is simpler than full libp2p when OIP only needs connectivity, not a DHT or pubsub. Address discovery for iroh endpoints has historically used DNS and Pkarr *(background; not stated in the 1.0 post)*.

**Limitations.** Rust-centric. Public relays are a convenience service run by n0, and deployments can self-host. It does not offer capability discovery or pubsub at the same level as libp2p.

### 3.3 Pkarr (Public-Key Addressable Resource Records)

**What it is.** DNS packets signed by an Ed25519 key and stored as BEP44 mutable items in the **BitTorrent Mainline DHT**, which has millions of nodes and needs no new network. HTTP relays let browsers publish and resolve. Packets are limited to **1,000 bytes**. Records expire after a few hours and must be republished.

**Reuse.** A very cheap, permissionless, optional **second resolution path** for OIP location records: a compact pointer such as "my location record lives at these URLs or these endpoints".

**Limitations.** The size cap rules out full descriptors, so it can carry pointers only. Mainline offers no strong guarantees, and records need republishing.

### 3.4 IPFS, content addressing and multiformats

**What it is.**
- **CIDs:** self-describing content hashes made of a multibase prefix, version, multicodec and multihash *(background)*.
- **Multiformats:** multihash, multibase, multicodec, multiaddr and multikey *(background)*. DID v1.1 and AT Protocol both use **Multikey/`publicKeyMultibase`**.
- **IPNS:** signed, mutable name records keyed by public key.
- **Delegated Routing V1 HTTP API:**
  - `GET /routing/v1/providers/{cid}`
  - `GET /routing/v1/peers/{peer-id}`
  - `GET|PUT /routing/v1/ipns/{name}`
  - the optional `/dht/closest/peers/{key}`
  - JSON or NDJSON responses, cache headers, CORS. It lets light and browser clients use a DHT through any HTTP server.

**Reuse.**
- Use **multibase, multihash and Multikey encodings** for addresses and keys. This aligns with DIDs, AT Proto and libp2p.
- Use **CIDs** to name immutable objects: capability descriptor versions, packet bodies and attachments. AGNTCY does this too.
- Copy the **Delegated Routing pattern** for OIP resolvers: a simple HTTP API in front of whatever resolution backend is used (cache, DHT, Pkarr). In particular, `GET /resolve/{address}` should return a signed record that any client can verify independently of the server.

**Limitations.** Content addressing alone does not handle mutability. IPNS is slow on the public DHT *(background)*.

### 3.5 AT Protocol (Bluesky)

**What it is.** A federated protocol whose central design choice is **identity independent of host**.

- **Identity:** each account is a DID. Only `did:plc` and `did:web` (hostname-level only) are supported. The DID document holds:
  - the signing key (a `#atproto` Multikey verification method),
  - the current host (service `#atproto_pds`, type `AtprotoPersonalDataServer`),
  - the human handle (`alsoKnownAs: at://handle`), which must be verified in both directions (DNS TXT or HTTPS well-known per the handle spec *(background)*).
- **did:plc:** a self-authenticating DID with a signed, hash-chained operation log and **rotation keys** separate from the signing key. It is hosted by the PLC directory.
  - **February 2026:** read-replica reference implementation released. Replicas sync via `/export` and the `/export/stream` WebSocket (PLC spec 0.3.0), verify every operation's hash, signature and timestamp, and act as **witnesses** against the primary. A full replica is about 150 GB.
  - Work to create an **independent PLC organisation** is ongoing, and WebPKI-style transparency logging is planned.
- **Account migration:**
  1. Create a deactivated account on the new PDS, proving DID control with a service-auth token.
  2. Export the repo as a CAR file and import it. Copy blobs and preferences.
  3. Update the DID document (new PDS endpoint and signing key; a self-held rotation key is recommended).
  4. Activate the new account and deactivate the old one.

  If the old PDS is uncooperative, a self-held rotation key allows **adversarial migration**. Firehose consumers see an `#identity` event, and other caches converge later.
- **Repos, relays, AppViews:** each account has a signed Merkle repo. Relays aggregate every PDS into a **firehose**. The `bsky.network` relay moved to **Sync 1.1** in January 2026, and **Tap**, a self-hosted sync consumer, was released in December 2025. AppViews build indexes from the firehose. Anyone can run any of these roles.
- **Lexicons:** namespaced (reverse-DNS) schemas for records and XRPC methods *(background)*.
- **Standardisation:** IETF BoF held at IETF 124. **ATP working group approved in late March 2026.**

**Reuse for OIP.**
- **The model itself:** address → (keys, current host endpoint), with host moves done by a signed log update. This is exactly R1 and R2.
- **The role split:** hosts (PDS), **aggregators** (relays/firehose) and **indexers** (AppViews) are all permissionless roles. OIP's capability indexers should copy this. A mind publishes its descriptor on its own host. Anyone can crawl or subscribe, and anyone can build an index.
- **Rotation keys separate from operational keys**, and adversarial migration.
- **Witness replicas** to hold the log operator to account.
- **Reverse-DNS namespaced schemas** for extensions (Lexicon-style).

**Limitations.**
- `did:plc` still depends on one directory operator (mitigated by replicas and planned independence).
- `did:web` ties identity to a domain.
- Exactly one PDS per account. AT Proto does not model "runs in many places" or forks.
- Permissioned or private data is still being designed (a 2026 focus).
- It was designed for public social data, not for request/response coordination.

### 3.6 ActivityPub and ActivityStreams 2.0

**What it is.** A W3C Recommendation (2018) for federation:
- every actor has an **inbox and outbox**;
- servers POST activities to inboxes, authenticated in practice with HTTP Signatures;
- ActivityStreams 2.0 provides the JSON-LD vocabulary (Create, Offer, Accept, Reject, Question, etc.) *(background)*.

**2026 state.**
- A new **W3C Social Web Working Group** (announced 15 January 2026) is revising AP and AS2 backwards-compatibly, targeting Q3 2026. Whether it shipped on time is *unverified*.
- It is also standardising **LOLA**, a live account-portability protocol: OAuth-authorised copy from the old server, then follower notification and redirects.
- DTI (May 2026) still described account portability as incomplete.
- **FEP-ef61 "Portable Objects"** (draft) proposes `ap://did:key:…/path` identifiers whose authority is a DID, not a host. It adds an ordered `gateways` list (HTTP servers that hold the latest copy, fetched via `/.well-known/apgateway/…`), mandatory integrity proofs (FEP-8b32), and `@gateway` location hints in references.

**Reuse.**
- The **inbox pattern** (HTTP POST of signed objects) as the simplest transport binding.
- **AS2 vocabulary** as inspiration and a Bridge mapping for Layer 2 intents and offers (Offer/Accept/Reject).
- **FEP-ef61's `gateways` list and location hints.** This is nearly the design OIP needs for multi-host minds.

**Limitations.**
- Identity is tied to the server domain; portability is still unsolved in practice.
- JSON-LD processing is heavy.
- There is no capability discovery beyond WebFinger and profiles.

### 3.7 Nostr

**What it is.** A minimal protocol in which **a secp256k1 key is the identity**. Signed JSON events go to dumb **relays** over WebSockets, and NIPs add features.

| NIP | What it adds |
|---|---|
| NIP-01 | Events, REQ/EVENT messages |
| NIP-05 | Maps a key to a DNS name via `/.well-known/nostr.json` |
| NIP-19 | Bech32 encodings |
| NIP-42 | Relay authentication |
| NIP-44 | Versioned encryption |
| NIP-17 + NIP-59 | Private DMs with "gift wrap" metadata hiding |
| NIP-46 | Remote signing |
| NIP-65 | Relay list metadata: a replaceable kind-10002 event listing a user's write and read relays (the "outbox model"). Clients fetch a user's events from their write relays and deliver mentions to their read relays. 2–4 relays per category is recommended. |
| NIP-89 | Recommended application handlers |

**NIP-90 "Data Vending Machines".** This was an attempt at a job and capability marketplace over Nostr. It is now **marked "unrecommended"** in the NIPs index, which says it "got totally out of control" and recommends use-case-specific micro-standards instead.

**Reuse.**
- **Keys as identity.**
- **NIP-65 outbox model:** a signed, replaceable "where to reach me" record. This is a direct analogue of OIP location records.
- **Dumb relays that anyone can run.**
- **NIP-05-style** `.well-known` mapping from a human name to a key.

**Limitations.**
- There is no key rotation, so losing the key means losing the identity. This is the major gap for "permanent" addresses.
- Relays do not guarantee delivery or storage.
- **Lesson from NIP-90:** an over-general capability and job schema degenerates. OIP should keep the capability core minimal and push domain semantics into namespaced extensions.

### 3.8 Matrix

**What it is.** A federated real-time communication protocol.
- **Rooms** are replicated event DAGs, and homeservers reach eventual consistency with a state-resolution algorithm.
- Server discovery uses `/.well-known/matrix/server` and SRV records *(background)*.
- E2EE uses Olm/Megolm *(background)*.
- **Matrix 1.19** (8 July 2026) added encrypted room-history sharing (MSC4268) and image packs, among others.
- Portable accounts and pseudonymous identities (MSC4014, "pseudo IDs") remain proposals and are not in the spec *(status as of this survey; MSC4014 is a draft PR)*.

**Reuse.**
- The **replicated, signed, hash-linked event DAG** with deterministic conflict resolution is a model for **multi-party sessions and collectives** (Layer 2), and for keeping a session consistent when a mind runs in several places.
- `.well-known` server delegation.

**Limitations.**
- User IDs are still bound to homeserver domains.
- State resolution is complex.
- The design is heavy for a v1.

### 3.9 DIDComm Messaging v2.1 (DIF)

**What it is.** A transport-agnostic, asynchronous, simplex messaging format between DIDs. Its status is "Working Group Approved".

- **Plaintext message:** `id` and `type` are required. Optional: `from`, `to`, `thid` (thread), `pthid` (parent thread), `created_time`, `expires_time`, `body`, `attachments`.
- **Signed (JWS) form:** gives non-repudiation.
- **Encrypted (JWE) form:**
  - *authcrypt* (ECDH-1PU), which authenticates the sender, is the default;
  - *anoncrypt* (ECDH-ES) hides the sender;
  - X25519 and P-384 are required, with A256CBC-HS512.
- **Routing:** **`forward` messages** through **mediators**, which re-wrap per hop and cannot read contents. The DID document advertises a `DIDCommMessaging` service endpoint.
- **Threading:** `please_ack` and `ack` for acknowledgements.
- **Out-of-band invitations** carry goal codes.
- **Transports:** HTTPS and WebSockets, among others.

**Reuse.**
- The **header set** (id/type/from/to/thid/pthid/created/expires) is a good, proven core for OIP context packets. OIP should keep field names compatible so a DIDComm binding is a pure re-encoding.
- **Mediators** solve "the mind is offline, paused or behind NAT": an always-on mailbox that holds packets until the mind resumes. This directly serves R5.
- Out-of-band invitations work as a Bridge pattern (QR code or link to start a session).

**Limitations.**
- JOSE/JWE complexity and multiple key types are a lot for a weekend implementation.
- There is no capability discovery.
- Ecosystem adoption is concentrated in SSI and wallet communities.
- Sessionless by design. Continuity has to be layered on top through threads.

### 3.10 NATS and MQTT

**NATS.**
- Dot-separated hierarchical **subjects** with wildcards: `*` matches one token and `>` matches the trailing tokens.
- **Queue groups** for load balancing, request-reply, and a reserved `$SRV` prefix for the Service API (service discovery and stats).
- Clustering and leaf nodes allow federation *(background)*.

**MQTT 5.**
- Topic hierarchies with `+` and `#` wildcards.
- **Shared subscriptions** (`$share/group/topic`) for load balancing.
- Retained messages and user properties *(background)*.
- The *Federation of Agents* research system runs its semantic task routing on MQTT pub/sub.

**Reuse.**
- **Hierarchical capability subjects plus "any one of the group answers" semantics** map exactly onto capability routing. For example, publish a request to `cap.translate.sw.law.commercial` and a queue group of capable minds receives it, with any one answering. OIP can define a **capability subject syntax** (derived from OASF taxonomy paths) so that any NATS or MQTT broker, or later GossipSub topics, can act as a capability router.

**Limitations.**
- Brokers are trusted, centralised infrastructure per deployment.
- Neither carries identity or signatures natively (OIP's envelope supplies them).
- Exact-match subjects cannot express "good track record" or fuzzy semantics. They need an index or ranking layer on top.

### 3.11 DNS, DNS-SD, SVCB and `.well-known`

**Background.**
- RFC 8615 defines `/.well-known/`.
- DNS-SD (RFC 6763) uses `_service._proto` PTR, SRV and TXT records *(background)*.
- SVCB and HTTPS records (RFC 9460) carry endpoint parameters.

**Agent-specific drafts in 2026.**
- **DNS-AID** (`draft-mozleywilliams-dnsop-dnsaid-02`, May 2026; Infoblox, Deutsche Telekom, Amazon and others; Standards Track individual draft).
  - Each agent gets an **SVCB record** at its owner name. The record carries host, port, ALPN, a well-known path, a capability-descriptor locator and a `cap-sha256` digest.
  - There is one record per agent protocol (`alpn=mcp…`, `alpn=a2a…`), with an experimental `bap` parameter.
  - An org index lives at `_index._agents.<domain>`.
  - DNSSEC is recommended, with optional DANE/TLSA.
  - **Cross-organisation capability search is explicitly out of scope.**
- **ANS / ANSv2** (`draft-narajala-ans`, expired; replaced by `draft-narajala-courtney-ansv2`, "domain-anchored identity layer"): a PKI-based agent naming registry.
- **AINS** (`draft-vandemeent-ains-discovery-02`, September 2026, Informational individual draft): a logical agent namespace resolved over HTTPS to JSON records (endpoint, capabilities, evidence references, "route posture"). Registries federate through **signed append-only change logs with optional Merkle proofs**, and **evidence is kept separate from trust scores**.
- **draft-song-anp-ans-00** (March 2026): ANP's name service *(not reviewed in detail)*.

**Reuse.**
- `.well-known` as the universal v1 publication point.
- **DNS-AID SVCB records** as an *optional* Bridge-layer way to point from a domain to an OIP mind (a `bap=oip` record).
- AINS's two ideas, evidence separate from scores and registry federation by signed change logs, align with OIP philosophy.

**Limitations.** DNS names are rented, not self-certifying, so they fail R1 as a root of identity. They are useful only as *aliases* (like AT Proto handles).

### 3.12 Agent cards, directories and capability schemas

**A2A v1.0** (released 12 March 2026; Linux Foundation in June 2025, then the **Agentic AI Foundation**).
- **Agent Card** at `/.well-known/agent-card.json` (IANA registration template included). Fields include name, description, provider, version, capabilities (streaming, push, extended card), default input/output modes, **skills**, and **`supportedInterfaces`** (protocolBinding + URL + version, in preference order).
- Bindings: JSON-RPC, gRPC and HTTP+JSON, which must be functionally equivalent.
- **Signed cards:** optional JWS signatures over the card canonicalised with **RFC 8785 JCS**, with the `signatures` field excluded. Multiple signatures support key rotation.
- **Extended cards** require authentication.
- Discovery is via well-known URI, curated registries, or direct configuration.
- Tasks carry a `contextId` that groups related tasks and messages.

**AGNTCY** (LF project).
- **Directory v1.0** (19 February 2026):
  - Records are named by **CIDs** and distributed as OCI artifacts (any OCI registry, reference store zot).
  - **libp2p Kad-DHT** maps OASF skill and domain taxonomy entries → record CIDs → hosting servers.
  - Signing is via OIDC or keys, with `dirctl verify` and SPIFFE/SPIRE mTLS.
  - Search can filter by skill and domain, for example `natural_language_processing/*`.
  - SDKs and an MCP server are available.
  - Cross-network federation is on the roadmap.
- **OASF** (Open Agentic Schema Framework): hierarchical skills and domains taxonomy with modules for A2A and MCP metadata.
- **SLIM v1.0** (February 2026; IETF draft `draft-mpsb-agntcy-slim-02`, July 2026):
  - hierarchical **`org/namespace/service/instance`** names (DID-based) with **anycast** to any instance of a service;
  - MLS (RFC 9420) end-to-end encryption through routers;
  - HTTP/2 / gRPC base;
  - point-to-point and group sessions.

**MCP Registry** (still **preview**).
- Central metadata registry with reverse-DNS names (`io.github.user/server`) verified by GitHub, DNS or HTTP challenge, and `server.json` metadata.
- Designed to be consumed by **downstream sub-registries and aggregators** that implement the same OpenAPI and poll it hourly.

**NANDA** (MIT-led, v0.3 RFC).
- A **lean index** of about 120-byte signed `AgentAddr` records pointing to **AgentFacts** (JSON-LD, ideally VC-signed capability and evaluation documents).
- Tiered TTLs: 1–6 hours for static endpoints, 5–15 minutes for rotating ones, 30–60 seconds for adaptive routing tokens.
- A privacy-preserving `PrivateFactsURL`.

**ANP (Agent Network Protocol).**
- `did:wba` (web-based DIDs).
- JSON-LD agent descriptions discovered at `/.well-known/agent-descriptions` or via search services.
- Natural-language **meta-protocol negotiation**.

**Reuse for OIP.**
- Make the OIP capability descriptor **a strict superset of the A2A Agent Card**. Any A2A agent is then an OIP mind with only a wrapper, and any OIP mind can emit a valid A2A card.
- Use **OASF taxonomy paths** as the structured capability vocabulary, while allowing free-text and other taxonomies.
- Copy **JCS + JWS signatures** (or plain Ed25519 over JCS) for descriptors.
- Copy **AGNTCY's two-phase DHT mapping** (capability → record CIDs → hosts) for the decentralised phase.
- Copy **NANDA's split** between a tiny, stable address record and a rich, separately updatable facts document, plus its TTL tiers.
- Copy **SLIM's anycast-to-service-instances** for "a mind running in many places".

**Limitations.**
- A2A identity is the domain or URL. There is no portable identity and no capability search.
- The MCP Registry is centralised by design.
- AGNTCY uses OIDC/SPIFFE trust, which is enterprise-oriented.
- None ties capability claims to verifiable track record. OIP Layer 2 receipts fill that gap.

### 3.13 Semantic and embedding-based capability routing

**Federation of Agents** (arXiv 2509.20175, September 2025).
- **Versioned Capability Vectors**: machine-readable profiles with embeddings, cost and limits.
- **Semantic routing** over **sharded HNSW** indices with cost-biased optimisation, task decomposition into DAGs, and clustering, all over MQTT.
- Reported a 13x improvement over single-model baselines on HealthBench. This is a research claim and has not been independently reproduced here.

Other registry surveys, such as arXiv 2508.03095 (centralised vs enterprise vs distributed agent registries), are useful background.

**Implications.**
- Embeddings are good for recall ("roughly who can do this?"). They are **not verifiable** and are **model-dependent**: vectors from different embedding models do not compare.
- OIP should therefore treat embeddings as an **indexer-side concern**. A descriptor carries text and structured tags. An indexer may compute embeddings with any model, and a query carries text or tags, not raw vectors. If vectors are ever exchanged, they must carry the embedding model identifier.
- Ranking by "good track record" must point to **verifiable evidence** (Layer 2 receipts) and leave scoring to the querying mind or the indexer it chooses. This follows AINS's evidence-not-score principle.

### 3.14 Session continuity mechanisms

- **QUIC connection migration (RFC 9000)** *(background)*: connection IDs decouple a connection from the IP/port 4-tuple, so a client can change networks without breaking the connection.
  - Server migration is limited (preferred address only). `draft-kozuka-quic-server-migration-00` (January 2026) proposes more.
  - **Multipath QUIC** (`draft-ietf-quic-multipath-21`) is IESG-approved and in the RFC Editor queue. No RFC number had been assigned by October 2026.
  - *Lesson:* separate the **session identifier** from the **path**. This works only within one live connection, not across a pause of a week or a move between hosts.
- **Signal Double Ratchet + X3DH/PQXDH** *(background)*, extended on **2 October 2025** with **SPQR** (an ML-KEM-based Sparse Post-Quantum Ratchet) into a **Triple Ratchet**. It gives forward secrecy and post-compromise security on long-lived, asynchronous sessions that survive arbitrary offline periods.
  - *Lesson:* session state that persists asynchronously is the right model for minds that pause.
  - *Caveat:* ratchet state must move with the mind when it changes host. Forked copies sharing ratchet state break the ratchet, so **forks must start new sessions**.
- **MLS (RFC 9420)** *(background)*: group key agreement with efficient add and remove. SLIM uses it. It suits collectives and multi-instance minds, where each instance is a group member.
- **CRDTs:** **Automerge 3.0** (July 2025) cut memory use by more than 10x by keeping the compressed format at runtime. It has a sync protocol, and iroh ships an Automerge integration. *Lesson:* shared session state (working memory of a joint task) can be a CRDT document whose ID is part of the session. It then merges correctly after partitions, moves and multi-instance writes.

---

## 4. Comparison table

Legend: ✔ native · ◐ partial or by extension · ✘ absent.

| System | Self-certifying ID | Key rotation, same ID | Host-independent identity | Multi-host / forks | Capability discovery | Signed messages | Offline/async delivery | Runs on plain HTTP/WS | Maturity (Oct 2026) | Best thing for OIP to take |
|---|---|---|---|---|---|---|---|---|---|---|
| libp2p | ✔ peer ID | ✘ | ✔ (per key) | ◐ | ◐ provider records | ✔ (transport) | ✘ | ◐ WS/WebTransport | Production | Multiaddrs, DHT, relay + hole punching, GossipSub |
| iroh 1.0 | ✔ | ✘ | ✔ | ✘ | ✘ | ✔ (transport) | ✘ | ◐ via relays | 1.0 stable (June 2026) | v2 "dial-by-key" binding |
| Pkarr | ✔ | ✘ | ✔ | ✘ | ✘ | ✔ records | n/a | ✔ via relays | Stable, niche | Optional DHT pointer to location record |
| IPFS / CIDs / multiformats | ✔ content | ◐ IPNS | ✔ | ✔ content | ◐ providers | ✔ IPNS | n/a | ✔ delegated routing | Production | Encodings; resolver HTTP API pattern |
| AT Protocol | ✔ (plc) | ✔ rotation keys | ✔ | ✘ one PDS | ◐ via AppViews | ✔ repo commits | ◐ | ✔ | Production; IETF WG 2026 | Host-move model, relay/indexer roles, witnesses |
| did:webvh | ✔ SCID | ✔ | ◐ (portable if configured) | ✘ | ✘ | ✔ log | n/a | ✔ | v1.0 (August 2025), 3 implementations | Hash-chained log served over HTTPS |
| ActivityPub (+FEP-ef61) | ◐ (ef61 draft) | ◐ | ◐ (ef61) | ◐ gateways | ✘ | ◐ HTTP Sigs / proofs | ✔ inbox | ✔ | Production; WG revising | Inbox POST; `gateways` list |
| Nostr | ✔ key | ✘ | ✔ | ◐ many relays | ✘ (NIP-90 deprecated) | ✔ | ◐ relays | ✔ WS | Production, small | Outbox/relay-list record |
| Matrix | ✘ (server-bound) | ◐ | ✘ | ✔ replicated rooms | ✘ | ✔ | ✔ | ✔ | Production | Signed event DAG for group sessions |
| DIDComm v2.1 | via DIDs | via DID method | ✔ | ◐ | ✘ | ✔ JWS/JWE | ✔ mediators | ✔ | WG approved; niche adoption | Header set, threads, mediators |
| NATS / MQTT | ✘ | ✘ | ✘ | ✔ queue groups | ◐ subjects | ✘ | ◐ (JetStream / retained) | ◐ (WS supported) | Production | Capability subject hierarchy + anycast |
| DNS / DNS-AID | ✘ (rented) | n/a | ✘ | ◐ | ◐ known-org only | ◐ DNSSEC | n/a | ✔ | Drafts | Optional domain alias → mind |
| A2A v1.0 | ✘ (URL) | ◐ multi-sig | ✘ | ◐ interfaces | ◐ well-known card | ◐ signed cards | ◐ push | ✔ | 1.0 (March 2026), AAIF | Card schema; JCS signing; Bridge target |
| AGNTCY Dir / OASF / SLIM | ✔ CIDs | ◐ | ◐ | ✔ anycast | ✔ taxonomy + DHT | ✔ | ◐ | ◐ (gRPC/OCI) | v1.0 (February 2026) | Taxonomy; capability→CID→host DHT; anycast |
| MCP Registry | ✘ | ✘ | ✘ | ✘ | ✔ central | ✘ | n/a | ✔ | Preview | Sub-registry mirroring pattern |
| NANDA | ◐ | ◐ | ◐ | ◐ | ✔ via AgentFacts | ✔ | n/a | ✔ | RFC / research | Lean address vs rich facts; TTL tiers |
| Federation of Agents | ✘ | ✘ | ✘ | ✔ | ✔ semantic | ✘ | ◐ | ◐ MQTT | Research | Indexer-side embedding routing |

---

## 5. Recommended design: OIP Layer 1 v1

Design rule: **every role is a plain HTTPS server anyone can run, every record is self-verifying, and no server is trusted for integrity, only for availability.** A weekend v1 needs Ed25519, SHA-256, RFC 8785 JCS, base58btc/multibase, HTTPS and WebSocket, all of which have mature libraries in every language.

### 5.0 Primitives

- **Crypto suite v1:**
  - Ed25519 signatures.
  - SHA-256 multihash.
  - X25519 + HPKE (RFC 9180) for optional encryption *(background)*.
  - Keys encoded as **Multikey** (`z6Mk…` for Ed25519), matching DID v1.1 (W3C CR, 5 March 2026), AT Proto and libp2p.
- **Canonical form:** RFC 8785 JCS. A signature is Ed25519 over `JCS(object without "sig")`, carried as `"sig": {"kid": "...#k1", "alg": "Ed25519", "value": "<base64url>"}`. A JWS form can be added for A2A compatibility.
- **Every signed object** carries `type`, `v` (protocol version), `issued` and `kid`.

### 5.1 (a) Mind address and resolution

**Address.** The address is a self-certifying identifier derived from a **genesis record**, in the style of did:plc and did:webvh SCIDs:

```
genesis = {
  type: "oip.genesis", v: 1,
  keys: { sign: [<multikey>], rotate: [<multikey>] },   // rotation keys separate from operational keys (AT Proto lesson)
  next_rotate_hash: <sha256 of next rotation key>,      // optional pre-rotation commitment
  kind: "agent" | "human" | "collective" | "institution",
  parent: <mind address> | null,                        // fork lineage
  created: <RFC3339>
}
mind_id  = base58btc( multihash_sha256( JCS(genesis) ) )   // e.g. "zQm..."
address  = "oip:" + mind_id            // canonical
did      = "did:oip:" + mind_id        // DID-compatible alias, so DID tooling and DIDComm work
```

The address never changes. Keys change through the log. Hosts change through location records.

**Key log (identity state).** An append-only list of signed operations, each with `prev` set to the hash of the previous operation:
- `rotate` (new signing or rotation keys; signed by a current rotation key)
- `fork` (signed by the parent: "child X is a fork of me at state hash H")
- `merge`
- `alias` (bidirectional link to a DNS name or other DIDs, like AT Proto handles)
- `tombstone`

Anyone can verify the whole chain from genesis. This is did:webvh/did:plc semantics without a privileged directory.

**Location record** (mutable, short-lived, signed by a current *signing* key):

```json
{
  "type": "oip.location", "v": 1,
  "mind": "oip:zQm…",
  "seq": 42,                         // monotonic; higher wins
  "log_head": "<hash of latest key-log op>",
  "endpoints": [
    {"id": "e1", "binding": "https", "url": "https://host-a.example/oip/v1", "priority": 10, "instance": "i-7f3"},
    {"id": "e2", "binding": "wss",   "url": "wss://host-b.example/oip/v1",   "priority": 20, "instance": "i-91c"},
    {"id": "e3", "binding": "mailbox","url": "https://mediator.example/oip/v1/mbox/zQm…", "priority": 90},
    {"id": "e4", "binding": "libp2p","addr": "/dns4/…/udp/4001/quic-v1/p2p/12D3…", "priority": 30}
  ],
  "descriptor": "<CID of current capability descriptor>",
  "status": "active" | "paused" | "migrating",
  "resume_after": "<RFC3339, optional>",
  "ttl": 900,
  "issued": "2026-10-30T09:00:00Z",
  "sig": {…}
}
```

- **Many places at once:** several endpoints, each with an `instance` tag, give SLIM-style anycast. A sender may hit any one. A sender that pins `instance` gets unicast.
- **Paused:** `status: paused`, plus a **mailbox** endpoint (the DIDComm mediator pattern), keeps the mind reachable while it is offline.
- **Moves:** publish `seq+1` with new endpoints. Old hosts SHOULD serve a redirect to the new record for one TTL, though this is not required, because adversarial moves must work too.

**Publication and resolution (layered, all optional except one).**
1. **Self-hosted well-known (required for v1):** `GET https://<any-host>/.well-known/oip/mind/<mind_id>` returns `{genesis, log, location}`. A host can serve many minds. Any host that has ever served the mind can keep serving the latest signed copy, and the client keeps the highest valid `seq`.
2. **Resolvers (permissionless, cache + gossip):** an HTTP API modelled on IPFS Delegated Routing:
   - `GET /oip/v1/resolve/{mind_id}` returns the bundle;
   - `PUT /oip/v1/resolve/{mind_id}` publishes a signed bundle.

   Anyone can run one. Resolvers can mirror one another through a firehose-style stream (`GET /oip/v1/stream`, the AT Proto relay / PLC `export/stream` pattern). Because records verify themselves, a resolver can only **withhold** them, never forge them. Clients query two or more resolvers and take the highest valid `seq`. Resolvers also act as **witnesses** of key-log history (PLC replica lesson), which makes forked-history attacks detectable.
3. **Location hints in references:** whenever a packet or descriptor mentions another mind, it MAY include `hints: [url…]` (FEP-ef61 `@gateway` / NIP-65 outbox lesson). Most lookups then need no resolver at all.
4. **Optional DHT (v1.x):** publish a compact Pkarr record or a libp2p Kad-DHT value under `sha256(mind_id)` pointing to resolver or host URLs. This removes the last "known server" bootstrap dependency.
5. **Optional DNS alias:** a `_oip.<domain>` TXT record, or a DNS-AID SVCB record with `bap=oip`, maps a human name to an `oip:` address. It is verified bidirectionally via the `alias` op.

**Bootstrap:** a client ships with a list of public resolvers (like DNS root hints or Nostr default relays), which any user can edit.

### 5.2 (b) Capability descriptors and capability queries

**Descriptor.** A signed, content-addressed document (named by CID), and a **superset of the A2A v1.0 Agent Card**:

```json
{
  "type": "oip.capabilities", "v": 1,
  "mind": "oip:zQm…",
  "a2a": { /* optional embedded or linked A2A AgentCard (name, description, skills, supportedInterfaces…) */ },
  "capabilities": [
    {
      "id": "translate-legal-sw",
      "summary": "Translate Swahili commercial-law documents to/from English",
      "tags": ["oasf:natural_language_processing/translation", "domain:legal/commercial", "lang:sw", "lang:en"],
      "subject": "cap.nlp.translation.legal.sw-en",        // NATS/MQTT/GossipSub-routable form
      "inputs": ["text/plain", "application/pdf"], "outputs": ["text/markdown"],
      "terms": {"price": {"amount": "0.02", "unit": "USD/word"}, "latency_p50_s": 600},
      "evidence": [{"kind": "oip.receipt-set", "ref": "<CID or URL of Layer-2 receipts>", "count": 214}],
      "attestations": [{"issuer": "oip:…", "ref": "<VC or signed claim>"}]
    }
  ],
  "ext": { "<reverse-dns namespace>": { … } },               // Lexicon-style extensions; ignored if unknown
  "issued": "…", "sig": {…}
}
```

- **Structured tags** use OASF taxonomy paths where they exist. Any other namespace is allowed with a prefix.
- **`subject`** is a dotted hierarchy, which lets any pub/sub system with wildcards route by capability (§3.10).
- **Evidence is referenced, not scored.** This follows AINS and the founding principle that "trust is computed".
- **No embeddings in the descriptor.** Embeddings are the indexer's job (§3.13).

**Publishing.** The mind's host serves the descriptor at `/.well-known/oip/mind/<id>/capabilities` (and at `/.well-known/agent-card.json` for A2A compatibility). The location record points to its CID. The mind MAY also `PUT` it to any number of indexers.

**Indexers: the permissionless capability-routing role** (AT Proto relay/AppView pattern).
- **Anyone can run an indexer.** It collects descriptors by crawling, subscribing to resolver streams, accepting PUTs, or mirroring other indexers (MCP sub-registry pattern). It may specialise by domain or region.
- **Query API:**

  ```
  POST /oip/v1/query
  { "want": "translate Swahili commercial law into English",       // free text
    "tags": ["lang:sw","domain:legal/*"],                          // structured filter (wildcards)
    "constraints": {"max_price": …, "deadline": …},
    "evidence": {"min_receipts": 20, "kinds": ["oip.receipt-set"]},
    "limit": 20 }
  → { "results": [ {"mind": "oip:…", "descriptor_cid": "…", "capability_id": "…",
                    "score": 0.91, "why": "…", "hints": ["https://…"]} ],
      "indexer": "oip:<indexer's own address>", "sig": {…} }
  ```

- **Ranking is the indexer's own policy.** It can be embedding similarity, receipt counts or anything else. The response is signed by the indexer's own OIP identity, so indexers build their own reputation. **Clients MUST fetch and verify the descriptor and evidence** before acting. An indexer can bias rankings but cannot forge capabilities.
- **Clients query several indexers** and merge the results. This is the AT Proto "choose your AppView / feed" model applied to capability search.
- **Capability-addressed sending (the "anyone who can…" case):** a client sends a context packet addressed to a **capability query** rather than a mind (`to: {"query": {...}}`). Either the client resolves it locally (query → pick → send), or it hands the packet to an **indexer that also acts as a broker**, which fans it out to the top-k candidates as a call for offers. Candidates reply directly to the sender with Layer 2 offers.
- **Decentralised phase (v2):**
  - a libp2p Kad-DHT mapping `hash(tag)` → descriptor CIDs → host or provider records (the AGNTCY Directory pattern);
  - GossipSub topics named by `subject` for broadcast calls for offers;
  - indexers become just one optimisation among several.

### 5.3 (c) Context-packet envelope

A JSON object, JCS-canonicalised and signed. Header names follow DIDComm v2.1 wherever there is a counterpart.

| Field | Req. | Meaning |
|---|---|---|
| `type` | ✔ | `oip.packet/1` |
| `id` | ✔ | Unique packet ID (ULID/UUIDv7) |
| `from` | ✔ | Sender mind address (+ `from_instance` optional) |
| `to` | ✔ | One or more mind addresses, **or** `{"query": …}` for capability routing, **or** `{"subject": "cap.…"}` for topic routing |
| `kid` | ✔ | Signing key used (resolvable through the sender's key log at `log_head`) |
| `created` / `expires` | ✔ / opt | RFC 3339 timestamps |
| `session` | opt | Session/relationship ID (§5.5) |
| `seq`, `prev` | opt | Sender's per-session sequence number and hash of its previous packet in the session (continuity chain) |
| `thid` / `pthid` | opt | Thread / parent thread (DIDComm-compatible; maps to A2A `contextId`/`taskId`) |
| `reply_to` | opt | Packet `id` being answered |
| `intent` | ✔ | What the sender wants: `{"verb": "request"\|"inform"\|"offer"\|"accept"\|"commit"\|"receipt"\|"query"\|…, "goal": "<short natural-language goal>", "schema": "<URI of Layer-2 primitive or extension>"}` |
| `content` | ✔ | `{"media_type": "...", "body": … }` or `{"cid": …, "url": …}` for large or external payloads; supports multiple parts |
| `context` | opt | What the receiver needs to interpret the content: `refs` (CIDs or URLs of prior packets and documents), `assumptions`, `language`, `audience`, `summary` of session state, `state_doc` (CRDT doc ID and heads) |
| `provenance` | opt | Origin chain: `derived_from` (packet or content CIDs), `generated_by` (model or tool ID, version), `on_behalf_of` (principal address + delegation credential ref), `attestations`; consistent with W3C PROV and C2PA ideas *(background)* |
| `constraints` | opt | Usage terms: `retention` (e.g. `"P30D"` / `"none"`), `allowed_uses` / `prohibited_uses` (e.g. `train`, `redistribute`), `confidentiality` level, `jurisdiction`, `licence` (SPDX/URL), `max_hops`, `forward_ok` |
| `hints` | opt | Location hints for any mind mentioned |
| `ext` | opt | Namespaced extensions; unknown ones are ignored |
| `sig` | ✔ | Signature over JCS of everything else |

**Encryption (optional in v1, required for private sessions in v1.1).** Wrap the signed packet in a sealed envelope:

```
{type: "oip.sealed/1", to: <address>, kid_to: <recipient X25519 key>, enc: "HPKE-Base-X25519-SHA256-ChaCha20Poly1305", ct: …}
```

The packet is signed first, then encrypted, as DIDComm recommends. Mediators and relays see only `oip.sealed` and the next hop. A `forward` wrapper, equivalent to DIDComm's, handles multi-hop routing. Group sessions later move to MLS.

**Constraints are declarations, not enforcement.** They bind the receiver socially and contractually, and Layer 2 can turn them into commitments with receipts. The paper should say this plainly.

### 5.4 (d) Transport bindings

All bindings carry the same packet bytes. A binding only defines how bytes move.

| Binding | v1? | Shape |
|---|---|---|
| **HTTPS inbox** | ✔ required | `POST {endpoint}/inbox` with body = packet (`application/oip+json`); `202` + receipt-of-delivery `{id, accepted_at, sig}` signed by the receiving mind/host. `GET {endpoint}/outbox?since=` optional. |
| **WebSocket** | ✔ | `wss://{endpoint}/ws`; frames = packets; challenge–response auth (server sends nonce, client returns signed nonce with its address), as in Nostr NIP-42; enables push to minds without public endpoints (they hold the socket open). |
| **SSE** | ✔ (cheap) | For streaming partial results (A2A-compatible streaming). |
| **Mailbox / mediator** | ✔ | Any host can offer `POST /mbox/{mind_id}` (store) and authenticated `GET /mbox/{mind_id}` (drain). Used for paused, offline or NATed minds. Packets are sealed, so the mediator cannot read them. |
| **A2A** | ✔ via Bridge | OIP packet ↔ A2A `Message` (parts ↔ content; `thid` ↔ `contextId`); OIP mind publishes an A2A card. |
| **DIDComm** | v1.x | Field-compatible re-encoding; `did:oip` resolves to a DID document exposing a `DIDCommMessaging` service. |
| **libp2p** | v2 | Protocol ID `/oip/packet/1.0.0` over any libp2p transport; DHT + GossipSub for resolution and capability topics; relay and DCUtR for NAT. |
| **iroh** | v2 | ALPN `oip/1`; endpoint key listed in location record. |
| **NATS / MQTT** | v2 (optional) | Publish to `subject` with queue-group / shared subscription for capability anycast. |
| **Email / SMS** | Bridge | Layer 0 maps humans reachable only by email into OIP via a gateway mind that signs on their behalf with explicit delegation. |

### 5.5 (e) Continuity and session model

**Separate three things that today's protocols conflate:**
1. **Identity:** the mind address. It is permanent.
2. **Relationship/session:** a long-lived logical conversation between two or more minds.
3. **Connection:** an HTTP request or socket. It is ephemeral and never carries continuity.

**Session ID** = `hash(JCS({participants (sorted addresses), opener_nonce, created}))`. It is fixed for the life of the relationship and unaffected by host or connection changes. This is the same idea as QUIC connection IDs, one level up.

**Session chain.** Each party's packets carry `seq` and `prev`, the hash of that party's previous packet in the session. Each side therefore holds a verifiable, append-only transcript, like a lightweight per-session Merkle log. On reconnection, after a move, a week's pause or an upgrade:
- the resuming party sends `oip.session.resume {session, my_last_seq, my_last_hash, seen_your_seq, seen_your_hash}`;
- the counterpart verifies both chains, then re-sends anything missing (from its outbox or mailbox).

Both parties can now **verify they are continuing the same relationship with the same counterpart**, which is the founding paper's continuity requirement. The new host's signing key must be authorised by the mind's key log, so a move is verifiable rather than merely asserted.

**Upgrades.** A mind can upgrade (new model, new code) without changing its address. It SHOULD emit `intent.verb = "inform"`, `schema = oip.lifecycle/upgrade`, with old and new version provenance, so counterparts can decide whether commitments still stand. This is a Layer 2 policy hook.

**Forks.**
- A fork gets a **new address** (new genesis with `parent` set, plus a `fork` op in the parent's log).
- The parent's sessions do **not** transfer automatically. A fork may *propose* continuation with `oip.session.branch {parent_session, fork_proof}`, and the counterpart chooses. This avoids two copies sharing one session or ratchet state (§3.14).
- **Multi-instance minds** (one address, many instances) share a session through a **state document** (an Automerge CRDT, ID in `context.state_doc`), so concurrent instances merge cleanly.

**Encryption state.**
- v1 uses per-packet HPKE, which is stateless and so trivially survives moves and pauses, at the cost of no forward secrecy across packets.
- v1.1 adds an optional ratcheted session (Double/Triple Ratchet-style, or MLS for groups). Its state is part of the mind's portable state and must be exported with the mind on a move.

**Offline delivery.** Senders try endpoints by priority. If all fail, they deliver to the mailbox endpoint. When `status = paused`, senders go straight to the mailbox and respect `resume_after`.

### 5.6 What a weekend v1 actually contains

1. A library with keygen, genesis, `mind_id`, key-log ops, location record, descriptor, packet, JCS + Ed25519 sign/verify, and seal/unseal (HPKE). About 600–1000 lines in TypeScript or Python using existing JCS, Ed25519 and HPKE packages.
2. A **host server** with `/.well-known/oip/mind/{id}[/capabilities]`, `/.well-known/agent-card.json`, `POST /inbox`, `/ws` and `/mbox`.
3. A **resolver + indexer server** (one process is fine for v1):
   - resolve, publish and stream for records;
   - publish and query for descriptors;
   - query does tag filtering plus a pluggable embedding ranker, for example SQLite + FTS5, with optional embeddings via sqlite-vec or similar *(tooling choice unverified for this purpose)*.
4. A CLI with `oip init`, `oip publish`, `oip resolve`, `oip find "<capability>"`, `oip send`, `oip move --to <host>` and `oip resume`.
5. An A2A Bridge adapter that wraps any A2A agent as an OIP mind.

**Path to full decentralisation, with no breaking changes because records verify themselves:**
- v1.x: Pkarr/DHT pointers, resolver witness gossip, DIDComm binding.
- v2: libp2p/iroh bindings, Kad-DHT capability index (AGNTCY pattern), GossipSub capability topics, MLS group sessions.
- v3: transparency logs for key-log histories, indexer federation via signed change logs (AINS pattern).

### 5.7 Open questions for the architecture paper

- **Key-log availability.** Without a single directory, a mind could serve different histories to different parties (equivocation). v1 mitigation: resolvers act as witnesses, and the latest `log_head` is embedded in every location record and packet. Is a lightweight transparency log needed in v1? (did:webvh "witnesses" and PLC replicas suggest *optional* in v1, recommended later.)
- **Address string.** Should the canonical form be `oip:` or `did:oip:`? Do both, but register `did:oip` with the W3C DID method registry? A further option is to accept existing `did:plc`, `did:webvh` and `did:key` as valid mind addresses through a generic DID resolver, which maximises the Bridge story at the cost of more verification code paths.
- **Capability taxonomy governance.** OASF covers agent skills, while OIP spans humans and institutions. OIP should allow multiple taxonomies with prefixes and avoid running one.
- **Track-record evidence format.** This belongs to Layer 2 receipts but must be referenceable from descriptors from day one.
- **Spam and Sybil resistance for indexers and mailboxes.** Options: proof-of-work stamps, deposits, rate limits per address, web-of-trust. This is left to indexer and mailbox policy in v1.

---

## 6. Sources

Primary specs, official repositories and official blogs are preferred. Accessed 30 October 2026.

**libp2p, iroh, Pkarr, IPFS**
- libp2p hole punching concepts — https://docs.libp2p.io/concepts/nat/hole-punching/
- js-libp2p release notes (2026-03-03) — https://blog.libp2p.io/releases/2026-03-03-js-libp2p-1-0-14/
- GossipSub v1.0 spec — https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
- GossipSub 1.2 (py-libp2p docs) — https://py-libp2p.readthedocs.io/en/stable/gossipsub-1.2.html
- IDONTWANT adoption on Ethereum mainnet — https://ethresear.ch/t/status-update-idontwant-message-adoption-on-ethereum-mainnet/21819
- iroh 1.0 announcement — https://iroh.computer/blog/v1
- Pkarr repository — https://github.com/pubky/pkarr
- IPFS Delegated Routing V1 HTTP API — https://specs.ipfs.tech/routing/http-routing-v1

**AT Protocol and DIDs**
- AT Protocol Spring 2026 roadmap — https://atproto.com/blog/2026-spring-roadmap
- PLC read replicas — https://atproto.com/blog/plc-replicas
- AT Protocol account migration guide — https://atproto.com/guides/account-migration
- AT Protocol DID spec — https://atproto.com/specs/did
- AT Protocol account spec — https://atproto.com/specs/account
- W3C DID v1.1 Candidate Recommendation (5 March 2026) — https://www.w3.org/TR/2026/CR-did-1.1-20260305
- W3C Controlled Identifiers v1.0 — https://www.w3.org/TR/2025/CR-cid-1.0-20250130/
- DIF: did:webvh v1.0 release — https://blog.identity.foundation/dif-celebrates-v1-0-release-of-did-webvh/
- DIDComm Messaging v2.1 — https://identity.foundation/didcomm-messaging/spec/v2.1/

**ActivityPub, Nostr, Matrix**
- FEP-ef61 Portable Objects — https://fediverse.codeberg.page/fep/fep/ef61/
- Social Web Foundation: new W3C Social Web WG — https://socialwebfoundation.org/2026/01/15/new-social-web-working-group-at-w3c/
- DTI: ActivityPub and account portability (May 2026) — https://dtinit.org/blog/2026/05/26/activitypub-and-account-portability
- Nostr NIPs index — https://github.com/nostr-protocol/nips
- NIP-65 — https://github.com/nostr-protocol/nips/blob/master/65.md
- Matrix v1.19 release — https://matrix.org/blog/2026/07/08/matrix-v1.19-release/
- MSC4014 pseudonymous identities — https://github.com/matrix-org/matrix-spec-proposals/blob/kegan/pseudo-ids/proposals/4014-pseudonymous-identities.md

**Brokers and DNS**
- NATS subjects — https://docs.nats.io/nats-concepts/subjects
- DNS-AID draft -02 — https://www.ietf.org/archive/id/draft-mozleywilliams-dnsop-dnsaid-02.html
- Agent Name Service draft — https://datatracker.ietf.org/doc/draft-narajala-ans/
- AINS discovery draft — https://datatracker.ietf.org/doc/draft-vandemeent-ains-discovery/
- ANP ANS draft — https://datatracker.ietf.org/doc/html/draft-song-anp-ans-00

**Agent protocols, directories and registries**
- A2A specification (source markdown) — https://github.com/a2aproject/A2A/blob/main/docs/specification.md
- A2A specification (site) — https://a2a-protocol.org/latest/specification/
- AAIF: A2A v1.0 builder's guide — https://aaif.io/blog/a2a-v1-0-a-builder-s-guide-part-1-discovery-tasks-and-clients
- AGNTCY Directory v1.0 — https://blogs.agntcy.org/technical/2026/02/19/dir-v1.html
- AGNTCY Directory overview — https://dir.agntcy.org/latest/dir/dir-overview/
- AGNTCY SLIM v1.0 — https://blogs.agntcy.org/technical/2026/02/03/slim-v1.html
- SLIM IETF draft -02 — https://www.ietf.org/archive/id/draft-mpsb-agntcy-slim-02.html
- MCP Registry overview — https://modelcontextprotocol.net/registry/about.md
- NANDA Index and AgentFacts (arXiv 2507.14263) — https://arxiv.org/abs/2507.14263
- ANP technical white paper (arXiv 2508.00007) — https://arxiv.org/html/2508.00007v1
- Federation of Agents (arXiv 2509.20175) — https://arxiv.org/abs/2509.20175
- Evolution of AI agent registry solutions (arXiv 2508.03095) — https://arxiv.org/pdf/2508.03095

**Continuity**
- Multipath QUIC draft status — https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/
- QUIC server migration draft — https://www.ietf.org/ietf-ftp/internet-drafts/draft-kozuka-quic-server-migration-00.html
- Signal SPQR / Triple Ratchet — https://signal.org/blog/spqr/
- Automerge 3.0 — https://automerge.org/blog/automerge-3/

**Background references (standards, not re-fetched today):** RFC 9000 (QUIC), RFC 9420 (MLS), RFC 9180 (HPKE), RFC 8785 (JCS), RFC 8615 (well-known URIs), RFC 6763 (DNS-SD), RFC 9460 (SVCB/HTTPS), W3C ActivityPub and ActivityStreams 2.0 Recommendations, MQTT 5.0 (OASIS).
