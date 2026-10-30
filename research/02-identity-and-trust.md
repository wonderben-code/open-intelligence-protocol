# Research 02: Identity, keys, signing and delegation for the OIP Mind Network

*Research input for the OIP technical architecture paper, Layer 1 (Mind Network).*
*Compiled 30 October 2026. Status claims were checked against primary sources on that date where possible. Where only a secondary source was available, or a source was ambiguous, this is marked **[uncertain]**.*

---

## 0. Summary

**What Layer 1 needs.** It needs (a) permanent, self-certifying mind addresses derived from keys, not tied to any machine or registry, (b) key rotation without losing the address, (c) verifiable lineage when a mind forks or merges, (d) scoped, revocable delegation ("this agent acts for this person or org"), and (e) a signature on every message.

**Bottom line.** Every building block already exists in a standard or near-standard. What nobody provides is the full combination, and fork/merge lineage in particular.

- **Self-certifying, registry-free identifiers with pre-rotation.** KERI (Trust over IP) solves this most completely. did:webvh v1.0 (DIF, 2025) solves it most practically, using JSON, JCS and Ed25519, but it ties the identifier to a web location. did:plc has the right shape (a hash of the genesis operation plus a rotation log), but a single directory still operates it.
- **Data model.** W3C DID v1.1 is a Candidate Recommendation (March 2026), DID Resolution v1.0 is a Candidate Recommendation (October 2026), and Controlled Identifiers v1.0 plus VC 2.0 and Data Integrity became W3C Recommendations in May 2025. Use their vocabulary so OIP addresses resolve in existing tooling.
- **Delegation.** UCAN 1.0 has the right semantics for chained, attenuated, offline-verifiable capabilities between keys/DIDs. Biscuit is the strongest alternative when policy logic matters. OAuth token exchange with the `act` claim, plus the new agent drafts, is how OIP should *bridge* to enterprise systems, not how it should represent native delegation.
- **Agent identity standards (2025–2026).** Lots of activity, nothing final. MCP authorization (2026-07-28 revision) is OAuth 2.1 with Client ID Metadata Documents. IETF WIMSE drafts define workload identity tokens. Web Bot Auth (now an IETF WG) signs HTTP requests from agents with RFC 9421. OpenID Foundation published a whitepaper. DIF has a Trusted AI Agents WG (KYA-OS). There is a new W3C Agent Identity Registry Protocol CG. **None defines fork/merge lineage.** draft-mcguinness-oauth-ai-agent-instance explicitly leaves copies and lineage undefined, which is open ground for OIP.
- **Signing.** Use JCS (RFC 8785) + Ed25519 detached signatures (equivalent to the W3C `eddsa-jcs-2022` cryptosuite) for OIP objects, and RFC 9421 HTTP Message Signatures on the HTTP bridge. ML-DSA for JOSE/COSE is now RFC 9964 (May 2026). W3C PQ Data Integrity suites are only a First Public Working Draft (June 2026). Plan crypto-agility, ship Ed25519.

**Recommendation in one line.** A mind address is `did:oip:<SCID>`, where the SCID is a hash of a JCS-canonicalised inception event that commits to the first keys *and* the next keys (pre-rotation). The address is backed by a portable, append-only key event log modelled on did:webvh's JSON Lines log, with KERI semantics and no domain dependence. Lineage is recorded as fork/merge events in that log. Delegation follows UCAN 1.0 semantics. Messages are JCS+Ed25519 signed. Sections 10–11 give the details and a weekend-sized v1.

---

## 1. W3C DID Core and the controlled-identifier family

**What it is.** DIDs are URIs of the form `did:<method>:<id>` that resolve to a DID document listing verification methods (keys), services and relationships (authentication, assertionMethod, capabilityDelegation, capabilityInvocation). DID Core says nothing about how a method anchors or rotates keys; each method defines that itself.

**Status (Oct 2026).**
- DID v1.0: W3C Recommendation (2022).
- **DID v1.1: Candidate Recommendation Snapshot, 5 March 2026.** It needs two conforming implementations per feature, and it is coupled to DID Resolution meeting its own exit criteria. In September 2026 minutes the WG discussed possibly needing DID Core changes to stay aligned with Resolution work, so it has not yet reached Recommendation **[uncertain on exact next date]**.
- **DID Resolution v1.0: Candidate Recommendation Draft, 26 October 2026.**
- **Controlled Identifiers (CID) v1.0: W3C Recommendation, 15 May 2025.** It generalises the "controller document" (verification methods, Multikey/JsonWebKey, `alsoKnownAs`) beyond DIDs.
- A DID Methods WG charter (to standardise methods in "ephemeral", "web-based" and "fully decentralised" categories) was ready for AC review in September 2026 but had not been adopted. It has faced formal objections. The W3C "DID Methods" registry is a non-normative Group Note (latest 1 Oct 2026).

**Strengths for OIP.** It is a widely deployed vocabulary that existing wallets, VC verifiers and resolvers understand. It has a `capabilityDelegation`/`capabilityInvocation` relationship and `alsoKnownAs`, which suits migrations and links across methods.

**Weaknesses.** DID Core is only a data model. Permanence, rotation and lineage depend entirely on the method. There is no standard notion of fork or merge.

**Recommendation.** Express OIP addresses as DIDs and serve DID-Core/CID-conformant documents, so existing tooling interoperates. Do not depend on any not-yet-standard DID method.

## 2. DID methods

### 2.1 did:key
- **What.** The identifier *is* a multicodec/multibase-encoded public key (e.g. `did:key:z6Mk...` for Ed25519). The document is generated deterministically and needs no registry.
- **Status.** W3C CCG draft, very widely implemented. It is listed in the W3C DID Methods Note. It is a likely candidate for the proposed "ephemeral" category, but it is not a Recommendation.
- **Strengths.** It is trivial to implement, works offline, and is the required principal format in UCAN 1.0.
- **Weaknesses.** **It cannot rotate.** A new key means a new identity. It has no history.
- **For OIP.** Use it for *ephemeral keys, device keys and session keys* and as the key-reference format inside logs. Do not use it as the permanent mind address.

### 2.2 did:web
- **What.** It resolves `did:web:example.com:alice` to `https://example.com/alice/did.json`.
- **Status.** CCG draft, widely used (enterprises, Bluesky handles, Web Bot Auth-style setups).
- **Strengths.** It needs no new infrastructure and is easy for organisations.
- **Weaknesses.** It is not self-certifying. Whoever controls DNS, TLS and the host controls the identity, and there is no history. It is tied to a domain, which conflicts with OIP's "not tied to any machine or registry" requirement.
- **For OIP.** Use it only as a *bridge* (Layer 0): an institution may publish `alsoKnownAs` linking its did:web to its OIP address.

### 2.3 did:peer
- **What.** These are pairwise or private DIDs, mainly for DIDComm. Numalgo 2 encodes keys and services inline. Numalgo 4 (current) uses a long form (hash + encoded input document) and a short form (just the hash), so the short form resolves only once you have seen the long form.
- **Status.** DIF spec, used in Aries/DIDComm stacks.
- **Strengths.** It needs no ledger, offers privacy (a different DID per relationship), and the short form is self-certifying.
- **Weaknesses.** Rotation is relationship-scoped (exchanged out of band). It is not meant to be a public, permanent identity.
- **For OIP.** Use it as a model for *pairwise or private* sub-addresses, which could be a v2 privacy feature. Numalgo 4's long/short trick is worth copying: an OIP address can be short, and the first message carries the inception event.

### 2.4 did:plc (AT Protocol / Bluesky)
- **What.** It is a hash of the signed genesis operation: DAG-CBOR, SHA-256, base32, truncated to 24 characters (`did:plc:` + 24 chars). Its state is a signed operation log. It has 1–5 *priority-ordered* rotation keys (secp256k1 or P-256 only), separate from signing keys. A higher-priority rotation key can override operations within **72 hours**, which gives account recovery. It has a public audit log.
- **Status.** It is a Bluesky spec (v0.x). Many millions of accounts use it. In September 2025 Bluesky announced it would move operation of the PLC directory to an independent Swiss-incorporated organisation **[current status of that transfer unverified]**.
- **Strengths.** It is self-certifying, rotation keeps the identifier, and the recovery window is a real usability win at proven scale.
- **Weaknesses.** One directory orders operations, so it is logically centralised: the directory can censor or withhold, though it cannot forge. It has no pre-rotation, no Ed25519 for rotation, and 24-char truncation (about 120 bits).
- **For OIP.** Borrow **priority-ordered recovery keys with a time-bounded override window**, a pattern that suits humans with lost devices. Do not depend on the PLC directory.

### 2.5 did:webvh (formerly did:tdw, "Trust DID Web with Verifiable History")
- **What.** It is did:web plus a verifiable history. A `did.jsonl` log (JSON Lines) holds entries with `versionId` (number + entry hash, chained), `versionTime`, `parameters`, `state` (the DID doc) and a Data Integrity `proof`. The **SCID** is computed from the first entry: replace self-references with a placeholder, canonicalise with JCS, take a SHA-256 multihash, encode base58btc. `updateKeys` authorise updates. **Pre-rotation** works through `nextKeyHashes`. Optional **witnesses** (did:key, weighted threshold, `did-witness.json`) and watchers can be added. `portable: true`, set only at creation, lets the DID move to a new domain while keeping its SCID and history. v1.0 permits only SHA-256 and the `eddsa-jcs-2022` cryptosuite.
- **Status.** **DIF v1.0 released (announced 7 Aug 2025)** with three interoperable implementations (Python and TypeScript from the Government of British Columbia, Rust from Affinidi). Production use is in Canadian public-sector trust registries.
- **Strengths.** It has almost exactly the cryptographic shape OIP needs: a self-certifying SCID, a hash-chained log, pre-rotation, witnesses, plain JSON + JCS + Ed25519 that weekend implementers can handle, and a real spec with test interop.
- **Weaknesses.** Resolution is still *by web location*. The SCID is permanent, but the full DID string includes a domain, and a non-portable DID dies with its domain. There is no fork/merge notion.
- **For OIP.** **Adopt its log format and SCID algorithm almost verbatim**, while making the address the SCID alone (location-independent). An OIP mind can optionally *also* publish as did:webvh for web resolvability.

### 2.6 KERI, AIDs, did:keri / did:webs
- **What.** Key Event Receipt Infrastructure. An **Autonomic Identifier (AID)** is a self-certifying prefix derived from the inception event. A **Key Event Log (KEL)** is an append-only, hash-chained, signed log (inception `icp`, rotation `rot`, interaction `ixn`, delegated inception/rotation `dip`/`drt`). **Pre-rotation** works by committing digests of the next keys, so compromising the current signing key cannot hijack rotation. KERI supports weighted multi-sig thresholds. **Witnesses** (chosen by the controller) receipt events. **Watchers** (chosen by validators) detect **duplicity**: two validly signed divergent KELs prove compromise or misbehaviour, and the rule is "at most one valid KEL". KERI also supports **delegated identifiers**, where a delegator's KEL must anchor the delegate's events (cooperative delegation). It is encoded in CESR (a compact text/binary dual encoding), with ACDC for credentials. did:webs (ToIP) projects a KERI AID onto web hosting.
- **Status.** Trust over IP KERI Suite WG. **KERI spec v1.1 dated January 2026** (ToIP PDF, Zenodo DOI). It is deployed in GLEIF's vLEI ecosystem (organisational identity for legal entities). An older IETF individual draft (draft-ssmith-keri) expired and KERI is **not** on the IETF standards track.
- **Strengths.** It is the most rigorous design for exactly OIP's requirements: registry-free, location-independent, rotation without losing the identifier, quantum-resistant *rotation* (hash commitments), multi-sig for institutions and collectives, delegated identifiers, and an explicit theory of forks as *duplicity*. It has real regulated-sector deployment.
- **Weaknesses.** It is complex: CESR, KAWA witness agreement, and a large spec surface. It has few implementations outside the WebOfTrust/keripy ecosystem, a steep learning curve, and a small community relative to JOSE/DID tooling. It treats forks as *bad* (duplicity). OIP needs *legitimate* forks, so these must be modelled as new identifiers with declared parents, not as divergent logs of one identifier.
- **For OIP.** **Adopt KERI's semantics** (pre-rotation, witnesses/watchers, duplicity detection, delegated inception, thresholds) but encode them in did:webvh-style JSON/JCS for implementability. Leave the door open to a formal KERI mapping (an OIP inception event could be expressed as a KERI `icp`), so a KERI-native implementation can interoperate later.

## 3. W3C Verifiable Credentials 2.0 and Data Integrity

- **What.** VC Data Model 2.0 is a JSON-LD-based model for signed claims (issuer, subject, validity, status). It is secured either by embedded **Data Integrity** proofs or by an enveloping **JOSE/COSE** proof (SD-JWT, COSE). **Bitstring Status List** handles revocation.
- **Status.** **W3C Recommendations, 15 May 2025.** The family includes VC Data Model v2.0, VC Data Integrity 1.0, Data Integrity EdDSA Cryptosuites v1.0 (`eddsa-rdfc-2022`, `eddsa-jcs-2022`), ECDSA Cryptosuites v1.0, Securing VCs using JOSE and COSE, Controlled Identifiers v1.0 and Bitstring Status List v1.0. **Quantum-Resistant Cryptosuites v1.0** (ML-DSA-44, SLH-DSA, FALCON, SQIsign, each with rdfc and jcs variants) became a **First Public Working Draft on 16 June 2026** and is explicitly "experimental, not for production".
- **Strengths.** It is a W3C standard with enterprise and government uptake (EU digital identity, education, supply chain). It suits *attestations about* minds: "this agent is operated by org X", "this model is version Y", KYA claims. `eddsa-jcs-2022` avoids RDF canonicalisation.
- **Weaknesses.** VCs are claims, not capability chains. Delegation chains as VCs are clunky, and verifiers must walk issuer→subject links by hand. JSON-LD processing is heavy if you use rdfc variants.
- **For OIP.** Use VC 2.0 + `eddsa-jcs-2022` for **attestations and credentials** (operator, model provenance, KYA, membership in collectives), and Bitstring Status List or log-based revocation for revocation. Use a capability format (below) for delegation, with an optional VC wrapping for ecosystems that want it (as KYA-OS does).

## 4. Capability delegation formats

### 4.1 UCAN (User-Controlled Authorization Network)
- **What.** UCANs are chained, offline-verifiable capability tokens between DID principals. A v1.0 token is a DAG-CBOR envelope (signature + payload with a Varsig header and a type tag like `ucan/dlg@1.0.0`). A **Delegation** has `iss`, `aud`, `sub` (the resource owner), `cmd` (a hierarchical command like `/crud/write`), `pol` (a predicate policy language over invocation args with jq-like selectors, `and/or/not`, `all/any`, glob), `nonce`, `exp`/`nbf` and `meta`. An **Invocation** exercises a capability with proofs (the delegation chain by CID). Revocation and Promise are separate sub-specs. Attenuation is enforced because each hop can only narrow. "Powerline" delegation (null subject) delegates all of a principal's authority across devices.
- **Status.** ucan-wg GitHub now presents the spec as **v1.0.0** **[uncertain: some sources still describe 1.0.0-rc.1; no dated release tag was visible]**. Implementations exist in JS (iso-ucan), Rust (rs-ucan), Go (go-ucan; revocation not yet implemented). The ecosystem includes Storacha/web3.storage and Fission. It has been explicitly proposed for AI agent delegation receipts in 2026 community work. `did:key` is the required principal method, with Ed25519, P-256 and secp256k1.
- **Strengths.** It is the closest existing match to "this agent acts for this person, with scoped, revocable authority, re-delegable to sub-agents, verifiable offline without an authorisation server". It is decentralised by design and its semantics map well to OIP.
- **Weaknesses.** It needs DAG-CBOR + Varsig + CIDs, which raises the bar for a weekend implementer and is less familiar than JSON. Revocation needs a revocation store and gossip. It is not an IETF/W3C standard (it is a community spec). Using non-did:key principals (e.g. an OIP DID with rotation) requires a profile.
- **For OIP.** **Adopt UCAN 1.0 delegation semantics** (iss/aud/sub/cmd/pol/exp/nonce, attenuation, revocation by CID). In v1, encode an OIP-native JSON/JCS profile with the same fields, and keep a 1:1 mapping to canonical UCAN envelopes so real UCAN libraries can be used from v1.x.

### 4.2 Biscuit
- **What.** Biscuit is a bearer token (Protobuf) of signed blocks. The authority block grants rights. Holders append blocks with **Datalog** checks to attenuate offline (using an ephemeral-key chain). It supports third-party blocks (attestations signed by other keys), sealing, and revocation IDs (per-block signatures). It uses Ed25519 by default, with P-256 also supported. Spec format 3.x (Datalog v3.0–3.3).
- **Status.** Eclipse Foundation project (eclipse-biscuit). Mature libraries in Rust, with WASM, Java, Go, Python and others.
- **Strengths.** It has a very expressive, deterministic policy language, small tokens, a good security track record and good performance.
- **Weaknesses.** It is key-based with one root key per token, not DID/principal-chain-based. Delegation is "attenuate what I hold" rather than "issuer→audience chains between named minds", so audience binding has to be built with checks. Datalog adds conceptual weight.
- **For OIP.** Do not use it as the core delegation format. It is a good choice *inside* a Layer 2 service that wants rich local policy, and it is a reference for the policy language if UCAN's `pol` proves too weak.

### 4.3 OAuth 2.x and agent extensions (bridge, not core)
- **OAuth 2.1** (draft-ietf-oauth-v2-1-16, Sept 2026) is still a WG document, with IESG submission targeted for Dec 2026.
- **Token Exchange (RFC 8693)** carries delegation via the `act` (actor) claim, which can be nested for chains.
- **draft-oauth-ai-agents-on-behalf-of-user (-02, Aug 2025, individual/informational)** adds `requested_actor` and `actor_token` to the authorization code flow so a user consents to a *specific* agent, with the resulting token carrying `sub` = user and `act.sub` = agent.
- **draft-mcguinness-oauth-ai-agent-instance-00 (July 2026, individual)** adds an attested `agent_instance_id` per running instance, plus `agent_model`, `agent_platform` and `agent_runtime` claims. Sub-agents get nested `act` chains. It states that keys are "binding material, not identity" (rotation keeps the instance ID). It **explicitly does not define copies, forks or lineage**.
- **draft-mcguinness-oauth-actor-profile (Apr 2026)** profiles actor claims.
- **Identity chaining across domains** (draft-ietf-oauth-identity-chaining) is reported approved by the IESG and in the RFC Editor queue (mid-2026) **[per an implementation-status draft; verify on datatracker]**. **Transaction Tokens** (draft-ietf-oauth-transaction-tokens) are reported in WG Last Call. Cross-domain txn-token drafts are emerging.
- **MCP authorization:** OAuth 2.1 + Protected Resource Metadata (RFC 9728) + resource indicators (RFC 8707). The 2026-07-28 revision prefers **Client ID Metadata Documents** (client_id is an HTTPS URL), deprecates Dynamic Client Registration, requires `iss` validation (RFC 9207), and binds credentials to their issuer.
- **For OIP.** These are how OIP minds plug into the existing internet (Layer 0 Bridge). An OIP delegation can be *presented* to an OAuth AS via token exchange, yielding an access token whose `act` chain mirrors the OIP chain. OIP agents can publish an HTTPS Client ID Metadata Document pointing to their OIP address. Do not make OAuth the native delegation format: it assumes an authorisation server per domain, which contradicts registry-free operation.

## 5. Agent identity standards activity, 2025–2026

| Effort | Body | State (Oct 2026) | Relevance to OIP |
|---|---|---|---|
| WIMSE: arch (-07, Mar 2026), workload credentials (-01, May 2026) | IETF WIMSE WG | WG drafts. Defines the **Workload Identity Token** (`wit+jwt`, key-bound via `cnf`, not a bearer token) and the X.509 WIC. Identifiers are URIs with a trust domain (`spiffe://`, `wimse://`) | Bridge for enterprise workloads. Its identifiers are trust-domain-scoped, the opposite of OIP's self-certification |
| draft-ni-wimse-ai-agent-identity | IETF (individual) | Not adopted | Dual identity: agent ID bound to owner |
| draft-klrc-aiagent-auth | IETF (individual, informational) | -00 | Separates the agent client ID from the delegated subject; short-lived audience-bound tokens |
| SPIFFE/SPIRE | CNCF | Graduated project, widely deployed | Workload identity inside a trust domain; bridge only |
| Web Bot Auth: HTTP Message Signatures for automated traffic | **IETF webbotauth WG**, draft-ietf-webbotauth-httpsig-protocol-00 (1 Sep 2026) | WG draft (Cloudflare, Google authors) | Agents sign HTTP requests (RFC 9421, Ed25519, JWK thumbprint `keyid`, `Signature-Agent` header pointing to a key directory). **Directly reusable for OIP's HTTP bridge** |
| DAWN (Discovery of Agents With Names) | IETF, charter under review (Sep 2026) | Pre-WG. Identity is out of scope | Discovery is Layer 1/2 routing, not identity |
| A2A 1.0 | Linux Foundation project **[governance detail unverified]** | Released (2026) | Signed Agent Cards: JWS over JCS-canonicalised card. Caller auth delegated to OAuth/OIDC |
| MCP authorization 2026-07-28 | MCP spec | Shipping | OAuth 2.1, CIMD (see 4.3) |
| OpenID Foundation AIIM Community Group: "Identity Management for Agentic AI" | OIDF | Whitepaper Oct 2025 | Names **recursive delegation** and cross-domain trust as unsolved gaps |
| DIF Trusted AI Agents WG / **KYA-OS** (donated by Vouched, Mar 2026) | DIF | Task force, spec in progress | DIDs + VCs for agent identity and delegation, with three conformance levels. A natural ally; OIP delegation credentials should be KYA-OS-compatible |
| W3C Agent Identity Registry Protocol CG | W3C CG (Apr 2026) | Starting | Plans an agent DID method, VC-based credentials, MCP/A2A/OAuth/SPIFFE profiles and PQ requirements. **Watch it and engage**, since it overlaps with OIP |
| "Know Your Agent" (KYA) | Industry term (a16z, Skyfire, Visa-style payment rails, Vouched) | Market practice, not a single standard | Attestations about who operates an agent. In OIP these are VCs about a mind address |

**Takeaway.** Industry is converging on: an agent has its own key-bound identity, distinct from the human it acts for; delegation is explicit and chained (`act` chains, VCs, UCANs); HTTP requests are signed (RFC 9421). Nobody yet provides **self-certifying, permanent agent identifiers with lineage**, which is the gap OIP Layer 1 should fill while staying mappable to all of the above.

## 6. Prior art on forking, copying and lineage

- **KERI duplicity.** A fork of *one* identifier's log is evidence of compromise. This is a useful constraint: OIP must keep "a mind's own log forked" (illegitimate, detectable) distinct from "a mind spawned a child" (legitimate, declared).
- **KERI delegated identifiers** (`dip`). The child's inception names the delegator, and the delegator anchors approval in its own KEL. This is the cleanest existing primitive for a *parent-approved child*, and it maps directly onto an OIP fork.
- **did:webvh portability and `alsoKnownAs`.** These cover continuity across locations, not across copies.
- **did:plc recovery forks.** A priority key can override recent operations. That is an intra-identifier fork resolution rule.
- **Proof-of-Descendancy (TU Delft bachelor thesis, June 2026).** Self-replicating LLM agents get HD-derived keys plus *parent-signed child certificates*, Merkle-batched Bitcoin anchoring for tamper evidence (explicitly not authorisation), and revocation/capability checks. It is a prototype, but it validates the "parent-signed birth certificate" approach and shows proof size grows linearly with depth.
- **Context Lineage Assurance for Non-Human Identities** (arXiv 2509.18415) concerns lineage of *context and data* through multi-agent systems, which is adjacent (provenance) rather than identity lineage.
- **OAuth agent-instance draft.** Nested `act` chains record spawning *for a single transaction*, not durable lineage. Lineage is explicitly out of scope.
- **Git / content-addressed DAGs** provide general prior art for multi-parent merge commits: a merge is a node with two parent hashes. OIP merge events can follow this exactly.

**Gap.** No standard defines a *merge* of two identities, or forks with persistent independent identity plus verifiable shared ancestry. This is a genuine OIP contribution. It should be specified as a thin layer on KERI-style events, not as new cryptography.

## 7. Signing and serialisation formats

| Format | What / status | For OIP |
|---|---|---|
| **JCS, RFC 8785** | Deterministic JSON canonicalisation (Informational RFC, 2020). Used by did:webvh, `eddsa-jcs-2022` and A2A card signing | **Core canonicalisation for v1.** Watch number and Unicode edge cases; restrict OIP payloads to integers and strings for safety |
| **JWS/JOSE (RFC 7515, 7517, 7519)** | Ubiquitous. RFC 9864 (fully-specified algorithms, Oct 2025) adds `Ed25519` as an `alg` and **deprecates `EdDSA`** | Use for the bridge (JWT/OAuth/WIMSE/A2A). Not ideal as the native envelope: base64 payload wrapping, alg confusion history |
| **COSE (RFC 9052)** | CBOR equivalent, compact, used by IoT, mdoc, SCITT | Candidate for a v2 binary transport; ML-DSA registered via RFC 9964 |
| **Data Integrity 1.0 + `eddsa-jcs-2022`** | W3C Rec (May 2025). An embedded `proof` object over the JCS-canonical document | **The OIP message proof should be wire-compatible with `eddsa-jcs-2022`**, so a W3C DI verifier can check OIP objects |
| **HTTP Message Signatures, RFC 9421** | Proposed Standard (2024). Signs selected HTTP components. Basis of Web Bot Auth | **Use on the HTTP bridge**: OIP over HTTPS signs requests with RFC 9421, with `keyid` resolving to the OIP address's current key |
| **CESR** (KERI) | Compact, self-framing text/binary encoding (ToIP) | Not for v1 (complexity). Allow it as an alternative encoding of the same events later |
| **DAG-CBOR + Varsig** (UCAN, IPLD) | Content-addressed CBOR | Needed only for native UCAN interop |

## 8. Key algorithms

| Algorithm | Status | For OIP |
|---|---|---|
| **Ed25519** (RFC 8032) | Universal, deterministic, fast, 32-byte keys and 64-byte signatures. JOSE `Ed25519` (RFC 9864), multicodec `0xed`, `did:key:z6Mk…` | **Default and mandatory-to-implement in v1** |
| **P-256 / ECDSA** | NIST/FIPS. Required where hardware support matters (WebAuthn/passkeys, Secure Enclave, HSMs, cloud KMS) | **Allowed** (v1 optional). Lets humans root identity in passkeys or device secure elements |
| secp256k1 | Common in blockchain; did:plc, UCAN | Optional, interop only |
| **ML-DSA (FIPS 204)** | NIST final (2024). **RFC 9964: ML-DSA for JOSE and COSE, Proposed Standard, May 2026.** W3C DI PQ suites at FPWD (experimental). Signatures 2.4–4.6 KB, public keys 1.3–2.6 KB | **Crypto-agile slot now; hybrid (Ed25519 + ML-DSA-65) for long-lived institutional addresses in v2.** Pre-rotation hash commitments already protect *rotation* against a future quantum attacker: you rotate to an ML-DSA key the attacker never saw |
| SLH-DSA (FIPS 205) | Hash-based, very conservative, large signatures | Optional for rare, high-value root keys |

---

## 9. Comparison table

Ratings: ✓ = yes / strong, ~ = partial, ✗ = no.

| Option | Self-certifying | Registry/location-free | Rotation keeps ID | Pre-rotation | Fork/merge lineage | Delegation | Standard status (Oct 2026) | Implementation effort |
|---|---|---|---|---|---|---|---|---|
| did:key | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | CCG draft | Trivial |
| did:web | ✗ | ✗ (DNS/host) | ✓ (host-asserted) | ✗ | ✗ | ✗ | CCG draft | Trivial |
| did:peer:4 | ✓ | ✓ | ~ (pairwise) | ✗ | ✗ | ✗ | DIF spec | Low |
| did:plc | ✓ | ~ (single directory) | ✓ | ✗ (priority + 72 h recovery) | ✗ | ✗ | Bluesky spec v0.x, large deployment | Low–medium |
| did:webvh | ✓ (SCID) | ~ (web location; portable) | ✓ | ✓ | ✗ | ✗ | DIF v1.0 (2025), 3 impls | Medium |
| KERI / AID | ✓ | ✓ | ✓ | ✓ | ~ (delegated inception; duplicity) | ~ (delegated AIDs) | ToIP spec v1.1 (2026), vLEI | High |
| VC 2.0 + Data Integrity | n/a | n/a | n/a | n/a | ~ (as attestations) | ~ (as claims) | **W3C Rec** (2025) | Medium |
| UCAN 1.0 | n/a (uses DIDs) | ✓ | n/a | n/a | ✗ | ✓ chained, attenuated, offline | Community spec v1.0 [rc?] | Medium (DAG-CBOR) |
| Biscuit | n/a | ✓ | n/a | n/a | ✗ | ✓ attenuation, Datalog | Eclipse project, spec 3.x | Medium |
| OAuth token exchange + agent drafts | ✗ (AS-issued) | ✗ | n/a | n/a | ✗ (lineage out of scope) | ✓ (`act` chains, AS-mediated) | RFC 8693 + drafts | Low if you already have an AS |
| WIMSE / SPIFFE | ✗ (trust domain) | ✗ | n/a | ✗ | ✗ | ~ | IETF drafts / CNCF | Medium |
| RFC 9421 HTTP sigs | n/a | n/a | n/a | n/a | n/a | n/a | **Proposed Standard** | Low–medium |

---

## 10. RECOMMENDED DESIGN for OIP Layer 1 identity

**Design principle:** compose existing standards. Take KERI's *semantics*, did:webvh's *encoding*, W3C DID/CID/DI *vocabulary*, UCAN's *delegation model*, and RFC 9421 for HTTP. The only genuinely new part is fork/merge lineage events.

### 10.1 Address format
- **Mind address = `did:oip:<SCID>`**, where SCID = base58btc(multihash(SHA-256, JCS(inception_event_with_placeholder))). This is the same algorithm as did:webvh's SCID.
- It has no domain, host or registry component, so the address is permanent and portable by construction.
- Short display form: `oip:<first 16 chars of SCID>` for humans, never for verification.
- The inception event commits to:
  - the current signing key(s) (`keys`), as Multikey
  - `next`: hashes of the next rotation key(s) (pre-rotation)
  - an optional `recovery` key list with priority order and override window, borrowed from did:plc (default 72 h), for humans
  - an optional `threshold` (weighted multi-sig) for institutions and collectives
  - an optional `witnesses` list + threshold
  - `kind` (`human` | `agent` | `collective` | `institution`; informational only)
  - `parents` (empty for a root mind; see lineage)
  - a creation time
- Resolution is **location-independent**: anyone holding the log can verify it from inception. Logs travel with first contact (did:peer:4-style long form: address + log), are cached by peers, and can be published anywhere (HTTPS, IPFS, OIP relays). An optional `did:webvh` and/or `did:webs` mirror plus `alsoKnownAs` gives existing web resolvers a path in.

### 10.2 Key type
- **Ed25519** is mandatory-to-implement for signing and rotation.
- **P-256** is optional, so passkeys, Secure Enclave and HSM-rooted human/institution keys work.
- Keys use **Multikey** encoding (CID v1.0), so they are `did:key`-compatible.
- **Crypto-agility.** Every key and signature carries a multicodec algorithm tag. ML-DSA-44/65 is reserved (RFC 9964 / W3C PQ DI draft codes). Long-lived institutional minds should use a hybrid Ed25519 + ML-DSA signature once libraries settle (v2).

### 10.3 Rotation mechanism (key event log)
- **Log** = JSON Lines, one event per line, did:webvh-style. Each event has `{v, id: "<seq>-<hash>", prev, time, type, data, proof}`, where `prev` is the hash of the previous event (hash-chained) and `proof` is an `eddsa-jcs-2022`-compatible Data Integrity proof.
- **Event types:** `inception`, `rotate`, `update` (services, endpoints, metadata), `fork` / `spawn`, `merge`, `delegate-anchor` (optional), `revoke`, `retire` (empty `next` = permanently closed, as in KERI abandonment).
- **Rotation:** a `rotate` event must be signed by keys whose hashes were committed in the previous `next`, and it commits a new `next`. Compromising the *current* signing key therefore cannot take over the address.
- **Recovery:** if a `recovery` list exists, a higher-priority recovery key can supersede events within the override window (the did:plc rule). After the window, events are final.
- **Witnesses (optional in v1, recommended for institutions):** witnesses sign receipts. Peers/watchers keep first-seen copies. Two validly signed divergent events at the same `seq` (outside a recovery override) are **duplicity**, which is published as evidence and makes the address untrusted until resolved (KERI rule).

### 10.4 Lineage records for fork and merge
- **Fork (spawn / copy):** a child mind is a *new address* with its own keys and its own inception. Its inception has `parents: [{addr, event}]`, where `event` is the parent log event hash at the moment of forking. The **parent** appends a matching `fork` event naming the child SCID (KERI delegated-inception pattern). Lineage is verified when both sides agree: the child claims the parent, and the parent's signed log acknowledges the child.
  - Unacknowledged claims are allowed but flagged `claimed-lineage`. This covers copies made without the parent's consent, which is a real case for leaked or open-weight agents.
  - Optional `fork.terms` record what was inherited (memory snapshot hash, model ID/version hash, delegated capabilities carried over, or none by default).
- **Merge:** a new mind with `parents: [A@eA, B@eB, …]` (Git-style multi-parent). Each parent appends a `merge` event naming the merged child and either `retire`s (the parent ends) or continues. Policy can require a threshold of parent signatures.
- **Continuity vs copy.** Rotation and migration keep *the same address* (continuity). A fork always creates *a new address* (a copy). This removes the "which copy is the real one" ambiguity at the protocol level: the original is whoever still controls the original log, and divergence of one log is duplicity, not forking.
- **Lineage queries:** ancestry is a DAG of `(address, event-hash)` nodes and can be verified offline by fetching logs. Proof size grows linearly with depth, so later versions can add Merkle checkpoints.
- **Attestations about lineage** (e.g. "same weights as parent", "trained from X") are VCs issued by whoever can vouch for them, not protocol facts.

### 10.5 Delegation format
- **Semantics: UCAN 1.0 delegation.** `iss` (delegator address), `aud` (delegate address), `sub` (the mind whose authority is delegated), `cmd` (hierarchical command such as `/oip/commit/offer` or `/mail/send`), `pol` (UCAN policy predicates over args), `nbf`/`exp`, `nonce`, `meta`, and `prf` (hashes of parent delegations for re-delegation chains). Each hop may only attenuate.
- Principals are OIP addresses, and verification checks the signer key was valid in the issuer's log *at signing time*. That is OIP's profile over UCAN's did:key default.
- **Revocation:** a `revoke` event in the issuer's log naming the delegation hash, plus short default expiry (e.g. 24 h for autonomous agents). Verifiers check the latest log head they can obtain. Optional Bitstring Status List for high-volume issuers.
- **Encoding:** v1 uses an OIP JSON profile (JCS + Ed25519 proof) with field names identical to UCAN. v1.x adds native UCAN 1.0 envelopes (DAG-CBOR/Varsig) for interop with UCAN libraries.
- **Bridges:**
  - Wrap as a VC 2.0 "DelegationCredential" for KYA-OS / W3C agent-identity ecosystems.
  - Exchange at an OAuth AS (RFC 8693) for an access token whose `sub`/`act` chain mirrors the OIP chain, compatible with the on-behalf-of and agent-instance drafts.
  - MCP clients advertise an HTTPS Client ID Metadata Document that links to their OIP address.

### 10.6 Message-signature format
- **Every OIP message** is a JSON object with `from` (address), `to`, `id`, `time`, `type` and `body`, plus a `proof` = Data Integrity proof (`cryptosuite: eddsa-jcs-2022`, `verificationMethod: did:oip:<SCID>#<key-id>`, `created`, optional `logHead` = hash of the sender's latest log event, and `proofValue`).
  - Including `logHead` lets the receiver detect stale or rotated keys and ask for missing log events.
  - Acting under delegation adds `cap`: the delegation chain hashes (or the inline chain).
- **Over HTTP:** also sign the request with **RFC 9421** (Web Bot Auth profile: cover `@method`, `@target-uri`, `content-digest`, with `created`/`expires`). `keyid` = the OIP verification-method URL. A `Signature-Agent`-style header points to where the sender's log can be fetched.
- **Replay protection:** `id` (nonce) + `time` window + receiver-side dedup.

---

## 11. Minimal v1 (weekend-implementable)

Everything below needs only an Ed25519 library, SHA-256, a JCS implementation (available in most languages) and base58btc.

1. **Keys:** Ed25519 only. Generate a signing key `k0` and a next key `k1`. Store `k1` offline.
2. **Inception:** a JSON object `{v:"oip/1", type:"inception", keys:[multikey(k0)], next:[sha256(multikey(k1))], parents:[], time}`. SCID = base58btc(multihash(sha256(JCS(event with id="{SCID}")))). The address is `did:oip:<SCID>`. Sign it with `k0` (`eddsa-jcs-2022`-style proof).
3. **Log:** `log.jsonl`, append-only, each event with `prev` hash. **Only three event types for v1:** `inception`, `rotate` (signed by the pre-committed key, commits a new `next`) and `fork` (parent acknowledges child). Verification is a ~100-line loop.
4. **Fork:** the child inception includes `parents:[{addr, event}]`, and the parent appends `{type:"fork", child:"did:oip:…"}`. Merge waits for v1.1 (same mechanism with multiple parents).
5. **Delegation:** a JSON object `{iss, aud, sub, cmd, pol:[], exp, nonce, prf:[]}` with an Ed25519 proof from `iss`'s current key. Verify the chain by walking `prf`, checking each `aud` = next `iss`, `cmd` narrowing (prefix match), and `exp`. Revocation = short expiry only in v1.
6. **Messages:** a JSON envelope + `proof` (JCS + Ed25519, with `logHead`). The receiver fetches or caches the sender's log, checks the key is current, and verifies.
7. **Transport:** HTTPS POST with an RFC 9421 signature, or simply the signed JSON body for v1, carrying the sender's log on first contact.

Deferred to v1.x/v2: witnesses/watchers and duplicity gossip, recovery keys with an override window, P-256/passkeys, merge events, native UCAN envelopes, VC and OAuth bridges, did:webvh/did:webs mirrors, ML-DSA hybrid signatures, pairwise private addresses (did:peer-style), and CESR/KERI-native encoding.

## 12. Open questions for the architecture paper

1. **Own DID method or profile of an existing one?** `did:oip` is effectively "did:webvh minus the web" or "KERI in JSON". A conversation with the DIF did:webvh and ToIP KERI groups is worthwhile: either may accept a location-independent mode, which would avoid a new method.
2. **Log availability.** With no registry, how does a verifier get the *latest* log head? Options: the sender always attaches it, witnesses, relays, or a gossip network. KERI watchers are the model. This must be resolved for revocation to mean anything.
3. **Fork consent policy.** Should unacknowledged (`claimed-lineage`) forks be first-class? This is an ethical and governance choice as much as a technical one.
4. **Alignment with the W3C Agent Identity Registry Protocol CG and DIF KYA-OS.** Engage early so OIP delegation credentials are compatible rather than competing.
5. **UCAN status.** Confirm whether 1.0 is final or still rc.1 before normatively referencing it.

---

## Sources

**W3C**
- DIDs v1.1 CR Snapshot (5 Mar 2026): https://www.w3.org/TR/2026/CR-did-1.1-20260305/
- W3C news, implementations invited for DID v1.1: https://w3.org/news/2026/w3c-invites-implementations-of-decentralized-identifiers-dids-v1-1/
- DID Resolution v1.0 (CR Draft, 26 Oct 2026): https://www.w3.org/TR/did-resolution-1.0/
- DID Methods registry (Group Note, Oct 2026): https://www.w3.org/TR/did-extensions-methods
- DID WG minutes 10 Sep 2026 (charters): https://www.w3.org/2026/09/10-did-minutes.html
- DID Methods WG chartering minutes 10 Nov 2025: https://www.w3.org/2025/11/10-did-methods-minutes.html
- VC 2.0 family becomes Recommendation (15 May 2025): https://www.w3.org/press-releases/2025/verifiable-credentials-2-0 and https://www.w3.org/ja/news/2025/the-verifiable-credentials-2-0-family-of-specifications-is-now-a-w3c-recommendation/
- Controlled Identifiers v1.0 (Rec): https://www.w3.org/TR/2025/REC-cid-1.0-20250515/
- Quantum-Resistant Cryptosuites v1.0 FPWD (16 Jun 2026): https://www.w3.org/TR/vc-di-quantum-resistant-1.0/
- Agent Identity Registry Protocol CG call for participation (Apr 2026): https://www.w3.org/community/agent-identity/2026/04/24/call-for-participation-in-agent-identity-registry-protocol-community-group/
- did:key (CCG): https://w3c-ccg.github.io/did-method-key/

**DIF / ToIP / other identity specs**
- did:webvh v1.0 spec: https://identity.foundation/didwebvh/v1.0/
- DIF announcement of did:webvh v1.0 (Aug 2025): https://blog.identity.foundation/dif-celebrates-v1-0-release-of-did-webvh/
- did:peer:4 description: https://hackmd.io/@dbluhm/did-peer-4
- KERI v1.1 specification (ToIP, Jan 2026): https://trustoverip.org/wp-content/uploads/KERI-V1.1-2026-01-21.pdf
- KERI Suite WG (ToIP): https://lf-toip.atlassian.net/wiki/spaces/HOME/pages/56819755/KERI+Suite+Working+Group
- KERI IETF individual draft (expired): https://datatracker.ietf.org/doc/html/draft-ssmith-keri
- GLEIF vLEI KERI infrastructure requirements (Mar 2026): https://www.gleif.org/media/pages/organizational-identity/become-a-vlei-issuer-qvi/vlei-ecosystem-governance-framework/8262a823f3-1774607082/2026-03-25_vlei-egf-v4.0-technical-requirements-part-1-keri-infrastructure_v1.4_final.pdf
- did:plc spec: https://web.plc.directory/spec/v0.1/did-plc
- Bluesky on an independent PLC organisation (Sep 2025, repost): https://hackers.pub/@boltless/019961db-e167-71d2-9d4d-2dffb7689acc
- DIF KYA-OS / Trusted AI Agents WG (Apr 2026): https://blog.identity.foundation/kya-os/

**Delegation**
- UCAN spec: https://github.com/ucan-wg/spec (rc.1 text: https://raw.githubusercontent.com/ucan-wg/spec/v1.0-rc.1/README.md)
- UCAN invocation spec: https://github.com/ucan-wg/invocation
- UCAN implementations overview (2026): https://cdn.jsdelivr.net/npm/@wovin/core@0.3.3/src/pubsub/UCAN%20Specs%20Overview.md
- Biscuit specification: https://doc.biscuitsec.org/reference/specifications and https://www.biscuitsec.org/

**IETF / OAuth / agents**
- OAuth 2.1 draft (-16, Sep 2026): https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/
- OAuth On-Behalf-Of for AI agents (-02): https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-02.html
- OAuth AI agent instance (-00, Jul 2026): https://datatracker.ietf.org/doc/draft-mcguinness-oauth-ai-agent-instance/00/
- OAuth Actor Profile (Apr 2026): https://ftp.kaist.ac.kr/ietf/draft-mcguinness-oauth-actor-profile-00.html
- Identity chaining / Txn-Token implementation status (Jun 2026): https://www.ietf.org/ietf-ftp/internet-drafts/draft-agnihotri-oauth-agent-impl-status-02.html
- Cross-domain Transaction Tokens (Jul 2026): https://ftp.sparcs.org/ietf/draft-liu-oauth-cross-domain-txn-token-00.html
- WIMSE architecture (-07): https://datatracker.ietf.org/doc/html/draft-ietf-wimse-arch-07
- WIMSE workload credentials (-01): https://ftp.otenet.gr/doc/internet-drafts/draft-ietf-wimse-workload-creds-01.html
- WIMSE WG documents: https://datatracker.ietf.org/wg/wimse/documents/
- HTTP Message Signatures for automated traffic (webbotauth WG, Sep 2026): https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol-00
- CSA research note on IETF agent identity work (Sep 2026; secondary): https://labs.cloudsecurityalliance.org/research/csa-research-note-ietf-agent-identity-standards-20260902-csa/
- RFC 9964, ML-DSA for JOSE and COSE (May 2026): https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium-11
- RFC 9864, Fully-Specified Algorithms for JOSE and COSE: https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13
- RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
- RFC 8785 JCS: https://www.rfc-editor.org/rfc/rfc8785
- RFC 8693 OAuth Token Exchange: https://www.rfc-editor.org/rfc/rfc8693

**Industry / agent ecosystems (secondary)**
- MCP authorization 2026-07-28 changes (secondary): https://ssojet.com/blog/mcp-authorization-spec-2026-07-28-what-changed
- MCP client registration spec page: https://modelcontextprotocol.net/specification/2026-07-28/basic/authorization/client-registration.md
- A2A 1.0 signed Agent Cards (secondary): https://api7.ai/blog/a2a-protocol-gateway-layer
- OpenID Foundation "Identity Management for Agentic AI" (Oct 2025): https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/
- OIDF AIIM Community Group: https://openid.net/cg/artificial-intelligence-identity-management-community-group/

**Lineage prior art**
- Proof-of-Descendancy: Identity for Self-Replicating LLM Agents (TU Delft BSc thesis, 2026): https://repository.tudelft.nl/record/uuid:070bf34d-8c94-4d62-b7c7-f3c029354c2d
- Context Lineage Assurance for Non-Human Identities (arXiv 2509.18415): https://arxiv.org/abs/2509.18415
