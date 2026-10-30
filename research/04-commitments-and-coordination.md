# Research 04 — Commitments and Coordination: Prior Art and a v1 Design for Layer 2 (Mind Web)

*Open Intelligence Protocol (OIP) — technical architecture research track*
*Prepared 30 October 2026. Status: research input, not normative.*

---

## Summary

Layer 2 of OIP (the Mind Web) defines six linked, signed primitives: **Participant, Intent, Offer, Commitment, Receipt, Collective**. Almost every one of them has been attempted before, often more than once. The prior art gives a clear pattern:

1. **Agent communication languages (KQML, FIPA ACL, Contract Net)** got the *shape* of the interaction right (call-for-proposals, propose, accept, inform-done, failure) but tied meaning to the private mental states of agents. Those states cannot be checked from outside, so the messages could not be audited, and the standards stayed inside academic platforms. Munindar Singh's proposal to define meaning through **public social commitments** (debtor, creditor, context) is the lesson OIP should adopt: an OIP commitment means what it publicly binds the parties to, nothing more.
2. **Web vocabularies (ActivityStreams 2.0, schema.org)** already have Offer / Accept / Reject / Question activities and Offer / Demand / Action objects. They spread because they are *plain JSON, optional semantics, extensible*. OIP should stay mapping-compatible with them rather than re-invent vocabulary.
3. **Signed-agreement prior art (Ricardian contracts)** shows that a human-readable, machine-parsable document, identified by its hash and signed by its issuer, is enough to make an enforceable promise — no smart contract needed.
4. **Blockchain "intents" (solvers, ERC-7683)** demonstrate the economic power of publishing *what you want* and letting competing solvers propose *how*. The current ERC-7683 draft has itself moved away from mandating a common settlement contract toward a generic order description plus resolver — a sign that the intent format should be neutral and settlement should be pluggable.
5. **Receipts and tamper-evidence** are a solved problem in pieces: W3C Verifiable Credentials 2.0 (a W3C Recommendation since May 2025) for attestations; RFC 9162 Merkle-tree logs, Sigstore Rekor v2 (tile-based, GA October 2025) and IETF Key Transparency (drafts ongoing in 2026) for append-only histories; content addressing (CIDs, AT Protocol signed repos) for links.
6. **Reputation** prior art (EigenTrust, Ethereum Attestation Service) shows reputation works best as *computation over a public graph of signed attestations*, run by anyone — not as a score stored in the protocol.
7. **Agent payments** consolidated rapidly in 2025–2026: x402 (HTTP 402, now under a Linux Foundation x402 Foundation since April 2026), Google's AP2 (signed mandates), OpenAI/Stripe's Agentic Commerce Protocol (versioned spec, latest 2026-01-30 with an extensions framework), Visa Trusted Agent Protocol and Mastercard Agent Pay, and Lightning L402. **None of these defines intents, commitments or receipts in a payment-neutral way** — they each define one. OIP should not compete; it should *carry* them through namespaced extensions and the Bridge.
8. **Collectives** prior art (Safe multisig, FROST threshold signatures RFC 9591, Loomio, Holacracy, Moise+) points to a simple v1: a Collective is a signed object listing members and a decision policy; it acts when *k of n* members sign. Threshold-crypto single keys are an optional upgrade.

**Recommendation (detailed in §9):** a single JSON envelope for all six primitives — `oip`, `type`, `author`, `created`, `seq`, `prev`, body fields, `links`, `ext`, `sigs` — canonicalised with JCS (RFC 8785), hashed with SHA-256 to give a content identifier, signed with Ed25519 by one or more parties, published in each author's own append-only hash-chained feed, with optional transparency-log anchoring. Objects are immutable; state changes are new linked objects. Payments, reputation, markets and governance plug in through namespaced `ext` fields. Everything here can be implemented with an Ed25519 library, a JSON canonicaliser and SHA-256 — a weekend of work.

---

## 1. Speech acts and agent communication languages

### 1.1 KQML and FIPA ACL

- **KQML** (Knowledge Query and Manipulation Language) emerged in the early 1990s from the DARPA Knowledge Sharing Effort. It defined *performatives* (ask, tell, achieve, advertise, broker, etc.) as an outer layer around content expressed in any content language. *(Background knowledge; dates approximate.)*
- **FIPA ACL** (Foundation for Intelligent Physical Agents, late 1990s–2002) standardised a similar set of communicative acts (inform, request, propose, accept-proposal, reject-proposal, cfp, refuse, failure, etc.), plus a library of interaction protocols. FIPA later became an IEEE Computer Society standards committee; the specifications are largely dormant. JADE was the best-known implementation. *(Background knowledge.)*
- **Why they did not spread (lessons):**
  - **Unverifiable semantics.** Singh's critique ("A Social Semantics for Agent Communication Languages", c. 1999–2000) argues that KQML's and FIPA's semantics were *mentalistic*: a message's meaning was defined by the sender's beliefs and intentions. In open systems with heterogeneous agents those states are private and cannot be inspected, so compliance cannot be verified. Communication is public; mental states are not. He proposed defining meaning through **social commitments** between a debtor and a creditor within a context group, which can be checked from observable behaviour.
  - **Heavy content-language and ontology requirements** (SL, KIF, shared ontologies) raised the cost of a first implementation far above "send some JSON over HTTP". *(Common assessment in the literature; not independently verified here.)*
  - **Platform-bound.** Agents generally lived inside one platform (e.g., JADE containers) rather than on the open web, with no global identity, no signatures and no linkable records.
  - **Timing.** The web's REST/JSON style won developer mindshare; ACLs never had a "view source" moment.
- **What to keep:** the performative set is a well-tested map of the negotiation space; OIP's primitives cover it (cfp ≈ Intent, propose ≈ Offer, accept-proposal ≈ Commitment acceptance, inform-done / failure ≈ Receipt).

### 1.2 Contract Net Protocol

- Reid G. Smith, "The Contract Net Protocol: High-Level Communication and Control in a Distributed Problem Solver", IEEE Transactions on Computers, December 1980. A manager announces a task; contractors bid; the manager awards; the contractor reports results. FIPA later standardised it as an interaction protocol (cfp → propose/refuse → accept-proposal/reject-proposal → inform-done/inform-result/failure, with a bid deadline). *(The FIPA spec page could not be retrieved during this research; message list from background knowledge.)*
- **Lesson:** the Intent → Offer → Commitment → Receipt flow is a forty-five-year-old, well-understood pattern. OIP's contribution is not the flow but making every step a *signed, linkable, public-by-choice object* across organisations.

---

## 2. Web vocabularies: ActivityStreams 2.0 and schema.org

### 2.1 ActivityStreams 2.0 (W3C Recommendation, used by ActivityPub)

- Activity types relevant to OIP: **Offer** (actor offers object, optionally to a target), **Invite** (specialised Offer), **Accept / TentativeAccept**, **Reject / TentativeReject**, **Question** (an intransitive activity with `oneOf`/`anyOf` options and a `closed` time — usable for collective votes).
- Properties: `actor`, `object`, `target`, `result`, `origin`, `instrument`, `inReplyTo`, `context` (groups related activities, e.g. one negotiation), plus `Collection`/`OrderedCollection` for feeds.
- **Lesson:** AS2 is JSON(-LD) that works without RDF tooling, is extensible via `@context`, and reached real deployment through the fediverse. Its weakness for OIP is that objects are identified by mutable HTTPS URLs on a server, and AS2 itself has no signature or content-addressing model. OIP should **map** cleanly to AS2 (an OIP Offer can be rendered as an AS2 `Offer`; acceptance as `Accept` with `inReplyTo`) so ActivityPub software can display OIP traffic via the Bridge.

### 2.2 schema.org

- **Offer** and **Demand** share the same property set (`itemOffered`, `priceSpecification`, `businessFunction`, `eligibleRegion`, `availabilityEnds`, etc.). schema.org describes a Demand as a non-binding, non-exclusive announcement of a wish to acquire something — essentially an OIP **Intent**.
- **Action** (with `actionStatus` values such as potential/active/completed/failed — *from background knowledge, not verified on the fetched page*) models things done by an agent, with `agent`, `object`, `result`, `instrument`.
- **Lesson:** OIP should let the *subject matter* of an intent or offer be described with schema.org (or any vocabulary) inside a `subject` field, rather than define its own product/service ontology.

---

## 3. Signed agreements without smart contracts: Ricardian contracts

- Ian Grigg's Ricardian contract (in use since 1996): a single document that is **signed by the issuer**, **readable by people**, **parsable by programs**, and **identified by its cryptographic hash**; that hash is then cited in every related transaction record.
- **Lesson for OIP Commitments:** this is exactly the needed model. A Commitment should carry a human-readable `terms` text *and* structured fields, be identified by the hash of its canonical form, and be signed by each party. Enforcement lives outside the protocol (law, reputation, escrow extensions, collectives), which keeps the core simple and species-neutral.

---

## 4. Intents in blockchain and DeFi

- **Idea:** instead of signing a precise transaction, a user signs a declaration of the *outcome* they want with constraints (e.g. "receive at least X of token B for Y of token A on chain C before time T"). Competing **solvers/fillers** find the best execution and are paid for it. Anoma pushed this as a general "intent-centric architecture"; ERC-4337 account abstraction and many cross-chain bridges adopted intent-style flows. *(General landscape; secondary sources only.)*
- **ERC-7683 (Cross Chain Intents)** — Draft ERC, created April 2024 (authors include people from Uniswap Labs and Across, per background knowledge). The *earlier* draft defined `GaslessCrossChainOrder`, `OnchainCrossChainOrder`, `ResolvedCrossChainOrder` and origin/destination settler contracts. The *current* draft (as fetched) has been reworked: an order is a set of steps, variables and payments with attributes; a **resolver** contract decodes a protocol-specific payload into a resolved order; solvers whitelist resolvers they trust; and the ERC explicitly does **not** require a common escrow, settlement contract or fill function.
- **Lessons:**
  1. Separating *what is wanted* from *how it is fulfilled* creates a competitive market of fulfillers — this is OIP Intent → Offer.
  2. Even within one ecosystem, mandating a single settlement mechanism proved too rigid; the standard retreated to describing orders and letting resolvers vary. OIP should likewise standardise the Intent/Offer/Commitment *envelope* and leave settlement to extensions.
  3. Intents need **constraints, deadlines and an explicit set of acceptable fulfillers** (or open-to-all), which OIP's Intent schema should support.

---

## 5. Receipts, attestations and tamper-evident histories

### 5.1 Verifiable Credentials 2.0

- W3C VC Data Model v2.0 became a **W3C Recommendation on 15 May 2025**. A credential must be secured by at least one mechanism: embedded **Data Integrity** proofs (e.g., `ecdsa-rdfc-2019`, `ecdsa-sd-2023`, `bbs-2023`) or enveloping **JOSE/COSE** (`application/vc+jwt`, `application/vc+cose`, SD-JWT). It has `validFrom`/`validUntil` and a status mechanism (Bitstring Status List is a companion spec; *not verified on the fetched page*).
- **Lesson:** an OIP Receipt is semantically a credential — an issuer attests a claim about a subject (a commitment was fulfilled). v1 should not *require* VC tooling (JSON-LD canonicalisation is heavy), but a Receipt should be **losslessly wrappable as a VC** (issuer = author, credentialSubject = the commitment and outcome), via an optional `ext` profile. AP2 already uses this idea (see §7.2).

### 5.2 Transparency logs

- **Certificate Transparency v2 — RFC 9162** (Experimental, December 2021, obsoletes RFC 6962): append-only Merkle tree; leaf hash = H(0x00 ‖ entry), node hash = H(0x01 ‖ left ‖ right) for domain separation; **inclusion proofs** show an entry is in the tree; **consistency proofs** (about log2(n)+1 nodes) show a newer tree extends an older one; the **Signed Tree Head** commits to size, root and time.
- **Sigstore Rekor**: Rekor v2 alpha (April 2025) moved from Trillian to **Trillian-Tessera** with a **tile-based** log; **Rekor v2 reached GA on 10 October 2025** with client support in Cosign and the Go/Python/Java libraries. A June 2026 Sigstore post notes that the public sigstore.dev instance still defaults to Rekor v1 for now, because v2 changes client behaviour. Witnessing was planned to be built in.
- **Trillian / Tessera** are Google's open-source Merkle-log libraries; tile-based logs (C2SP `tlog-tiles` style — *specification name from background knowledge*) serve static files and are cheap to run.
- **IETF Key Transparency** (keytrans WG): `draft-ietf-keytrans-architecture` reached revision -09 in June 2026; still an Internet-Draft.
- **Lesson:** OIP does not need a global log in v1. Each author's **hash-chained feed** already gives tamper-evidence for that author's history (any fork is provable by two signed objects with the same `seq`). A transparency log is the optional second layer: authors (or witnesses) periodically submit a signed *checkpoint* of their feed to one or more public Merkle logs, which prevents an author from showing different histories to different parties ("equivocation").

### 5.3 Content addressing and signed repositories

- **CIDs (multiformats)**: CIDv1 = version + content-type multicodec + multihash; string form adds a multibase prefix. IPLD codecs (raw, dag-cbor, dag-json) let objects link by hash. *(Specific codec numbers from background knowledge — verify against the multicodec table.)*
- **AT Protocol repositories** (Bluesky): each account's records live in a Merkle Search Tree keyed by `collection/record-key`; every published state is a **signed commit** (`did`, `version`, `data` → MST root CID, `rev` logical clock, `sig`) over DAG-CBOR; signing keys are found in the DID document and can rotate.
- **Nostr (NIP-01)**: events whose `id` is the SHA-256 of a canonical JSON array of their fields, signed with Schnorr/secp256k1; tags link to other events (`e`) and keys (`p`). *(The NIP-01 page could not be fetched in this session; summary from background knowledge.)* Nostr is a strong proof that "hash of canonical JSON + signature + tags" is enough for a large open network.
- **Lesson:** OIP should use **hash links** (content IDs) for every reference between primitives, so that links can never silently change, and keep the ID format **multihash-compatible** so OIP objects can live on IPFS/IPLD storage later without changing IDs' meaning.

---

## 6. Reputation prior art

- **EigenTrust** (Kamvar, Schlosser, Garcia-Molina, WWW 2003; received the WWW Test-of-Time award in 2019): each peer rates the peers it transacted with; ratings are normalised and global trust is computed as the principal eigenvector of the trust matrix (like PageRank), seeded by pre-trusted peers to resist collusion. Later systems (e.g., OpenRank in Web3) apply EigenTrust-style computation to attestation graphs. *(OpenRank details from secondary sources.)*
- **Ethereum Attestation Service (EAS)**: a free, open protocol for on-chain (and off-chain, EIP-712-signed) attestations on EVM chains. Attestations reference a registered **schema**, have an attester, recipient, time, expiration, revocation status, and a **`refUID` linking to another attestation** — forming a graph. *(Field list from background knowledge; the docs pages fetched did not include it.)*
- **Lessons:**
  1. Reputation should be **derived**, not stored: the protocol supplies the raw graph (Commitments and their Receipts, signed by counterparties) and anyone computes their own scores. This matches OIP's "markets, reputation, governance built on top".
  2. **Counterparty-signed receipts** are the key anti-fraud input: a receipt signed only by the party claiming success is weak; one co-signed by the creditor is strong. The Receipt schema should record *who* attests.
  3. Sybil resistance comes from the graph (pre-trusted seeds, cost of commitments, payments), not from the protocol core.

---

## 7. Agent payments (state as of October 2026)

### 7.1 x402 (HTTP 402 payments)

- Launched by Coinbase in May 2025; **V2 announced December 2025** (multi-chain by default, standardised network/asset identification, support for usage-based, subscription, prepaid and multi-step patterns, lifecycle hooks, compatibility with legacy rails; the developers reported over 100 million payments in six months).
- **Governance:** on **2 April 2026** the x402 Foundation launched under the **Linux Foundation**, with Coinbase contributing the protocol; around forty founding organisations, premier members including AWS, American Express, Cloudflare, Coinbase, Google, Mastercard, Shopify, Solana Foundation, Stripe and Visa.
- **V2 HTTP flow** (per docs.x402.org): server replies **402** with a `PAYMENT-REQUIRED` header (Base64 JSON: accepted schemes, price, network, destination); client retries with `PAYMENT-SIGNATURE` (Base64 `PaymentPayload`); server settles and returns `PAYMENT-RESPONSE` (Base64 `SettlementResponse`). Schemes include `exact`, `upto` and `batch-settlement`. A *facilitator* service that verifies/settles on the server's behalf is part of the ecosystem *(from background knowledge; the fetched page did not cover it; the GitHub repo page could not be fetched)*.

### 7.2 AP2 — Agent Payments Protocol (Google and partners)

- Apache-2.0, repository `google-agentic-commerce/AP2`, site ap2-protocol.org; described as an open **extension to A2A and MCP**. Spec v0.1 covers human-present "pull" payments (cards) and step-up challenges; human-not-present, push and recurring payments are planned for V1.x.
- **Mandates** are signed "verifiable digital credentials": the **Intent Mandate** (user-signed with a device-bound key when the human will be absent: criteria, allowed payment categories, prompt playback, TTL); the **Cart Mandate** (merchant-created, user-signed, merchant also signs to commit to fulfilment — exact items, amounts, refund terms); the **Payment Mandate** (shared with network/issuer, bound to the Cart/Intent mandate, signalling agent involvement and human presence).
- **Lesson:** AP2's mandates are *payment-specialised* versions of OIP's Intent and Commitment. An OIP Commitment can embed or link an AP2 Cart Mandate in `ext`, and an OIP Intent can link an AP2 Intent Mandate as the delegation evidence.

### 7.3 ACP — Agentic Commerce Protocol (OpenAI and Stripe)

- Apache-2.0, agenticcommerce.dev. Versioned by date: **2025-09-29** (initial: Agentic Checkout + Delegate Payment specs), **2025-12-12** (fulfilment changes, Intent Traces, affiliate attribution; `API-Version` header required), **2026-01-30** (capability negotiation, a structured **Payment Handlers** framework, an **Extensions Framework**, first extension = Discounts). Stripe's Shared Payment Token is the first compatible delegated-payment implementation; the merchant remains merchant of record.
- **Lesson:** ACP converged on the same answer OIP needs — a small core plus a declared, versioned **extensions framework** and capability negotiation.

### 7.4 Card networks

- **Visa Trusted Agent Protocol (TAP)** (announced 14 October 2025, within Visa Intelligent Commerce, developed with Cloudflare): agent verification, not a payment token — agents sign HTTP requests with **HTTP Message Signatures**, aligned with IETF **Web Bot Auth** (now an IETF WG draft, `draft-ietf-webbotauth-httpsig-protocol-00`, September 2026), carrying agent intent, consumer recognition and optional payment information. Specs on the Visa Developer Center and GitHub; Visa intends to align with IETF, OpenID Foundation and EMVCo.
- **Mastercard Agent Pay** (announced 29 April 2025): registered, verified agents pay with **Mastercard Agentic Tokens** built on network tokenisation, within consumer-set limits.
- Both are still rolling out in 2026 *(secondary sources)*.

### 7.5 Lightning L402

- HTTP 402 with `WWW-Authenticate` carrying a token (macaroon recommended) committed to a Lightning invoice's payment hash; the client pays, obtains the preimage, and presents token + preimage. Macaroons can be attenuated and delegated, so an agent can pass narrowed rights to sub-agents. Formerly called LSAT *(name history from background knowledge)*.

### 7.6 How OIP should carry payments

- **Never in the core.** Payment terms appear in an Offer/Commitment as an `ext` block (e.g., `ext["x402"]`, `ext["ap2"]`, `ext["acp"]`, `ext["l402"]`) carrying the scheme's own native objects (x402 `PaymentRequired`, AP2 mandate references, ACP checkout session IDs, L402 invoice).
- **Proof of payment is a Receipt.** A Receipt whose `evidence` includes the payment rail's own proof (x402 `SettlementResponse`, L402 preimage, on-chain transaction hash, ACP order ID) makes payment history part of the same linked web as task delivery.
- **Bridge role:** the Bridge (Layer 0) translates an HTTP 402 challenge into an OIP Offer with an x402 extension, and an outgoing OIP payment commitment into the rail's native call — so OIP minds can pay and be paid on every rail without OIP defining money.

---

## 8. Collectives and governance prior art

- **Multisig smart accounts (Safe):** an account controlled by *n* owners with a *threshold k*; transactions execute when k owners have signed. **EIP-1271** lets a contract account validate signatures on its own behalf (`isValidSignature`) so a collective can "sign" like an individual.
- **Threshold signatures — FROST, RFC 9591** (IRTF CFRG, Informational, June 2024): two-round threshold Schnorr signing; ciphersuites include Ed25519 (output verifies with a standard RFC 8032 verifier), ristretto255, Ed448, P-256 and secp256k1; trusted-dealer key generation in an appendix, DKG out of scope; nonces must be random, not deterministic. **Lesson:** FROST lets a collective have *one* public key indistinguishable from an individual's — elegant, but requires coordinated key generation and a two-round signing service. Too heavy as a v1 requirement; ideal as an optional profile.
- **DAOs:** on-chain governance (token-weighted voting, timelocks, proposal lifecycles) shows the value of explicit, machine-checkable decision rules — and the danger of hard-coding one voting model. OIP should let the Collective *declare* its policy and leave exotic policies to extensions.
- **Loomio:** proposals with positions *agree / abstain / disagree / block*, a closing time and a recorded outcome statement; multiple poll types (consent, score, ranked choice, etc.). *(Loomio help page could not be fetched; summary from search results and background knowledge.)* **Lesson:** a decision is itself a linkable record: proposal → votes → outcome — easily expressed as an Intent (proposal) addressed to the collective, member Receipts or signatures (votes), and a Commitment signed under the collective's policy (outcome).
- **Holacracy:** organisation as nested **circles** of **roles**, each with a *purpose*, *domains* (things it controls exclusively) and *accountabilities* (ongoing activities it is expected to perform), defined in a published constitution. **Lesson:** a Collective's rules can include named roles with delegated powers ("the Treasurer role may sign commitments up to N without a vote") — a natural fit for delegation in v1.
- **Multi-agent organisation research — Moise+** (Hübner, Sichman, Boissier, early 2000s): organisations specified along **structural** (roles, groups, links), **functional** (goals, missions/plans) and **deontic** (permissions and obligations of roles to missions) dimensions. **Lesson:** OIP's Collective should be minimal (membership + decision policy + roles), with richer organisational specification layered on through extensions; Moise+'s "obligation of a role to a mission" is exactly an OIP Commitment made by a role-holder on behalf of a Collective.

---

## 9. Recommended design: OIP Layer 2 (Mind Web) v1

### 9.1 Design goals

1. **Weekend-implementable:** only Ed25519, SHA-256, JSON and JCS (RFC 8785) are required.
2. **Immutable, linkable objects:** every object has a content ID; links are hash links.
3. **Public semantics:** meaning is defined by the signed public object (Singh's lesson), never by inferred internal states.
4. **State by succession:** state changes are new signed objects that link to the old ones; current state is a deterministic function of the linked set.
5. **Small core, open extensions:** anything not needed by all six primitives goes in namespaced `ext`.
6. **Bridge-friendly:** mappable to ActivityStreams, Verifiable Credentials, AP2/ACP/x402 objects.

### 9.2 Common envelope (all primitives)

| Field | Req. | Meaning |
|---|---|---|
| `oip` | yes | Protocol version string, `"0.1"` for v1 |
| `type` | yes | One of `Participant`, `Intent`, `Offer`, `Commitment`, `Receipt`, `Collective` |
| `author` | yes | Author's mind address (Layer 1). For v1: `did:key` with an Ed25519 key, or a Collective ID |
| `created` | yes | RFC 3339 UTC timestamp (author's claim) |
| `seq` | yes | Integer position in the author's feed, starting at 0 |
| `prev` | yes* | ID of the author's previous object in its feed (`null` only when `seq` = 0) |
| `links` | no | Array of `{ "rel": string, "id": oip-id }` typed hash links (in addition to the typed fields below) |
| `supersedes` | no | ID of an earlier object by the same author that this one replaces (new version / status change) |
| `expires` | no | RFC 3339 time after which the object should be treated as closed |
| `ext` | no | Object of namespaced extension blocks (§9.9) |
| `sigs` | yes | Array of signatures `{ "by": address, "alg": "Ed25519", "sig": base64url }` |

`@context` is **optional** — present only when a publisher wants JSON-LD processing; v1 implementations MUST ignore it for hashing/verification purposes other than including it in the canonical form like any other field.

### 9.3 Identifier scheme

1. Take the object **without** `id` and `sigs`.
2. Canonicalise with **JCS (RFC 8785)**; encode as UTF-8.
3. Hash with **SHA-256**.
4. Encode as a multihash (`0x12 0x20 ‖ digest`) in **base32-lower** with a `b` multibase prefix, producing a string like `bciq…`. *(Using a multihash makes later migration to CIDv1/IPLD trivial; exact prefix bytes should be verified against the multiformats tables during spec drafting.)*

The **content ID** is that string. The **full OIP reference** combines author and content:

```
oip:<author-address>/<content-id>
e.g. oip:did:key:z6MkhaXg…/bciqd4x…
```

The content ID alone is sufficient to verify an object (re-hash and compare); the author part tells a resolver *whose feed* to fetch it from. `id` MAY be included in the transmitted JSON for convenience but is never part of the hashed form.

Signatures are computed over the **same canonical bytes** that produce the content ID (equivalently over the 32-byte digest, prefixed with the domain-separation string `"OIP-v1-sig:"` to prevent cross-protocol signature reuse). Every signer signs the identical bytes, so adding a co-signature never changes the object's ID.

### 9.4 Signatures and multi-party commitments

- **Single author:** `sigs` contains the author's signature.
- **Multi-party (Commitment):** the Commitment lists `parties` with their roles. Because signatures cover the object minus `sigs`, each party can sign independently, in any order and over any channel; signed copies are merged by union of `sigs`. A Commitment is:
  - **proposed** — signed by at least one party but not all required parties;
  - **accepted (in force)** — signed by every party with `"required": true`.
- **Countersignature as a separate object (optional):** a party that wants its acceptance in its own feed publishes a tiny Receipt with `outcome: "accepted"` linking to the Commitment and carrying its signature. Either form is valid evidence of acceptance.
- **Key rotation and delegation** are Layer 1 concerns; Layer 2 verifiers resolve the signer's key *as of `created`* via Layer 1. For `did:key` (no rotation), the address is the key.

### 9.5 Lifecycles

Objects never mutate. Status is computed from the object and the signed objects linking to it.

| Primitive | States | Transition is evidenced by |
|---|---|---|
| Intent | `open` → `closed` (`satisfied` / `withdrawn` / `expired`) | A superseding Intent by the author with `status` set, or `expires` passing, or a Commitment linking it with `resolves` and `closesIntent: true` |
| Offer | `open` → `closed` (`withdrawn` / `expired` / `exhausted`) | Superseding Offer, `expires`, or quantity limit reached |
| Commitment | `proposed` → `accepted` → `fulfilled` / `broken` / `cancelled` (+ `disputed` as an overlay) | Signatures (proposed/accepted); Receipts with `outcome` (fulfilled/broken/cancelled/disputed) |
| Receipt | final on publication; may be `revoked` | A superseding Receipt by the same author with `outcome: "revoked"` |
| Collective | `active` → `dissolved`; membership/policy changes by succession | Superseding Collective object signed under the *previous* version's policy |

**Resolution rules (v1):**
- A Commitment is **fulfilled** when a Receipt with `outcome: "fulfilled"` is signed by the *creditor(s)* — or by any party when `terms.selfReport` is true. A fulfilment claim signed only by the debtor is recorded as `claimed-fulfilled` until accepted or disputed.
- **cancelled** requires signatures of all required parties on the cancelling Receipt (mutual release); **broken** may be asserted by any party (it is a claim; reputation systems decide how to weigh it).
- Conflicting claims (one party says fulfilled, another says broken) yield `disputed`; resolution is out of core scope (arbiters, collectives, or courts via extensions). This mirrors Singh's view that commitments are public claims whose compliance is judged from observable records.

### 9.6 The six primitives — minimal schemas

Required fields beyond the envelope are **bold**.

**Participant** — a mind's self-description (profile), published at `seq` 0 or later and superseded on change.
- **`name`**; `kind` (`human` | `agent` | `collective` | `institution` | `service` | other string); `capabilities` (array of free-text or URI tags); `endpoints` (array of `{ "proto": "https" | "a2a" | "mcp" | "email" | "activitypub" | …, "uri": … }`); `actsFor` (array of addresses with links to delegation evidence); `ext`.

**Intent** — what a mind wants.
- **`want`** (human-readable statement); `subject` (structured description, any vocabulary — e.g. a schema.org object or an MCP/A2A task spec); `constraints` (object: budget, deadline, location, quality, etc.); `audience` (`"public"`, or array of addresses/collectives, or a capability query); `status` (`open` default | `satisfied` | `withdrawn`).

**Offer** — what a mind can do, on what terms. May answer an Intent or stand alone (an advertisement).
- **`provides`** (human-readable); `subject`; **`terms`** (object; at minimum free text `summary`; may include `price`, `deliveryBy`, `quantity`, `conditions`); `inReplyTo` (Intent ID, if answering one); `audience`; `status`.

**Commitment** — a signed promise by one or more parties.
- **`parties`**: array of `{ "address": …, "role": "debtor" | "creditor" | "witness" | other, "required": bool }`; **`promise`**: human-readable statement of who will do what for whom (the Ricardian "readable" part); **`terms`**: structured terms (deadline, deliverables, payment reference, conditions, `selfReport`); `resolves`: array of Intent/Offer IDs this commitment resolves; `onBehalfOf`: Collective ID if a party commits for a collective; `closesIntent`: bool.

**Receipt** — verifiable evidence of what happened.
- **`about`**: Commitment ID (or any object ID); **`outcome`**: `accepted` | `progress` | `fulfilled` | `broken` | `cancelled` | `disputed` | `revoked` | extension-defined string; `statement`: human-readable account; **`evidence`**: array of evidence items (§9.7) — may be empty for `accepted`/`progress`; `rating`: optional object, e.g. `{ "score": 0–1 }` (reputation systems may ignore or use).

**Collective** — a group acting as one.
- **`name`**; **`members`**: array of `{ "address": …, "roles": [ … ] }`; **`policy`**: decision policy (§9.8); `purpose`: human-readable; `roles`: optional map of role name → `{ "purpose", "powers": [ … ] }` (Holacracy-style delegation); `status`: `active` | `dissolved`.

### 9.7 How receipts reference evidence

Each `evidence` item:

```json
{ "kind": "oip" | "hash" | "uri" | "vc" | "payment" | "log",
  "ref": "...",              // OIP ID, URI, tx id, etc.
  "digest": "sha256:<hex>",  // required for uri/hash kinds: binds the content
  "mediaType": "...",        // optional
  "note": "..." }            // optional human-readable
```

- `oip`: links another OIP object (e.g., a deliverable published as an Offer/Receipt, or a counterparty's receipt).
- `hash` / `uri`: an off-protocol artefact (file, dataset, web page, Git commit); the `digest` pins the exact bytes, so the artefact may be stored anywhere (S3, IPFS, a website) without weakening the evidence.
- `vc`: an embedded or linked W3C Verifiable Credential (e.g., an AP2 mandate, a certification, an inspection by a third party).
- `payment`: rail-specific proof — x402 `SettlementResponse`, L402 preimage, on-chain tx hash, ACP order ID — with `rail` named in an `ext` block.
- `log`: an inclusion proof from a transparency log, proving the evidence or the receipt itself was logged at a time.

### 9.8 How collectives sign

**v1 default — threshold of members (no special crypto):**

```json
"policy": { "kind": "threshold", "k": 2, "of": "members" }
```

A Collective-authored object (`author` = Collective ID) is valid when `sigs` contains valid signatures from at least *k* distinct current members (membership resolved as of `created` from the Collective's version chain). This uses only ordinary Ed25519 and is how Safe multisig and k-of-n PGP-style co-signing work.

**Collective ID:** the content ID of the Collective's **genesis object** (`seq` 0, signed by all founding members). Later versions `supersede` the previous one and must satisfy the previous version's policy — this gives the Collective a self-certifying, permanent address and a verifiable membership history, analogous to how Layer 1 gives individual minds self-certifying addresses.

**Other v1-allowed policy kinds** (all checkable mechanically):
- `"unanimous"` — all members;
- `"delegate"` — named roles may sign alone within declared `powers` (e.g., `{"role": "steward", "maxValue": "500 USD"}`); verification checks the signer holds the role;
- `"weighted"` — members carry weights, threshold is a weight sum.

**Optional profiles (extensions, not v1 core):**
- `ext["oip.frost"]`: the Collective publishes a single FROST(Ed25519) group key; signatures verify with ordinary Ed25519 — compact, private about which members signed, but requires a DKG/dealer and a two-round signing service.
- `ext["oip.vote"]`: Loomio-style proposals — the proposal is an Intent addressed to the Collective; members publish Receipts with `outcome` extended to `agree`/`abstain`/`disagree`/`block`; the outcome is a Collective-signed Commitment linking the proposal and the votes.
- `ext["eip1271"]`: the Collective is backed by an on-chain smart account; validation via EIP-1271.

### 9.9 Publication, linking and transparency

1. **Author feed (required):** every author publishes objects in an append-only, hash-chained feed (`seq`, `prev`). Minimal transport: an HTTPS directory `/.well-known/oip/feed/` returning newest-first pages plus `/.well-known/oip/obj/<content-id>`; any static host works. Layer 1 routing can carry the same objects as context packets. A **fork** (two different objects signed by the same author with the same `seq`) is self-proving misbehaviour.
2. **Co-signed objects** (Commitments) are published in *each* signing party's feed (same content ID, each feed's copy can carry the full merged `sigs`).
3. **Links:** typed fields (`inReplyTo`, `resolves`, `about`, `members`) plus generic `links` are all content IDs; backlinks ("which offers answer this intent?") are computed by indexers/crawlers — exactly as search engines compute web backlinks. The protocol does not require a global index.
4. **Checkpoints and transparency (optional):** an author may publish a signed `checkpoint` (feed length + Merkle root over its object IDs, RFC 9162 hashing with 0x00/0x01 prefixes) and submit it to one or more public logs (a Rekor-v2/Tessera-style tile log, or a Bitcoin timestamp via OpenTimestamps, which the OIP repository already uses for its own provenance). Witnesses co-sign checkpoints to catch split views. Inclusion proofs can then be cited as `evidence` of kind `log`.
5. **Privacy:** objects are public *by choice*. Private negotiations can exchange the same signed objects point-to-point (encrypted at Layer 1) and later disclose only the hash, or the full object, as needed — the ID stays valid either way.

### 9.10 Extension mechanism

- `ext` is an object whose keys are **namespaces**: reverse-DNS (`com.example.escrow`), a registered short name (`x402`, `ap2`, `acp`, `l402`, `vc`, `as2`, `schema.org`), or an `oip.*` name reserved for future OIP profiles.
- Each extension block MAY include `"v"` (its version) and MUST be ignorable: **unknown extensions MUST be preserved and MUST NOT change core validity**, unless listed in the envelope's optional `critical: ["ns", …]` array, in which case an implementation that does not understand it MUST treat the object as unverifiable-for-action (it can still store and forward it). This mirrors the critical-extension pattern in X.509/JOSE.
- Extensions may also define new `outcome` values, new `policy.kind` values and new evidence `kind`s, always namespaced (`"x402:settled"`).
- An optional registry (a plain Markdown file in the OIP repository) lists known namespaces; registration is never required.

### 9.11 Example objects

*Keys, hashes and signatures below are illustrative placeholders, not real values.*

**Participant**

```json
{
  "oip": "0.1",
  "type": "Participant",
  "author": "did:key:z6MkAgentTranslatorExample",
  "created": "2026-10-30T09:00:00Z",
  "seq": 0,
  "prev": null,
  "name": "Lexis Translation Agent",
  "kind": "agent",
  "capabilities": ["translate:sw-en", "domain:commercial-law"],
  "endpoints": [{ "proto": "https", "uri": "https://lexis.example/oip" },
                { "proto": "a2a", "uri": "https://lexis.example/.well-known/agent-card.json" }],
  "actsFor": [{ "address": "did:key:z6MkLexisLtdExample",
                "evidence": "oip:did:key:z6MkLexisLtdExample/bciqdelegationexample" }],
  "sigs": [{ "by": "did:key:z6MkAgentTranslatorExample", "alg": "Ed25519", "sig": "base64url…" }]
}
```

**Intent**

```json
{
  "oip": "0.1",
  "type": "Intent",
  "author": "did:key:z6MkHumanAminaExample",
  "created": "2026-10-30T10:00:00Z",
  "seq": 14,
  "prev": "bciqprevexample",
  "want": "Translate a 12-page Swahili commercial lease into English, legally accurate.",
  "subject": { "@type": "Service", "serviceType": "legal translation",
               "inputDigest": "sha256:9f2c…" },
  "constraints": { "deadline": "2026-11-02T17:00:00Z",
                   "budget": { "max": "150", "currency": "USD" },
                   "requires": ["domain:commercial-law"] },
  "audience": "public",
  "expires": "2026-10-31T10:00:00Z",
  "sigs": [{ "by": "did:key:z6MkHumanAminaExample", "alg": "Ed25519", "sig": "base64url…" }]
}
```

**Offer** (answering the Intent, with an x402 payment extension)

```json
{
  "oip": "0.1",
  "type": "Offer",
  "author": "did:key:z6MkAgentTranslatorExample",
  "created": "2026-10-30T10:04:00Z",
  "seq": 211,
  "prev": "bciqprev2example",
  "inReplyTo": "bciqintentexample",
  "provides": "Certified-quality EN translation of your lease, reviewed by a human lawyer.",
  "terms": { "summary": "120 USD, delivered by 1 Nov 18:00 UTC, one revision included.",
             "price": { "amount": "120", "currency": "USD" },
             "deliveryBy": "2026-11-01T18:00:00Z" },
  "expires": "2026-10-30T22:00:00Z",
  "ext": {
    "x402": { "v": 2, "accepts": [{ "scheme": "exact", "network": "eip155:8453",
                                     "asset": "USDC", "amount": "120000000",
                                     "payTo": "0xPayToExample" }] }
  },
  "sigs": [{ "by": "did:key:z6MkAgentTranslatorExample", "alg": "Ed25519", "sig": "base64url…" }]
}
```

**Commitment** (two-party, fully signed → accepted)

```json
{
  "oip": "0.1",
  "type": "Commitment",
  "author": "did:key:z6MkAgentTranslatorExample",
  "created": "2026-10-30T10:20:00Z",
  "seq": 212,
  "prev": "bciqofferexample",
  "parties": [
    { "address": "did:key:z6MkAgentTranslatorExample", "role": "debtor",   "required": true },
    { "address": "did:key:z6MkHumanAminaExample",      "role": "creditor", "required": true }
  ],
  "promise": "Lexis will deliver an English translation of the lease (input sha256:9f2c…) by 1 Nov 2026 18:00 UTC; Amina will pay 120 USDC on delivery.",
  "terms": { "deadline": "2026-11-01T18:00:00Z",
             "deliverables": [{ "describe": "EN translation PDF" }],
             "payment": { "amount": "120", "currency": "USDC", "when": "on-fulfilment" },
             "selfReport": false },
  "resolves": ["bciqintentexample", "bciqofferexample"],
  "closesIntent": true,
  "ext": { "x402": { "v": 2, "scheme": "exact", "network": "eip155:8453" } },
  "sigs": [
    { "by": "did:key:z6MkAgentTranslatorExample", "alg": "Ed25519", "sig": "base64url…" },
    { "by": "did:key:z6MkHumanAminaExample",      "alg": "Ed25519", "sig": "base64url…" }
  ]
}
```

**Receipt** (creditor-signed fulfilment, with delivery and payment evidence)

```json
{
  "oip": "0.1",
  "type": "Receipt",
  "author": "did:key:z6MkHumanAminaExample",
  "created": "2026-11-01T17:40:00Z",
  "seq": 19,
  "prev": "bciqprev3example",
  "about": "bciqcommitmentexample",
  "outcome": "fulfilled",
  "statement": "Translation received on time and reviewed; payment sent.",
  "evidence": [
    { "kind": "uri", "ref": "https://lexis.example/deliver/7731.pdf",
      "digest": "sha256:41ab…", "mediaType": "application/pdf" },
    { "kind": "payment", "ref": "0xTxHashExample", "note": "x402 settlement on Base" }
  ],
  "rating": { "score": 0.95 },
  "ext": { "x402": { "v": 2, "settlement": "base64-SettlementResponse…" } },
  "sigs": [{ "by": "did:key:z6MkHumanAminaExample", "alg": "Ed25519", "sig": "base64url…" }]
}
```

**Collective** (genesis, 2-of-3 threshold with a delegated role)

```json
{
  "oip": "0.1",
  "type": "Collective",
  "author": "did:key:z6MkResearchAgentAExample",
  "created": "2026-10-30T12:00:00Z",
  "seq": 0,
  "prev": null,
  "name": "Open Materials Research Cell",
  "purpose": "Find, test and publish candidate battery electrolytes.",
  "members": [
    { "address": "did:key:z6MkResearchAgentAExample", "roles": ["steward"] },
    { "address": "did:key:z6MkResearchAgentBExample", "roles": [] },
    { "address": "did:key:z6MkHumanDrOkaforExample",  "roles": ["reviewer"] }
  ],
  "policy": { "kind": "threshold", "k": 2, "of": "members" },
  "roles": {
    "steward": { "purpose": "Run day-to-day compute purchasing",
                 "powers": [{ "policy": "delegate", "maxValue": { "amount": "500", "currency": "USD" } }] }
  },
  "status": "active",
  "sigs": [
    { "by": "did:key:z6MkResearchAgentAExample", "alg": "Ed25519", "sig": "base64url…" },
    { "by": "did:key:z6MkResearchAgentBExample", "alg": "Ed25519", "sig": "base64url…" },
    { "by": "did:key:z6MkHumanDrOkaforExample",  "alg": "Ed25519", "sig": "base64url…" }
  ]
}
```

A later Commitment by this Collective would set `"author": "oip-collective:bciqgenesisexample"` (the genesis content ID) and carry signatures from any two members.

### 9.12 Weekend implementation checklist

1. `canonicalize(obj)` — JCS (libraries exist for JS, Python, Go, Rust, Java).
2. `contentId(obj)` — strip `id`/`sigs`, JCS, SHA-256, multihash, base32.
3. `sign(obj, key)` / `verify(obj)` — Ed25519 over `"OIP-v1-sig:" ‖ digest`; resolve `did:key` to a public key.
4. `Feed` — append with `seq`/`prev`; serve static JSON over HTTPS; detect forks.
5. `status(id, linkedObjects)` — the lifecycle rules in §9.5 as a pure function.
6. `collectiveValid(obj, collectiveChain)` — threshold/unanimous/delegate checks.
7. JSON Schemas for the six types; test vectors (fixed keys → fixed IDs/signatures) published in `spec/`.

### 9.13 Open questions for the architecture paper

- **Canonicalisation:** JCS-over-JSON (simple) vs DAG-CBOR (native CIDs, used by AT Protocol). Recommendation: JCS for v1, define a lossless DAG-JSON/CBOR mapping later.
- **Timestamps:** `created` is author-asserted; trusted time comes only from transparency logs or Bitcoin timestamps. Should deadlines reference log time in disputes?
- **Partial disclosure:** selective-disclosure receipts (SD-JWT, BBS) may be needed for private commerce — an extension candidate.
- **Equivocation economics:** how strongly should reputation systems punish feed forks?
- **Collective key rotation** when a member leaves under a threshold policy (supersession requires the old policy — what if *k* members are lost?). Possibly a recovery-role pattern.
- **Interop mappings** to AS2 (`Offer`/`Accept`), A2A task objects, AP2 mandates, ACP checkout sessions — to be specified in the Bridge.

---

## 10. Retrieval notes and uncertainty

- Could not be fetched during this session (permission timeouts or site errors): the x402 GitHub repository (`github.com/coinbase/x402`), Nostr NIP-01, Loomio's help page on proposals, the `did:key` method spec, and the FIPA Contract Net specification page. Statements about these are from background knowledge or secondary sources and are marked.
- Card-network agent programme details (Visa TAP, Mastercard Agent Pay) are from secondary sources; their 2026 rollout status is not independently confirmed.
- Multicodec/multihash byte values and the `z6Mk` `did:key` prefix should be verified against the multiformats tables before they enter a normative spec.

---

## Sources

**Agent communication languages and Contract Net**
- Munindar P. Singh, "A Social Semantics for Agent Communication Languages" — https://www.csc2.ncsu.edu/faculty/mpsingh/papers/mas/ijcai-99-acl.pdf
- Labrou, Finin, Peng, "Agent communication languages: the current landscape" (IEEE Intelligent Systems, 1999) — https://userpages.cs.umbc.edu/finin/papers/ieee99.pdf
- R. G. Smith, "The Contract Net Protocol" (IEEE Trans. Computers, Dec 1980) — https://www.cs.ucf.edu/~lboloni/Teaching/EEL6788_2008/papers/The_Contract_Net_Protocol_Dec-1980.pdf
- FIPA Contract Net Interaction Protocol Specification (not retrieved) — http://www.fipa.org/specs/fipa00029/SC00029H.html

**Web vocabularies**
- W3C Activity Vocabulary (ActivityStreams 2.0) — https://www.w3.org/TR/activitystreams-vocabulary/
- schema.org Demand — https://schema.org/Demand

**Signed agreements**
- Ian Grigg, "The Ricardian Contract" — https://iang.org/papers/ricardian_contract.html

**Intents**
- ERC-7683: Cross Chain Intents — https://eips.ethereum.org/EIPS/eip-7683
- Delphi Digital, "WTF is Anoma? Part 1 – Intents" — https://members.delphidigital.io/reports/wtf-is-anoma-part-1-wtf-are-intents
- Web3Auth, "A Focus on Intent-Based Architectures" — https://blog.web3auth.io/intents-blockchain-architecture/

**Credentials, logs, content addressing**
- W3C Verifiable Credentials Data Model v2.0 — https://www.w3.org/TR/vc-data-model-2.0/
- RFC 9162, Certificate Transparency Version 2.0 — https://www.rfc-editor.org/rfc/rfc9162.html
- Sigstore blog (Rekor v2 alpha, GA, 2026 update) — https://blog.sigstore.dev/index.xml and https://blog.sigstore.dev/rekor-v2-alpha/
- IETF Key Transparency Architecture, draft -09 — https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-architecture-09
- RFC 8785, JSON Canonicalization Scheme — https://www.rfc-editor.org/rfc/rfc8785.html
- Multiformats CID — https://github.com/multiformats/cid (maintained spec: https://specs.ipfs.tech/cid/)
- AT Protocol Repository spec — https://atproto.com/specs/repository
- Nostr NIP-01 (not retrieved) — https://github.com/nostr-protocol/nips/blob/master/01.md

**Reputation**
- Kamvar, Schlosser, Garcia-Molina, "The EigenTrust Algorithm for Reputation Management in P2P Networks" (WWW 2003) — https://zoo.cs.yale.edu/classes/cs457/fall13/Eigentrust.pdf
- IW3C2 Test-of-Time award 2019 — https://iw3c2.org/papers/2019-EigenTrust/
- Ethereum Attestation Service — https://docs.attest.org/docs/welcome and https://github.com/ethereum-attestation-service/eas-contracts

**Agent payments**
- The Block, x402 V2 (Dec 2025) — https://www.theblock.co/amp/post/382284/coinbase-incubated-x402-payments-protocol-built-for-ais-rolls-out-v2
- The Block, x402 to Linux Foundation (Apr 2026) — https://www.theblock.co/amp/post/396155/tech-crypto-giants-to-help-steward-coinbases-neutral-x402-payments-protocol-under-linux-foundation
- Coinbase CDP, x402 Foundation — https://docs.cdp.coinbase.com/x402/support/x402-foundation
- x402 docs, HTTP 402 core concept — https://docs.x402.org/core-concepts/http-402
- x402 GitHub (not retrieved) — https://github.com/coinbase/x402
- AP2 repository — https://github.com/google-agentic-commerce/AP2
- AP2 specification — https://ap2-protocol.org/specification/
- Agentic Commerce Protocol — https://www.agenticcommerce.dev/ and changelog https://agenticcommerce.dev/docs/changelog
- OpenAI Delegated Payment Spec — https://developers.openai.com/commerce/specs/payment
- Visa Trusted Agent Protocol specifications — https://developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications
- IETF HTTP Message Signatures for Bots (Web Bot Auth) — https://datatracker.ietf.org/doc/html/draft-ietf-webbotauth-httpsig-protocol
- Eco, Mastercard Agent Pay vs Visa Trusted Agent (secondary) — https://eco.com/support/en/articles/15192003-mastercard-agent-pay-vs-visa-trusted-agent-2026-compared
- Lightning Labs, L402 — https://docs.lightning.engineering/the-lightning-network/l402

**Collectives and governance**
- RFC 9591, FROST — https://www.rfc-editor.org/rfc/rfc9591.html
- EIP-1271 tutorial — https://ethereum.org/en/developers/tutorials/eip-1271-smart-contract-signatures/
- Safe smart account concepts — https://docs.safe.global/advanced/smart-account-concepts
- Loomio, "Why the distinction between Disagree and Block?" — https://www.loomio.com/d/xPyUG8tE/why-the-distinction-between-disagree-and-block
- Holacracy Constitution v5.0 — https://www.holacracy.org/constitution/5-0/
- Hübner, Sichman, Boissier, MOISE+ — https://www2.pcs.usp.br/~jaime/papers/hubner_jfiadsma02_f.pdf
