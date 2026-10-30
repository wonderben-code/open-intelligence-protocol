# Build Brief: OIP v1 Reference Implementation

This is the brief for building the first reference implementation of the Open Intelligence Protocol. It is written for the engineer or coding agent (for example, Claude Code) who will build it, and assumes no context beyond this repository.

## 1. Read first

1. [papers/01-founding-paper.md](papers/01-founding-paper.md): what OIP is for.
2. [papers/02-technical-architecture.md](papers/02-technical-architecture.md): how it works and why.
3. [spec/](spec/): the normative rules. **The specification is the source of truth.** If the paper and a spec disagree, follow the spec and fix the paper.
4. [spec/test-vectors/](spec/test-vectors/): golden values produced by an independent Python implementation. Your implementation must reproduce them byte for byte.

## 2. Goal

A complete, well-tested, open-source TypeScript implementation of OIP revision 2026-10-31 that lets anyone, in minutes:

- create a mind with a permanent `did:oip` address;
- publish its location, profile and feed;
- find other minds by capability;
- exchange signed (and optionally sealed) packets in sessions;
- make Intents, Offers, Commitments and Receipts, act under delegation, and form collectives;
- use all of the above from any MCP-capable assistant through the OIP MCP server;
- bridge A2A agents in and out.

## 3. Stack

- **Language:** TypeScript, ESM, Node.js 22 or later. Code that does not need Node APIs should also run in browsers and edge runtimes.
- **Monorepo:** pnpm workspaces. **Tests:** Vitest. **Lint and format:** ESLint and Prettier. **CI:** GitHub Actions running lint, type-check, tests and the Python vector checker on every push.
- **Cryptography:** audited, dependency-light libraries only. Suggested: `@noble/curves` (Ed25519, X25519), `@noble/hashes` (SHA-256), `@noble/ciphers`, `@scure/base` (base58btc, base32) and `canonicalize` (RFC 8785 JCS), plus an RFC 9180 HPKE library supporting DHKEM(X25519, HKDF-SHA256) with ChaCha20-Poly1305 (for example the `hpke-js` packages). Verify each package's current status before adopting it. **Never implement cryptographic primitives yourself.**
- **Servers:** Hono (portable across Node, Bun and edge runtimes) with `ws` for WebSockets; SQLite (`better-sqlite3`, with FTS5) for resolver and indexer storage; an RFC 9421 HTTP Message Signatures library.
- **Bridges:** the official MCP TypeScript SDK (`@modelcontextprotocol/sdk`) and the A2A JavaScript SDK.
- **Validation:** JSON Schemas for every record type (written from the spec as part of milestone 1), enforced with Ajv.

## 4. Repository layout

```
packages/
  core/          JSON profile, JCS, content IDs, Multikey, Data Integrity proofs, references
  identity/      identity logs: create, verify, state, DID documents, key validity, duplicity, lineage, collectives
  delegation/    delegations, chains, policies, revocations
  web/           Layer 2 records, countsFor, status functions, evidence
  net/           Location, Participant, Entry, Checkpoint, Packet, Session, Resume, Branch, Ack, Sealed
  keystore/      encrypted local key storage
  host/          well-known endpoints, inbox, WebSocket, mailbox
  resolver/      resolve, publish, stream, duplicity evidence
  indexer/       submit, query, signed results, brokered delivery
  client/        resolution, sending, receiving, sessions: the library apps use
  cli/           the `oip` command
  mcp-server/    the OIP MCP server
  bridge-a2a/    A2A gateway and Agent Card publication
  conformance/   a test suite that runs against any implementation's HTTP endpoints
examples/
  translation-demo/   the scenario from the papers, end to end
spec/schemas/    JSON Schemas (generated in milestone 1)
```

## 5. Milestones and acceptance criteria

Each milestone ends with passing tests, updated documentation and a commit.

**M1. Core.** JSON profile validation (no floats, safe integers, timestamp and decimal formats); JCS; content IDs; key hashes; Multikey encode/decode with prefix and length checks; `eddsa-jcs-2022` proof creation and verification; reference parsing; JSON Schemas for every record type.
*Accept:* every JCS output, content ID, address, key hash and `proofValue` in `spec/test-vectors/vectors.json` is reproduced exactly; tampering any byte of any vector record makes verification fail.

**M2. Identity.** Create and verify `Genesis`, `Update`, `Fork` and `Retire` events for key-controlled and member-controlled minds; identity state; key validity (Layer 1, Section 6) including revocation with compromise times and the latest-state rule for current-state records; DID document projection with `versionId`; duplicity detection; lineage classification (acknowledged or claimed); collective nesting limit.
*Accept:* all identity vectors verify; property-based tests show that reordered, truncated, re-signed or forged logs are rejected; a log replayed to any `versionId` yields the right state.

**M3. Delegation and Layer 2.** Delegations, chains up to length 8, the policy language, revocations; Intent, Offer, Commitment, Receipt and Collective records; `countsFor` (Layer 2, Section 7) including delegated and collective routes; the status functions of Layer 2, Section 8.
*Accept:* the vectors' 120/900 policy check behaves identically; a table-driven test covers every branch of every status function; co-signing never changes a content ID.

**M4. Network records.** Location, Participant, Entry and Checkpoint (RFC 9162 Merkle tree hash); Packet validation (Layer 1, Section 12.4); Session, Resume and Branch; Ack; Sealed (HPKE).
*Accept:* round-trip tests for every record; sealed packets open only with the right key; a session with a gap is detected and repaired by `Resume`.

**M5. Servers.** Host, resolver and indexer exactly as specified in Layer 1, Sections 13, 17 and 18, including WebSocket challenge authentication, RFC 9421-authenticated mailbox draining, the resolver stream, first-seen witnessing and duplicity evidence, the capability query with SQLite FTS5 ranking, signed `QueryResult`s and brokered delivery with fan-out limits and rate limiting.
*Accept:* the `conformance` package passes against all three servers; malformed or unsigned input is rejected with the right problem type.

**M6. Keystore and CLI.** An encrypted keystore (scrypt key derivation, XChaCha20-Poly1305) that keeps the next control key separate from everyday keys and never prints private keys. The `oip` command: `init`, `show`, `rotate`, `add-key`, `revoke-key`, `fork`, `publish`, `resolve`, `find`, `send`, `inbox`, `intent`, `offer`, `commit`, `receipt`, `status`, `delegate`, `collective create`, `collective sign`.
*Accept:* a new user can go from installation to a published, resolvable mind in under five minutes by following the README.

**M7. OIP MCP server.** The tools of Layer 0, Section 2.2, with keys outside the model's context, packet content presented as untrusted data, and confirmation before signing Commitments or Delegations.
*Accept:* works in the MCP Inspector and in at least one MCP host (for example Claude Desktop or Claude Code), with a copy-paste configuration snippet in the README.

**M8. A2A bridge.** Wrap an A2A agent as a bridged mind (Layer 0, Section 3.1); publish Agent Cards for OIP minds (3.2); support the OIP A2A extension (3.3).
*Accept:* an A2A sample agent completes a task for an OIP mind, and the task's completion produces a Receipt.

**M9. End-to-end demo.** `examples/translation-demo` runs the papers' scenario locally (Amina, Lexis Ltd, the Lexis agent, a 2-of-3 collective) with a host, a resolver and an indexer, and prints every step and every verification. A Docker Compose file starts the whole network.
*Accept:* one command runs the demo from a clean checkout; the output matches the narrative in the papers.

**M10. Public infrastructure (decision required).** A public resolver, indexer and host so that new users have somewhere to publish. This needs a hosting decision and an account from the project owner; prepare deployment configuration and stop for that decision rather than creating accounts.

## 6. Engineering rules

1. **Spec first.** Every MUST in the specification has a test. If implementing something reveals a gap or a mistake in the spec, fix the spec, the paper and the vectors in the same change, and record it in `spec/CHANGELOG.md`.
2. **Golden vectors.** `vectors.json` is a test fixture. Add new vectors to the Python generator (`spec/test-vectors/oip_vectors.py`) as well as to the TypeScript tests, so the two implementations keep checking each other.
3. **Strict input handling.** Validate every record against its schema and the core rules before doing anything else with it; reject on the first violation with the right problem type.
4. **No secrets in logs, errors or model context.** Private keys never leave the keystore except to sign.
5. **Small, documented packages** with typed public APIs and a README each.
6. **Licences.** Code under Apache-2.0 (see `LICENSE`); add the SPDX identifier to source files.
7. **Commits.** Small, frequent commits with clear messages. Every push to `main` is timestamped on Bitcoin, and branch heads are stamped every six hours.

## 7. Out of scope for v1

Merges; recovery keys; witness gossip between resolvers; P-256 and passkeys; DIDComm, libp2p, iroh, NATS and MQTT bindings; DHT and DNS-AID publication; the OAuth bridge; credential export; payment-rail gateways; MLS and ratcheted sessions; threshold signatures; pairwise addresses. These are listed in Section 10 of the technical paper and follow v1.

## 8. Definition of done

v1 is done when M1 to M9 are complete, CI is green, the conformance suite passes against the reference servers, the demo runs from a clean checkout, and the README lets a newcomer create a mind, find another and make a Commitment with it.
