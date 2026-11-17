# OIP v1: The Build Plan

This is the plan for building the reference implementation of the Open Intelligence Protocol. It aims to be production-grade from the first commit, complete across all three layers, and ready for the world to build on.

It is written for the engineer or coding agent who builds it (for example, Claude Code) and assumes no context beyond this repository. [CLAUDE.md](CLAUDE.md) says how work is run here; [PROGRESS.md](PROGRESS.md) says where the build stands.

**Implements:** specification revision 2026-11-17 ([spec/](spec/)) · **Papers:** [founding paper](https://doi.org/10.5281/zenodo.24301206) and [technical architecture](https://doi.org/10.5281/zenodo.24301209)

1. [What v1 is](#1-what-v1-is)
2. [The quality bar](#2-the-quality-bar)
3. [Architecture](#3-architecture)
4. [Technology](#4-technology)
5. [The build order](#5-the-build-order)
6. [Workstreams through every milestone](#6-workstreams-through-every-milestone)
7. [How the work runs](#7-how-the-work-runs)
8. [Decisions and actions only Eks takes](#8-decisions-and-actions-only-eks-takes)
9. [Definition of done](#9-definition-of-done)
10. [After v1](#10-after-v1)

## 1. What v1 is

v1 is the first complete implementation of OIP and the reference that every later implementation is measured against. People will run it, build on it, read it to learn how OIP works, and trust it with their keys. It is built to that standard from the first commit. In order: it is correct, then secure, then clear, then fast, then a pleasure to use.

### 1.1 What ships

| For | What | Where |
|---|---|---|
| Developers | A typed SDK for every layer, for servers, browsers and edge runtimes | `@oip/*` packages |
| Anyone with a terminal | The `oip` command | `@oip/cli` |
| Every MCP-capable assistant | The OIP MCP server: an assistant joins the network with one configuration snippet | `@oip/mcp-server` |
| A2A agents | A gateway in both directions | `@oip/bridge-a2a` |
| Operators | Host, resolver and indexer servers, as libraries and as signed container images | `@oip/host`, `@oip/resolver`, `@oip/indexer` |
| Implementers | A conformance suite for every profile, JSON Schemas, the test vectors, a `did:oip` method specification and DID resolver drivers | `@oip/conformance`, `@oip/did-resolver`, `spec/` |
| Everyone | OIP Explorer: look up any mind and watch every signature verify in the browser | `apps/explorer` |
| The curious | The papers' scenario as a demo network that starts with one command | `examples/translation-demo` |

`@oip` is the intended npm scope (decision G1, Section 8). Use it in code from the start; if G1 settles on another scope, rename it in one change.

### 1.2 The five-minute promise

A newcomer who has Node.js installed can follow the README and, within five minutes, go from nothing to a published, resolvable mind that finds another mind by capability and makes a signed Commitment with it. Every milestone protects this promise, and M7 measures it.

### 1.3 Profiles

v1 implements every conformance profile in [spec/README.md](spec/README.md): Core, Mind, Host, Resolver, Indexer, Mind Web, and Gateway for both MCP and A2A.

## 2. The quality bar

This table makes "production-grade" concrete. Each row is enforced in CI from the milestone in which the code it covers lands. None is waived to finish a milestone sooner.

| Dimension | The bar | Enforced by |
|---|---|---|
| **Conformance** | Every value in `spec/test-vectors/vectors.json` reproduced byte for byte; every must-accept case and control accepted; every negative case rejected, for its stated reason | `pnpm test:vectors` |
| **Spec traceability** | Every numbered clause of the specifications that states a requirement has at least one test that cites it (`clause("L1 6.4")`). By M12, no MUST is left untested | `pnpm spec:coverage` |
| **Differential testing** | This implementation and the independent Python checker give the same verdict on randomly generated logs, records, delegations and evidence | on every PR that touches verification; a longer run nightly |
| **Test depth** | Property-based tests for every parser and verifier. Line and branch coverage of at least 95% for `core`, `identity`, `delegation`, `web` and `net`, and 85% elsewhere. A mutation score of at least 85% for the verification code | Vitest coverage; Stryker weekly and on release branches |
| **Security** | Strict Ed25519 (core 4.4); size, count and depth limits on every input (L1 19); schema validation before any processing; an SSRF guard on every outbound fetch; no secrets in logs, errors or model context; a fuzz target for every parser; a threat model for every service | CI, fuzzing jobs, review gates |
| **Types and API** | TypeScript `strict`, with `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`; no `any` in public APIs; public API reports checked in; semantic versioning | `tsc`, ESLint, API Extractor, Changesets |
| **Layering** | Pure packages do no I/O and never read the clock; no package imports a layer above it | dependency-cruiser |
| **Performance** | The budgets in Section 3.8, measured by benchmarks. A regression of more than 10% on a hot path fails the PR | benchmark job |
| **Operability** | Structured logs, metrics, traces, health and readiness endpoints, graceful shutdown, versioned migrations, documented backups | integration tests, ops guide |
| **Supply chain** | Frozen lockfile; GitHub Actions pinned by commit SHA; few dependencies, each justified in an ADR; SBOMs; npm provenance through trusted publishing; signed container images | release workflow; OpenSSF Scorecard, with every check the project controls passing |
| **Docs and DX** | A README per package with a runnable example; API reference; guides; error messages that say what went wrong and what to do | docs job: every example compiles and runs |
| **Licensing** | Apache-2.0 code with SPDX headers; CC BY 4.0 documents | `reuse lint` |
| **Portability** | Node.js 24 LTS and later. Pure packages and the client also run in browsers, Deno and Bun | CI matrix, Playwright browser tests |

## 3. Architecture

### 3.1 Layers

```
 apps and tools   cli · mcp-server · bridge-a2a · explorer · examples
                                   │
 services         host · resolver · indexer          (Hono, SQLite)
                                   │
 client           client  ─────────── keystore
                                   │
 protocol         net         Layer 1 records, packets, sessions, sealing, bindings
                  web         Layer 2 records, countsFor, status
                  delegation  chains, policies, revocations
                  identity    logs, state, key validity, evidence, duplicity, lineage, collectives
                                   │
 foundation       core        JSON profile, JCS, content IDs, Multikey, proofs, strict Ed25519
                  schema      JSON Schemas and types for every record
```

The rules:

1. **Pure packages.** Foundation and protocol packages do no network or file I/O, read no environment and never read the clock. The current time and the verifier's evidence are passed in as parameters. So these packages run anywhere and are deterministic under test.
2. **I/O lives at the edges**: in the keystore, client, services and tools.
3. **One-way dependencies.** A package depends only on packages below it.
4. **Validate, verify, then use.** Everything that arrives from outside is checked against its schema and the core rules, then verified, before any other code touches it.

### 3.2 Packages

| Package | Responsibility | Runs in |
|---|---|---|
| `@oip/schema` | JSON Schemas (2020-12) for every record type in core 11, exported to `spec/schemas/`; TypeScript types; compiled validators | anywhere |
| `@oip/core` | JSON profile (core 1); JCS (core 2); content IDs and key hashes (core 3); Multikey and keys (core 4); `eddsa-jcs-2022` proofs with strict Ed25519 (core 4.4, 5); references and proof digests (core 6); common fields (core 7); extensions (core 8); time (core 9); problem types (core 10) | anywhere |
| `@oip/identity` | Identity-log events and verification (L1 3–4); identity state and DID documents (L1 5); key validity (L1 6); evidence and evaluation times (core 9); duplicity (L1 7); lineage (L1 8); collectives, heights and charters (L1 9) | anywhere |
| `@oip/delegation` | Delegations, chains carried in a proof's `authority`, the policy language, revocations, `/oip/send` (L1 11) | anywhere |
| `@oip/web` | Intent, Offer, Commitment, Receipt and Collective (L2 2–6); `countsFor` and the author rule (L2 7); status functions (L2 8); evidence (L2 9) | anywhere |
| `@oip/net` | Feeds and checkpoints with RFC 9162 Merkle trees (L1 10); packets and sealing with HPKE (L1 12); bindings and RFC 9421 HTTP signatures (L1 13); sessions (L1 14); location records (L1 15); profiles (L1 16) | anywhere |
| `@oip/keystore` | Encrypted key storage by role, with backups and an OS keychain adapter | Node; browser adapter |
| `@oip/client` | The library apps use: create and manage a mind, publish, resolve, find, send, receive, sessions, Layer 2 objects, delegation, collectives. It verifies everything it receives | Node, browsers, edge |
| `@oip/host` | Well-known resources, inbox, WebSocket, mailbox (L1 13) | Node, container |
| `@oip/resolver` | The resolver API, first-seen witnessing, the stream and duplicity evidence (L1 17) | Node, container |
| `@oip/indexer` | Submission, capability queries, signed `QueryResult`s, brokered delivery (L1 18) | Node, container |
| `@oip/cli` | The `oip` command | Node |
| `@oip/mcp-server` | The OIP MCP server (L0 2.2) | Node |
| `@oip/bridge-a2a` | The A2A gateway, Agent Cards and the OIP extension for A2A (L0 1, 3) | Node, container |
| `@oip/conformance` | The conformance suite, for library adapters and over the wire for any implementation, by profile | Node |
| `@oip/did-resolver` | A `did:oip` driver for the DIF `did-resolver` library, plus a DIF Universal Resolver driver image | anywhere; container |
| `apps/explorer` | OIP Explorer | browser, static hosting |
| `examples/*` | `translation-demo` and short focused examples | Node |

### 3.3 Time and evidence in code

OIP judges every time rule on **evidence** of when a signature existed (core 9), never on the signer's own `created`. This is the part of OIP that is easiest to get subtly wrong, so it gets one clear design:

- Verification functions take an `EvidenceView` and a `now`. The view answers "what is the earliest time this verifier can show this proof (by proof digest) or this identity event (by content ID) existed?" Its answers come from the verifier's own first-seen store, the witnesses it trusts, anchored checkpoints and acknowledgements (core 9.4).
- `t(p) = max(p.created, τ(p))` and `eventTime(e) = max(e.created, τ(e), eventTime(prev))` are implemented once, in `@oip/identity`, and used everywhere else.
- Before counting a proof, a verifier holds the signer's log as a trusted witness served it, with that witness's first-seen times (core 9.4). The client does this automatically when it resolves.
- Services persist first-seen times in append-only tables and serve them as `firstSeen`. They never lose or rewrite them.
- The `seen` convention in the test vectors maps directly onto `EvidenceView`.

### 3.4 Keys and signing

- Keys have roles: control keys (the next one is pre-rotated), operational keys, invocation keys and agreement keys (L1 3). The keystore keeps each role apart. It stores the next control key separately, destroys a control key once the event it signed is published, and never exports a private key except in an encrypted backup.
- Signing goes through a `Signer` interface, so hardware and remote signers fit later without API changes.
- In the MCP server, keys stay in the server process and never enter the model's context (L0 2.2).

### 3.5 Errors

HTTP APIs return RFC 9457 problem details with `type` set to `urn:oip:error:<code>` (core 10.2). Library errors are typed (`OipError`, with a `code`, a human `detail` and the spec `clause` they enforce) and never contain key material. Every error message says what was wrong and, where possible, what to do.

### 3.6 Storage

Services use a storage interface with a SQLite implementation (`better-sqlite3`, WAL mode, FTS5 for the indexer). Logs, first-seen times and feeds live in append-only tables. Migrations are versioned and tested. Backups with Litestream are documented. A PostgreSQL implementation is a v1.x item, and the interfaces must not rule it out.

### 3.7 Security architecture

- **Inputs.** Each input is checked against the limits of L1 19 and core 1.6 before it is parsed, then against its schema and the core rules, then verified.
- **Outbound requests** (resolvers fetching homes, gateways fetching Agent Cards) go through one guarded fetcher. It allows HTTPS only, resolves DNS and blocks private, loopback, link-local and metadata addresses, sets size and time limits, and follows no cross-host redirects.
- **Abuse.** Rate limits and quotas apply per IP address and per mind. The replay rules of L1 12.4 are enforced, with nonce stores that expire. WebSocket and stream limits are enforced too.
- **Untrusted content.** Packet content is data, never authority (L1 12.5). The MCP server labels it as untrusted and asks for confirmation before signing a Commitment or a Delegation (L0 2.2).
- **Threat models.** Each service and each tool gets a STRIDE threat model in `docs/threat-models/`, which is kept up to date.

### 3.8 Performance budgets

These are the starting budgets. M1 and M5 measure them on a reference machine, record the results in an ADR and adjust if needed. After that, a regression fails CI.

| Operation | Budget |
|---|---|
| Verify a record with two proofs (public-key order checks cached) | 2 ms median, single core |
| Verify a 1,000-event identity log | 1 s |
| Resolver: resolve a known mind | p99 of 25 ms at 500 requests per second on one core |
| Resolver: accept a published bundle | p99 of 100 ms |
| Indexer: capability query over 100,000 profiles | p99 of 100 ms |
| Packet delivery over WebSocket, same machine | p99 of 20 ms |
| Cold start of a server container | 2 s |

## 4. Technology

At M0, check each choice's current version, maintenance, licence and security history, then record the decision in an ADR. Prefer audited, dependency-light libraries. **Never implement a cryptographic primitive.**

| Concern | Choice | Notes |
|---|---|---|
| Language | TypeScript, strict, ESM only | |
| Runtime | Node.js 24 LTS and later | pure packages and the client must also run in browsers, Deno and Bun |
| Monorepo | pnpm workspaces | add a task cache (Turborepo) only if build times call for it |
| Build | `tsc` with project references | |
| Tests | Vitest, fast-check (property-based), Stryker (mutation), Playwright (browser and Explorer) | |
| Lint and format | ESLint (typescript-eslint, strict type-checked), Prettier | |
| API and docs | API Extractor reports, TypeDoc | |
| Versioning and release | Changesets; npm trusted publishing with provenance | |
| Signatures and keys | `@noble/curves` (Ed25519, X25519), `@noble/hashes` (SHA-256, scrypt), `@noble/ciphers` (XChaCha20-Poly1305, ChaCha20-Poly1305), `@scure/base` (base58btc, base32) | apply core 4.4 on top of the library: pass `{ zip215: false }` or its equivalent in the version adopted, and reject public keys and `R` values that are not of order exactly L. The vectors have keys and signatures on each side of the rule |
| Sealing | an RFC 9180 HPKE implementation supporting DHKEM(X25519, HKDF-SHA256) with ChaCha20-Poly1305, for example the `hpke-js` packages | check it against the RFC 9180 test vectors for that suite |
| Canonical JSON | `canonicalize` (RFC 8785) | check it against the vectors and the RFC 8785 examples |
| Schemas | TypeBox, generating JSON Schema 2020-12; Ajv with standalone validators | |
| HTTP and WebSocket | Hono with `@hono/node-server`; `ws` | |
| HTTP signatures | an RFC 9421 library if a mature one exists, otherwise a small implementation over `@noble/curves` | test against RFC 9421 Appendix B |
| Storage | `better-sqlite3` (WAL, FTS5) | |
| Observability | `pino`; OpenTelemetry for traces and metrics; a Prometheus endpoint | |
| MCP and A2A | `@modelcontextprotocol/sdk`; the A2A JavaScript SDK | |
| DIDs | DIF `did-resolver` | |
| Explorer | Vite and React, using `@oip/client` in the browser | static build |
| Containers | distroless images that run as non-root with a read-only file system; multi-architecture; signed with cosign (keyless); SBOMs from Syft | GitHub Container Registry |
| Supply chain | Renovate (or Dependabot); `pnpm audit` and OSV-Scanner; CodeQL; dependency review; OpenSSF Scorecard; Actions pinned by SHA | |

## 5. The build order

Build one milestone at a time, in this order: each one builds on the last. A milestone is **done** when all four of these hold:

- its acceptance criteria pass in CI;
- its documentation is written;
- an independent review agent has checked it against the specification (Section 7), and every finding has been fixed or logged as an issue;
- [PROGRESS.md](PROGRESS.md) is updated.

Sizes are rough: **S** is about one focused session, **M** two or three, **L** four or more.

### M0. Foundations (M)

**Goal.** A repository where correct, secure code is the easy path.

- **Workspace and tooling.**
  - pnpm workspace (`packages/*`, `apps/*`, `examples/*`), with `packageManager` pinned, a `.node-version` file and `.editorconfig`.
  - A strict base `tsconfig` with project references.
  - ESLint, Prettier and Vitest with coverage; fast-check; API Extractor; Changesets; TypeDoc; dependency-cruiser rules for Section 3.1; REUSE configuration with SPDX headers.
  - Root scripts: `build`, `test`, `test:vectors`, `lint`, `typecheck`, `spec:coverage`, `bench`, `docs`.
- **CI** in GitHub Actions, pinned by SHA:
  - install with a frozen lockfile; lint; typecheck; tests on Node 24 and the newest Node;
  - the Python vector checker; `reuse lint`; CodeQL; dependency review; OpenSSF Scorecard.
  - Leave the Bitcoin timestamp workflows as they are.
- **Community and governance files.**
  - `CONTRIBUTING.md`, with DCO sign-off; `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1); `SECURITY.md`, with private vulnerability reporting.
  - `GOVERNANCE.md`: the OIP Enhancement Proposal (OEP) process from Section 12 of the technical paper, with an `oeps/` template.
  - Issue templates (bug, spec question, OEP), a PR template with the done-checklist, and `CODEOWNERS`.
- **ADRs** in `docs/adr/`:
  - ADR-0001, tooling;
  - ADR-0002, cryptography libraries;
  - ADR-0003, the evidence model in code (Section 3.3);
  - ADR-0004, error model and problem types.
- **`@oip/schema`.** A schema for every record type in core 11, exported to `spec/schemas/`, with a CI check that the exported files are current.
- **Vector harness.** A typed loader for `vectors.json`, plus a runner for each case kind (`log`, `countsFor`, `sentFor`, `status`, `assurance`, `record`) that calls the implementation through adapters. Every case starts as pending and turns green milestone by milestone, so progress is visible.
- **Spec traceability.**
  - `scripts/spec-clauses` extracts every numbered clause of `spec/*.md` (for example `core 4.4`, `L1 6.4`, `L2 8.3`, `L0 2.2`), with its RFC 2119 keywords, into `spec/clauses.json`.
  - Tests cite the clauses they enforce.
  - `pnpm spec:coverage` writes `docs/conformance/coverage.md` and fails on any MUST clause that is neither tested nor listed as pending for a later milestone.
- **Differential harness.**
  - Add a `--judge` mode to `spec/test-vectors/oip_vectors.py`: it reads a case in the vectors' format on standard input and prints its verdict.
  - Add a TypeScript runner that generates cases with fast-check and compares verdicts with the Python checker. It is wired up fully in M2.

**Accept.**
- CI is green on the wired, empty workspace.
- Every vector record validates against its schema, and every malformed `record` case fails.
- `pnpm spec:coverage` lists every clause.
- A contributor can clone the repository and run `pnpm install && pnpm test` in under two minutes.

### M1. Core (M)

**Build.**
- The JSON profile (core 1): I-JSON with no duplicate member names, safe integers only, decimal strings with exact arithmetic, amounts that are never negative, timestamps compared at full precision, durations, string lengths in code points and the 1 MiB limit.
- JCS (core 2).
- Content IDs with their one canonical spelling, `^bciq[a-p][a-z2-7]{50}[aiqy]$`, and key hashes (core 3).
- Multikey with prefix and length checks (core 4).
- `eddsa-jcs-2022` proof creation and verification (core 5), with strict Ed25519 (core 4.4): `S < L`, canonical encodings, and `A` and `R` of order exactly L, which excludes the identity point and every small-order or mixed-order point. Order checks on public keys are cached.
- Proof purposes, at most 256 proofs per record, references and proof digests (core 6), extension handling (core 8), and problem types (core 10).

**Accept.**
- Every JCS output, content ID, address, key hash and `proofValue` in the vectors is reproduced.
- Non-canonical content-ID spellings are rejected.
- The Ed25519 negative cases are rejected and their controls accepted.
- Changing any byte of any vector record makes verification fail (property test).
- 10⁶ generated inputs to the JSON-profile parser cause no crash and no acceptance of out-of-profile input.
- The first two budgets in Section 3.8 are measured.
- The mutation score is at least 85%.

### M2. Identity (L)

**Build.**
- Create and verify `Genesis`, `Update`, `Fork` and `Retire` events for key-controlled and member-controlled minds, with majority thresholds (`2t > n`) and parameter checks. `Merge` and the member name `recovery` are reserved and rejected (L1 3–4).
- Identity state with operational, invocation and agreement keys.
- Evaluation times from evidence (core 9), and a first-seen store keyed by proof digest for proofs and by content ID for events.
- Holding a signer's log with a witness's first-seen times before counting its proofs (core 9.4).
- Key validity (L1 6):
  - removal, revocation with compromise times and retirement;
  - the current-state rule for `Location`, `Participant` and `Hello`;
  - members' proofs on a collective's identity events judged at the event's evaluation time (L1 6.4).
- DID documents with `versionId` (L1 5).
- Duplicity detection and resolution by earliest evidence, with every branch's removals applying (L1 7).
- Lineage through `Fork` events and `Lineage` records (L1 8).
- Collectives, with heights fixed at genesis and charters (L1 9).

**Accept.**
- All identity vectors and DID documents reproduce.
- Every identity case in `negative` is rejected, and every identity case in `valid` and `controls` is accepted.
- Property tests show that reordered, truncated, re-signed or forged logs are rejected.
- A log replayed to any `versionId` yields the right state.
- Differential testing with the Python checker runs 10,000 generated logs per PR (10⁶ nightly) with no disagreements.

### M3. Delegation and Layer 2 (L)

**Build.**
- Delegations carried in a proof's `authority`, checked exactly as listed: one chain, root first, at most 8 links, never searched for. A delegate differs from its author. A proof counts for its signer and at most one other mind (L1 11).
- The full policy language: comparisons on decimals only, connectives, quantifiers and selectors. A missing path or a malformed value is an error that fails the whole policy.
- Revocations taking effect from their evidence, and `/oip/send`.
- Intent, Offer, Commitment (with `payer` and `payee` in `price`), Receipt and Collective records (L2 2–6).
- `countsFor` (L2 7), by every route: delegated; threshold (proofs without `authority`, and the latest membership for current-state records); and role (proofs that name the charter). The author rule applies.
- The status functions (L2 8), including `superseded` and `disputed`, and evidence (L2 9).

**Accept.**
- The vectors' policy cases behave identically: 120 and 500 USD within the agent's authority; 500.01 and 900 USD not; the payee, self-dealing and counterparty limits; a negated comparison on a missing member.
- Every Layer 2 and delegation case in `negative` is rejected, and every control is accepted.
- Table-driven tests cover every branch of every status function.
- Co-signing never changes a content ID.
- Differential testing is extended to delegations and status.

### M4. Network records and sealing (M)

**Build.**
- `Location`, `Participant`, `Entry` (committing to the proofs of what it publishes) and `Checkpoint`, with the RFC 9162 Merkle tree hash (L1 10, 15, 16).
- `Lineage`; packets with their replay rules (L1 12.4); `Session`, `Resume` and `Branch` with per-sender, per-instance chains (L1 14); `Ack`; `Hello`.
- `Sealed` with HPKE (L1 12).
- Endpoint bindings and RFC 9421 HTTP message signatures (L1 13).

**Accept.**
- Every network-record vector reproduces, and round-trip tests pass for every record type.
- RFC 9162, RFC 9180 (for the chosen suite) and RFC 9421 test vectors pass.
- A sealed packet opens only with the right key.
- A session with a gap is detected and repaired by `Resume`.
- Duplicate and replayed packets are rejected inside their window and forgotten after it.

### M5. Servers: host, resolver and indexer (L)

**Build.**
- The three services exactly as L1 13, 17 and 18 specify:
  - well-known resources, the HTTPS inbox and the WebSocket binding with challenge authentication;
  - the mailbox, with RFC 9421-authenticated draining;
  - `GET` and `PUT` on `/oip/v1/resolve/<mindId>`;
  - the resolver stream, first-seen witnessing per identity event and per proof (served as `firstSeen`), and duplicity evidence;
  - the capability query, ranked with SQLite FTS5, with signed `QueryResult`s;
  - brokered delivery, with `brokers` checks and fan-out limits.
- Production features:
  - configuration validated at start-up; storage with migrations;
  - the guarded fetcher; rate limits; CORS for browser clients;
  - logs, metrics and traces; `/healthz` and `/readyz`; graceful shutdown;
  - container images and a Docker Compose file.
- `@oip/conformance` over the wire: tests by profile that run against any implementation's endpoints and produce a machine-readable report.
- Threat models for the three services.

**Accept.**
- The conformance suite passes against all three servers.
- Malformed, oversized, unsigned or replayed input is rejected with the right problem type.
- Load tests meet the Section 3.8 budgets.
- Restarts mid-stream, lock contention and a severed host connection lose no first-seen evidence.
- The HTTP fuzz targets run clean.

### M6. Client SDK and keystore (L)

**Build.**
- **The keystore.**
  - scrypt key derivation with XChaCha20-Poly1305, keeping every role apart (Section 3.4);
  - destroys control keys once used;
  - encrypted backup and restore;
  - an OS keychain adapter and an IndexedDB adapter for browsers.
- **`@oip/client`**, with a `Mind` API covering:
  - create, rotate, add, revoke and fork;
  - publish location, profile and feed;
  - resolve, with the witness rule of core 9.4 applied automatically;
  - find; send and receive, sealed or not; sessions with resume;
  - Intents, Offers, Commitments (co-signing), Receipts and status;
  - delegate and revoke; collectives (create, sign by threshold and by role).
- Everything received is verified before it is returned.
- A reconnecting WebSocket client and an offline outbox.

**Accept.**
- The papers' scenario runs through the SDK against in-process servers, in Node and in a browser (Playwright).
- Every public method has documentation and a runnable example.
- The API report is reviewed and frozen for 0.x.

### M7. The `oip` command (M)

**Build.**
- Core commands: `init`, `show`, `rotate`, `add-key`, `revoke-key`, `fork`, `publish`, `resolve`, `find`.
- Messaging: `send`, `inbox`.
- Layer 2 and delegation: `intent`, `offer`, `commit`, `receipt`, `status`, `delegate`, `revoke`, `collective create`, `collective sign`.
- Tools: `verify` (verify any record, log or bundle and explain every verdict with its spec clause), `keys backup`, `keys restore`, `doctor`, and `demo`.
- Every command has `--json` output and `--help` with an example. Shell completions. Private keys are never printed.

**Accept.**
- The five-minute promise is measured by a scripted newcomer run: a fresh container follows the README, and the run takes under five minutes in CI.
- Snapshot tests cover the help and output of every command.

### M8. OIP MCP server (M)

**Build.**
- The tools of L0 2.2: `oip_whoami`, `oip_find`, `oip_send`, `oip_inbox`, `oip_publish_intent`, `oip_make_offer`, `oip_commit`, `oip_receipt`, `oip_status`.
- Tool descriptions written for models.
- Keys stay in the server.
- Packet content is marked as untrusted data.
- Confirmation through MCP elicitation before signing a Commitment or a Delegation, unless the user has configured a policy that permits it.
- Configuration snippets for Claude Desktop, Claude Code and other MCP hosts.

**Accept.**
- The server passes MCP Inspector checks in CI and works in Claude Desktop and Claude Code.
- A prompt-injection suite passes: packets whose content tries to make the model commit, delegate or leak never cause a signature without confirmation.
- It is ready for the official MCP Registry. The listing itself is gate G6.

### M9. A2A bridge (M)

**Build.**
- Bridged minds for A2A agents, each attested by an entry in the gateway's feed that names the bridged genesis (L0 1.2, 3.1), with assurance levels (L0 1.3).
- Agent Cards for OIP minds, with the mapping and digest of L0 3.2.
- The OIP extension for A2A, with its URI as given in L0 3.3.
- A Receipt when a bridged task completes.
- The guarded fetcher for Agent Cards.

**Accept.**
- An A2A sample agent completes a task for an OIP mind, and the task's completion produces a Receipt.
- The A2A Technology Compatibility Kit passes wherever it applies.
- A self-attested bridged mind is labelled `claimed`.

### M10. The demo network (S)

**Build.**
- `examples/translation-demo` runs the papers' scenario: Amina, her assistant, Lexis Ltd, the Lexis agent, a research agent and a 2-of-3 collective, on a local host, resolver and indexer. It prints every step and every verification as a readable narrative.
- `docker compose up` starts the whole network, and `oip demo` runs the demo without Docker.
- A recorded terminal session and a short animation for the website.

**Accept.** One command runs the demo from a clean checkout, and the output matches the narrative in the papers.

### M11. OIP Explorer (M)

**Build.** A static web app.
- Enter a `did:oip` address, or browse the demo network.
- See the mind's identity log as a timeline, its keys with their validity windows, its DID document, location, profile, feed and checkpoints, and its Layer 2 objects with computed status.
- Every signature is verified in the browser.
- A "why" view traces each verdict to the spec clauses behind it.
- It works with any resolver and indexer URL.

**Accept.**
- Playwright tests pass against the demo network.
- Lighthouse scores are at least 95 for accessibility, performance and best practices.
- No data leaves the browser except requests to the resolvers and indexers the user chose.

### M12. Hardening and release candidate (L)

- **Independent security reviews** by fresh review agents, each in its own area: cryptography and encodings; protocol logic and time; servers and the network surface; the MCP server and prompt injection; supply chain. Every finding is fixed, and every review is saved in `reviews/build/`.
- **Campaigns.** A long fuzzing campaign on every parser; 10⁷ differential cases with no disagreements; mutation testing across the verification packages; memory and leak tests for the servers; a final performance pass against the budgets.
- **Documentation.**
  - Guides: Quickstart, Concepts, Recipes (delegate to an agent, form a collective, make a Commitment, bridge MCP and A2A), Operating the servers, and the Security model.
  - The API reference.
  - The `did:oip` method specification, ready for the W3C DID Extensions registry.
  - The threat models.
- **Specification.** Fold every change found during the build into a new specification revision, with its CHANGELOG entry, regenerated vectors and an updated technical paper. Publishing the paper's new Zenodo version is a click for Eks (G4).
- **API freeze.** API reports are reviewed, and `1.0.0-rc.1` is tagged.
- **External audit.** An optional audit by a security firm (G5). Without one, the internal reviews are published and the community is invited to review the code before 1.0.

**Accept.** Every gate in Section 2 is green, and the release candidate is published under the `next` tag (G1 on first publication).

### M13. Release 1.0 (S)

- Version the packages to `1.0.0` with Changesets.
- Publish to npm with provenance through trusted publishing.
- Sign the container images and attach SBOMs.
- Write the GitHub Release notes.
- Mint a software DOI through Zenodo's GitHub integration (G4), and update `CITATION.cff`.
- Prepare an announcement kit for the website and outreach stages: release notes, a short explainer, the demo recording and diagrams.

**Accept.**
- `npx @oip/cli init` works from the public registry on macOS, Linux and Windows.
- `docker compose up` works from the released images.
- The software DOI resolves.

### M14. Public infrastructure (M, needs G3)

**Build.**
- Deployment configuration for a public resolver, indexer and host: infrastructure as code, monitoring and alerts, backups, an abuse policy, a status page and a cost estimate.
- Stop for Eks's hosting decision (G3), then deploy.

**Accept.**
- The public endpoints pass the conformance suite.
- Monitoring is live.
- Service levels are documented (best effort at first).
- The README's quickstart uses the public endpoints by default.

## 6. Workstreams through every milestone

| Workstream | What it means in every milestone |
|---|---|
| **W1 Conformance** | New code cites its clauses; the vector harness turns more cases green; differential testing covers each new verifier |
| **W2 Security** | Every new parser gets a fuzz target; every new service or tool updates its threat model; each milestone's review includes security |
| **W3 Performance** | Hot paths get benchmarks when they land, measured against Section 3.8 |
| **W4 Docs and DX** | Each package's README and examples are written with the code; examples compile and run in CI; error messages are reviewed like code |
| **W5 Spec feedback** | When the code reveals a gap or a mistake in the specification, fix the spec text, the CHANGELOG, the Python generator and vectors, and the technical paper, in the same change, and never let the code diverge silently. Record formats change only through a spec revision |
| **W6 Release** | Every PR that changes a package adds a changeset; API reports are updated deliberately |

## 7. How the work runs

- **Sessions.** Start by reading [PROGRESS.md](PROGRESS.md). End by updating it, committing and pushing, so that no work is lost to a usage limit.
- **Branches.** Use one branch per milestone (for example `m2-identity`), with small commits. Open a PR to `main` once the milestone's acceptance criteria pass, merge only when CI is green, and use a merge commit. Never rewrite or force-push `main`: every push to `main` is timestamped on the Bitcoin blockchain.
- **The review gate.** At the end of each milestone, start a fresh review agent whose only context is the repository, the specification and the milestone's diff. It checks spec conformance, security and test quality. Fix every finding before merging, and save the review as `reviews/build/M<n>-<name>.md`.
- **Decisions.** Any decision that is hard to reverse gets an ADR in `docs/adr/`.
- **Issues.** Use GitHub issues for spec questions and deferred work, labelled by layer and milestone.
- **Parallel work.** Subagents may run independent workstreams in parallel (documentation, fuzz targets, examples), but milestones land in order.
- **Model and effort.**
  - Use Fable (`/model fable`), the model Claude Code recommends for the hardest and longest-running tasks. If Fable is not available, or Eks chooses not to use it (on some plans it bills to usage credits), use Opus (`/model opus`).
  - Set effort to `xhigh` (`/effort xhigh`) for everyday building. Opus 5.5 defaults to `medium`, which is too low for this code.
  - Switch to `max` (`/effort max`, which applies to the session) for M1 to M3, where the cryptography, the time model and the policy language live, and for the M12 security reviews.
  - Do not use `max` everywhere: it costs far more tokens and can overthink routine work.

## 8. Decisions and actions only Eks takes

Prepare everything up to the decision or the click, then stop and ask: say what is needed, why, and exactly what to click.

| Gate | What | When | Prepared beforehand |
|---|---|---|---|
| **G1** | npm organisation (`@oip` if available, otherwise `@openintelligence`), with trusted publishing configured | before the first publication (M12) | package metadata and the publishing workflow |
| **G2** | A domain name for the website and documentation | before 1.0 | a shortlist with availability; the A2A extension URI stays as L0 3.3 gives it unless a spec revision changes it |
| **G3** | Hosting and accounts for the public infrastructure | M14 | deployment configuration and cost estimate |
| **G4** | Zenodo: link GitHub for software DOIs, and publish new paper versions | M12 and M13 | the release and the drafts, ready to publish |
| **G5** | An external security audit (optional; it has a cost) | M12 | the audit scope |
| **G6** | Public listings: the MCP Registry, a W3C DID Extensions registry PR, a DIF Universal Resolver PR | after 1.0 | the entries and PRs, ready to submit |
| **G7** | A GitHub organisation for the project (optional; moving the repository keeps its history and redirects) | before launch | the move checklist |
| **G8** | Anything that creates an account, spends money, publishes or posts publicly | whenever it arises | everything up to the last click |

## 9. Definition of done

v1.0 is done when all of the following hold:

- [ ] M0 to M13 are complete, and M14 is complete or waiting only on G3.
- [ ] CI is green, with every gate in Section 2 enforced.
- [ ] Every value in the vectors reproduces; every must-accept case and control is accepted; every negative case is rejected.
- [ ] Every MUST clause in the specifications has a test.
- [ ] 10⁷ differential cases have run against the Python checker with no disagreements.
- [ ] The conformance suite passes for every profile against the reference servers.
- [ ] The five-minute promise holds from the public npm registry.
- [ ] The demo runs from a clean checkout with one command.
- [ ] The MCP server works in Claude Desktop and Claude Code, and the A2A bridge works with A2A samples.
- [ ] OIP Explorer verifies any mind in the browser.
- [ ] The security reviews are published and their findings fixed.
- [ ] The packages are published with provenance, the images are signed, and the release has a DOI.
- [ ] The documentation lets a newcomer create a mind, find another and make a Commitment with it, and lets an implementer build a second implementation from the specification and the conformance suite alone.

## 10. After v1

These are not part of v1: merges; recovery keys; witness gossip between resolvers; P-256 and passkeys; DIDComm, libp2p, iroh, NATS and MQTT bindings; DHT and DNS-AID publication; the OAuth bridge; credential export; payment-rail gateways; MLS and ratcheted sessions; threshold signatures; pairwise addresses (technical paper, Section 10).

Also after v1: PostgreSQL storage for large deployments; a Python SDK, building on the Python checker; a second production implementation in Rust, for embedded and high-throughput use; remote (HTTP) MCP with OAuth; and a bug bounty.
