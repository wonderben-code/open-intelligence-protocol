# Progress

This file is the live status of the Open Intelligence Protocol project, so that any session can resume exactly where the last one stopped.

**Last updated:** 21 November 2026 (UTC)

## Where the build stands on this branch (21 November)

This branch is `m9-bridge`. It is stacked on `m8-mcp-server`, `m7-cli`, `m6-client`, `m5-servers`, `m4-network`, `m3-delegation-web` and `m2-identity`, which are each ahead of `main`. The table below this section is the one on `main`, and is rewritten milestone by milestone as each closes; this section says where the work really is.

| Milestone | Branch | Built | `pnpm run ci` | Still owed before its pull request |
|---|---|---|---|---|
| M2. Identity | `m2-identity`, pushed | Yes | Green | The sixteenth review round (fifteen are done and fixed), the mutation score, the review record |
| M3. Delegation and Layer 2 | `m3-delegation-web`, pushed | Yes | Green | Two more reviews, the mutation score, the review record. [OEP-0003](oeps/oep-0003-delegation-and-mind-web-clarifications.md) needs Eks |
| M4. Network records and sealing | `m4-network`, pushed | Yes | Green | Two reviews, the mutation score, the review record |
| M5. Servers | `m5-servers`, pushed | Yes, see below | Green | Reviews, the mutation score, the review record |
| M6. Client and keystore | `m6-client` | Yes, see below | Green | Reviews, the mutation score, the review record |
| M7. The `oip` command | `m7-cli`, pushed | Yes, see below | Green | Reviews, the mutation score, the review record |
| M8. The MCP server | `m8-mcp-server`, pushed | Yes, see below | Green | Reviews, the mutation score, the review record. A look at it in Claude Desktop needs Eks |
| M9. The A2A bridge | `m9-bridge` | The A2A gateway and the DID resolver, see below. A gateway for MCP servers is being built | To run | The A2A TCK and the two new images, which run on GitHub and not here. Reviews, the mutation score, the review record |

Reviews are made by fresh agents, which were not to be had between 19 and 21 November (a usage limit). The build went on with what does not need them.

**What M5 has so far:**

- **`@oip/server`**, what the three services share ([ADR-0013](docs/adr/0013-the-server-package.md)), and **`@oip/resolver`**, **`@oip/host`** and **`@oip/indexer`**: Layer 1, Sections 13, 17 and 18, each a library and a command, with its README, threat model, changeset and API report.
- **The conformance suite over the wire** ([README](packages/conformance/README.md#over-the-wire)): the Resolver, Host and Indexer profiles as checks that need nothing of an implementation but its URL, a report that is JSON, and the command `oip-conformance`. The three reference services pass. Some eighty planted faults fail the checks they should.
- **Container images and a stack for one machine** ([ADR-0014](docs/adr/0014-containers.md), [guide](docs/guides/containers.md)): distroless, not root, read-only. Each is ready within 0.5 to 1.2 s of its start, and the three pass the conformance suite from their containers. A CI job does that on every push.
- **Fuzz targets** for the three HTTP interfaces (`pnpm test:fuzz`, 200,000 requests each night), and **planted faults** under services that run as processes: a kill while publishing and while a client reads the stream, a severed socket, a locked database. Nothing a service answered for is lost, or first seen at another time.
- **Load tests** against the budgets of BUILD.md 3.8, each service a process of its own (`packages/*/bench/load.bench.ts`).
- **`oip-indexer init`**, which makes the indexer's own mind.

**What M5 found:**

- **A resolver verified each published log four to five times over**, and all of it again when the same bundle was published once more. `@oip/core` now remembers a signature that verified: publishing a new log of two events takes 9 ms where it took 19, and the same bundle again 3 ms where it took 22. With that the five budgets of the services are met by the portable Ed25519 ([ADR-0015](docs/adr/0015-server-budgets.md)).
- **OpenSSL does the arithmetic of a signature in the services** ([ADR-0016](docs/adr/0016-native-ed25519.md)), as ADR-0006 planned: a signature is checked in a tenth of a millisecond where the library takes two. The rule stays core 4.4 and stays in `@oip/core`, whose tests of it run unchanged with the library, with an engine written out from RFC 8032 and with OpenSSL. The first two rows of BUILD.md 3.8 are met in the services.
- **The regression checks of `pnpm bench` are measured turn about** ([ADR-0020](docs/adr/0020-ratios-turn-about.md)). On a shared machine whose speed changed by half for seconds at a time, three runs in a row each failed a different ratio with the code unchanged: the two sides of a ratio were measured a second apart. They are now sampled in turns, a few milliseconds apart, and the ratios hold to two parts in a hundred from run to run. Three budgets that compare unlike work have more room.
- **Two gaps in the specification, which the conformance suite showed** ([OEP-0005](oeps/oep-0005-service-clarifications.md), items 4 and 13): what "no two events first seen at one time" asks of a resolver, and what media type a submission and a query have.
- **A signed request was judged at two readings of the clock**, and failed on a clock that moves. Fixed in the host and the resolver.

**What M6 has so far:**

- **`@oip/keystore`** ([ADR-0017](docs/adr/0017-the-keystore.md), [0018](docs/adr/0018-the-keystore-in-a-browser.md), [0019](docs/adr/0019-the-system-keychain.md); [threat model](docs/threat-models/keystore.md)): each role of a mind's keys sealed apart with scrypt and XChaCha20-Poly1305, a control key bound to one event and destroyed once that event is published, an encrypted backup, a directory, IndexedDB and the system keychain as storage.
- **`@oip/client`** ([ADR-0021](docs/adr/0021-the-client.md), [threat model](docs/threat-models/client.md), [README](packages/client/README.md) with six examples that run as tests). A `Mind` can:
  - be made and opened; rotate, add and revoke keys; fork and retire, each identity change in an order that survives a process that stops;
  - publish its location, its profile and a feed, and move to other hosts with its feed (Layer 1, 15.4);
  - resolve any mind with the witness rule of core 9.4 applied, read a feed, check aliases (5.3), and find minds through indexers with every record they name verified (18.4);
  - send packets, sealed unless told otherwise, and read its mailbox; send to whoever a query finds, through a broker; send for another mind under a delegation;
  - delegate, pass a delegation on and revoke one; make Intents, Offers, Commitments and Receipts, for itself or for the mind it acts for; co-sign; and say whether a record counts for a mind and what its status is.
  - found a collective with other minds, change it, and sign for it: by the threshold of its members, or alone by a role of its charter;
  - keep a packet that did not arrive, and try it again ([ADR-0025](docs/adr/0025-the-clients-outbox.md));
  - listen at its host over a socket ([ADR-0024](docs/adr/0024-the-clients-socket.md)): what arrives is judged as a mailbox is, acknowledged over the socket, and a connection that ends is opened again;
  - talk in a session ([ADR-0023](docs/adr/0023-sessions-in-the-client.md)): each packet has its place in the mind's chain before it leaves, what arrives is returned in order, a gap is asked about with a `Resume`, and a participant's `Resume` is answered with what it lacks.
- **The scenario of the papers runs through the client** against the real resolver, host and indexer in one process (`packages/client/test/dealings.test.ts`, `examples/deal.ts`).
- **It runs in a browser too** ([ADR-0022](docs/adr/0022-the-client-in-a-browser.md)): a page of Chromium runs the README's examples against the same services, with its keys sealed in IndexedDB, and the test checks that each service would have let a browser make every request the page made (`packages/client/test/browser.real.test.ts`, the `browser` job of CI).

**Everything on M6's build list is built**, and every public method of `Mind` and of `Lookup` is called in a runnable example the README shows, which a test holds. The API report was read through and is frozen for 0.x: the reading found that closing a mind left its sockets open, which it no longer does. What remains before the milestone closes: the independent reviews and the mutation run.

**What M9 has so far:**

- **`@oip/bridge-a2a`**, the program `oip-bridge-a2a` ([README](packages/bridge-a2a/README.md), [ADR-0029](docs/adr/0029-the-a2a-gateway.md), [threat model](docs/threat-models/bridge-a2a.md)): a gateway between the network and A2A 1.0, in both directions.
  - **An A2A agent becomes a mind.** `bridge` reads the agent's card as a stranger's data, verifies its signatures, and makes a bridged mind that the gateway attests in its own feed (Layer 0, 1.2, 3.1). `serve` relays: a packet with verb `request` is a message to the agent, and a task that ends is a Receipt by the bridged mind that says what the gateway observed (1.4), with the artifacts as evidence.
  - **A mind becomes an A2A agent.** A mind that lists the card in its profile is served an Agent Card and the JSON-RPC binding of A2A (3.2). An A2A client sends messages and follows tasks, and the mind answers with packets. The gateway keeps the tasks.
  - **The OIP extension for A2A** (3.3), both ways: an agent that declares it is sent the whole signed packet, and a client that sends one has it verified under Layer 1, 12.4 and brought to the mind as it is.
- **Assurance levels** (1.3) in `@oip/web`, with vectors and a differential campaign: `Lookup.assurance` says `native`, `bridged` or `claimed`, and a mind that only says it is bridged is `claimed`.
- **`@oip/did-resolver`**, the program `oip-did-resolver` ([README](packages/did-resolver/README.md), [ADR-0030](docs/adr/0030-the-did-resolver-drivers.md), [threat model](docs/threat-models/did-resolver.md)): `did:oip` for the DIF `did-resolver` library, with no dependency on it, and the HTTP interface of a driver for the DIF Universal Resolver. Its tests run the driver through the DIF library itself.
- **What the gateway puts on the wire is held against the A2A project's own JSON Schema** in the tests: every result of every method, and every card. The schema is kept beside the tests, unchanged.
- **The A2A TCK has a job in CI** (`pnpm a2a:tck`): a real resolver, host and indexer on the runner, a gateway, and an ordinary OIP mind that plays the TCK's scenarios by answering packets. The TCK is cloned at a pinned commit, and `uv` is pinned by hash.
- **Container images** for the DID resolver and the gateway, built and started by the `containers` job.

**What M9 found:**

- **A profile that carried the gateway's entry in place of its reference was taken as attested by one implementation and not by the other.** The differential tests found it. Layer 0, 1.3 now says that the profile names the entry by its reference, and that a `Genesis` that names a gateway is a declaration ([OEP-0006](oeps/oep-0006-bridge-clarifications.md), items 2 and 3).
- **A record asked for again after a failed call was listed twice on a feed.** `publishRecord` now returns the entry that waited. A gateway that signs a Receipt and is stopped before the feed took it relies on that to publish the Receipt once.
- **An agent could put words into the gateway's mouth.** A task's name and an agent's answer are text the agent chooses, and both go into a Receipt's statement. They are quoted as strings of JSON, which no text can end early.
- **A reply could go on with someone else's task.** A question an agent puts to a requester is a packet, and any mind that learned its ID could answer it. Only the mind a task is for goes on with it.
- **A pass of the relay that stopped could ask an agent twice, or sign two Receipts.** A packet is now written down before anything is done with it and is not sent again once the agent has answered, and a Receipt is written down as soon as it is signed.
- **A packet has no place for bytes.** Layer 1, 12.2 gives content a body of JSON or a reference with a digest. A file an A2A agent returns inline is attested by its digest in the Receipt and left out of the packet, and the requester is told. A convention for bytes is a matter for an OEP.
- **`ListTasks` assumes a caller the server knows.** The gateway knows none. It shows a client the tasks of a context the client names, and nothing else.
- **A proof is first seen before its signer's log is asked for.** The first version of the packet check resolved the sender and then judged the packet, and every packet failed: the log has to stand no earlier than the first sight (core 9.4). The client does it in that order, and the gateway now does too.

**For Eks, from M9:** (1) The A2A TCK and the two new container images cannot be run in the place this is built: the TCK is another project's code, and there is no Docker. Both run on GitHub once this branch is pushed. `pnpm a2a:tck` runs the TCK on your machine, if you want to see it (it needs `uv`). (2) Submitting the DID resolver to the DIF Universal Resolver, and `did:oip` to the W3C DID Extensions registry, are gate G6. The image and its settings are ready. (3) [OEP-0006](oeps/oep-0006-bridge-clarifications.md) has three items now, and waits for your word as the other OEPs do.

**What M8 has:**

- **`@oip/mcp-server`**, the program `oip-mcp` ([README](packages/mcp-server/README.md), [ADR-0028](docs/adr/0028-the-mcp-server.md), [threat model](docs/threat-models/mcp-server.md)): the nine tools of Layer 0, 2.2, each described for a model, over standard input and output. It speaks the MCP revisions up to 2025-11-25 and that of 2026-07-28, which changed the protocol's shape, through the official library.
- **The three rules of Layer 0, 2.2 hold against a model that obeys whatever it reads.** The keys stay in the server, and no tool reads a file. What other minds wrote reaches the model under `untrusted`. A Commitment is signed only once the person has confirmed the terms the server shows them, or their `policy.json` permits them. An answer counts for the question it was given to, once.
- **The prompt-injection suite** (`packages/mcp-server/test/injection.test.ts`): a mind that writes calls for the model in packets, a profile, an Offer and the promise of a Commitment, against a model that makes every call it reads, in both shapes of MCP. Nothing is signed without the person, the person is shown the true terms, no result holds a key or a passphrase, and every word of the other mind's is under `untrusted`.
- **A host that does not behave is tried too** (`mcp.test.ts`): an answer nobody asked for, a yes given to other terms, a state that was altered or that another server made, the same yes twice, a yes after a no.
- **`@oip/local`** ([ADR-0027](docs/adr/0027-a-mind-on-one-machine.md)): the mind's directory, the lock of its keys and what is kept between runs, taken out of the command so that the server uses the same directory.
- **It runs under the MCP Inspector in CI** (`pnpm mcp:inspector`): the Inspector lists the tools with its strict check of their schemas, calls three of them, and gets no signature for a Commitment it cannot ask about.
- **Claude Code connects to it** as the README says (`claude mcp add oip -- node …/dist/bin.js`, then `claude mcp list`: connected), tried here with Claude Code 2.1.
- **It is ready for the MCP Registry**: `server.json`, valid against the Registry's schema, and the package's `mcpName`. Listing it is gate G6, after the package is on npm.

**What M8 found:**

- **A Receipt needs the person as a Commitment does.** Layer 0, 2.2 asks for confirmation before a Commitment or a Delegation. A model that a packet talked into it could otherwise publish, in the person's name, that a Commitment owed to them was fulfilled. The server asks before a Receipt too, and `policy.json` has a part for Receipts. [OEP-0006](oeps/oep-0006-bridge-clarifications.md) proposes it for the specification, and Layer 0, 2.2 now names a Receipt: it waits for Eks's word, as the other OEPs do.
- **The command's way of naming a record by a file is not for a model.** A tool that takes a path can be talked into sending the file. The tools take a content ID alone.
- **Who pays, by default, is the first creditor.** A test of the suite assumed the debtor. The question the person is shown names the payer and the payee in so many words, which is what caught it.
- **A policy could not be checked before it was used.** `@oip/delegation` gained `checkPolicy`, so that a policy that is none is refused when the server starts, and `oip delegate --policy` uses it too.
- **Not in the server:** acting for another mind through a delegation or a charter (the tools sign as the mind itself); confirmation of packets, Intents and Offers, which bind nobody and are the host's to approve; an output schema for each tool. Each is said in the README and the threat model.

**What M7 has:**

- **`@oip/cli`**, the `oip` command ([README](packages/cli/README.md), [ADR-0026](docs/adr/0026-the-command.md), [threat model](docs/threat-models/cli.md)): every command of the build list, each with `--json`, `--help` and an example. `init`, `show`, `rotate`, `add-key`, `revoke-key`, `fork`; `publish profile`, `publish location`, `publish record`; `resolve`, `find`; `send`, `inbox`; `intent`, `offer`, `commit`, `receipt`, `status`; `delegate`, `revoke`; `collective create`, `collective sign`; `verify`; `keys backup`, `keys restore`; `doctor`; `demo`; `completions`.
- **`oip verify` says why of every verdict**, with the clause it rests on, for a record, a log, a bundle or a mind by its address.
- **`oip demo` runs a resolver, a host and an indexer on the user's machine**, so that a mind can be tried before anyone has chosen or deployed a service.
- **The five-minute promise is measured**: `pnpm newcomer` (`scripts/newcomer.ts`) installs and builds the repository, and runs the lines of the command's README as they stand, in a home directory that holds nothing. Two minds and an accepted, verified Commitment between them take about thirty seconds once the repository is built. CI runs it on every push and fails it at five minutes.
- **No private key is printed, and no passphrase is an option.** Everything printed has its control characters shown as escapes, so that a stranger's text cannot act on the terminal.
- **Tests**: the help and the output of every command are held by snapshots; the papers' scenario runs end to end through the command, each step a run of its own; the command is also run as a real process; the bash completions are run in bash. Every file of the package meets the coverage threshold.

**What M7 found:**

- **The client forgot when it had first seen a record once its process ended.** That is the finding listed under M6 below: the command was the first program to keep records between runs, and to need the evidence kept with them.
- **An Offer or an Intent published through the client was never brought to an indexer**, so nothing could find one. `publishRecord` now submits the mind's own, as Layer 1, 18.1 has an indexer take them.
- **The client could acknowledge a child mind and could not make one** that names its parent. `oip fork` now does both, in that order.
- **GitHub's CI needed more time than it was given.** Once the tests of the stack were mended, the job that runs every check was cut off at thirty minutes, and a test or a hook ran out of its own time on a shared runner. The timeouts are now there to end what hangs, and the budgets stay with the benchmarks.
- **Not in the command yet:** sessions, retiring a mind, and drafting a change to a collective. The client does all three. A packet read from a mailbox and not yet written to the directory is lost if the process dies between the two: closing that needs the client to confirm a packet only once the application has kept it. Both are noted in the README and the threat model.

**What M6 found:**

- **A mind could not publish its own retirement to a resolver that asks for signed requests**, nor the event that removes the key it signs with. The archive judged a mind's own request by the log in its bundle alone, where Layer 1, 17.3 also takes a key that is valid by the logs the resolver holds. Fixed in `@oip/server`, and 17.3 now says it in so many words ([OEP-0005](oeps/oep-0005-service-clarifications.md), item 5).
- **A page could not list a mind at the indexer.** The indexer's answer to a browser's preflight did not allow the headers of a signed request, which submitting needs. Found by the run in a browser, and fixed in `@oip/indexer`.
- **GitHub's CI had failed on every branch since M2, and never on the machine the code is written on.** Two tests place a call a chosen number of frames above the end of the call stack. They measured the stack with code the engine then compiled again at another frame size, and whether that happened depended on the machine. The testkit now asks the engine to leave that code as it is (`keepFramesOneSize`), and the tests give the same answers on Node.js 24, 26 and 27. A third test compared HTTP headers by prototype, which Node.js 27 changed. The fixes are on the `m2-identity` and `m5-servers` branches and merged upwards. The keychain job passed on macOS and Windows on its first run there.
- **A packet could be lost where the client's memory could not be written.** A reading that judged a packet and then failed to write left it remembered in the process, and the next reading removed it as a duplicate, unreturned. Found by the tests of the socket, and fixed in the client.
- **A program that kept its records between runs lost the evidence of when they came.** The client's own record of when it first obtained a proof is evidence under core 9.4, and for most proofs the only evidence. It was held in the process alone, so a Commitment signed under a delegation that later expired, or was revoked, stopped counting when the program started again. Found while the `oip` command was given a directory to keep records in. `Mind.sightings` now gives that record, and `Mind.hold` takes it back. A mind may also now be made as a fork of another (`NewMind.parents`), which the client could acknowledge but not make.
- **A rate limiter kept a client out for as long as the clock had been set back.** It now keeps it out for no longer than its own tolerance.
- **How a mind brings a host its records is not in Layer 1.** The client speaks the reference host's own interface. A second host would have to offer the same, which is a matter for an OEP when one exists.
- **A host learns that a mind it serves has retired only if the mind brings it the event.** A host that follows the resolvers for the minds it serves would close this. It is noted in the client's threat model, and is for a later milestone.

**For Eks, from M8:** (1) Try the server in Claude Desktop, with the snippet in its [README](packages/mcp-server/README.md): Claude Code and the MCP Inspector were tried here, and Claude Desktop cannot be. (2) The server's name in the MCP Registry is prepared as `io.github.wonderben-code/oip`, which needs only the GitHub account. A name under a domain of the project's (gate G3) would be `<the domain, reversed>/oip`: say which you want before G6. (3) [OEP-0006](oeps/oep-0006-bridge-clarifications.md): Layer 0, 2.2 asks for confirmation before a Receipt as well, as the server now does. It changes normative text and waits for your word.

**For Eks, besides what is listed further down:** OEP-0002, OEP-0003, OEP-0004 and OEP-0005 each change normative text and wait for your word, as OEP-0001 does (E13). OEP-0005 has one more sentence since M6, on 17.3. The keychain storage of the keystore is tested on Linux here; its tests on macOS and Windows run for the first time when this branch reaches GitHub.

## Where the v1 build stands on `main`

| Milestone | Status |
|---|---|
| **M0. Foundations** | **Done**, pending merge of [its pull request](https://github.com/wonderben-code/open-intelligence-protocol/pull/1), which waits on one repository setting (E11 below). Two independent reviews; every finding fixed, queued or handed to Eks ([reviews/build/M0-foundations.md](reviews/build/M0-foundations.md)) |
| **M1. Core** | **Done**, pending merge of [its pull request](https://github.com/wonderben-code/open-intelligence-protocol/pull/2). Four independent reviews; every finding fixed, queued or handed to Eks ([reviews/build/M1-core.md](reviews/build/M1-core.md)). The pull request carries [OEP-0001](oeps/oep-0001-core-clarifications.md), which is Eks's to accept (E13 below) |
| **M2. Identity** | **Next.** Start here |
| M3 to M14 | Not started |

The plan is [BUILD.md](BUILD.md). [docs/conformance/coverage.md](docs/conformance/coverage.md) shows, clause by clause and vector case by vector case, what the code enforces today.

### What M0 delivered

- **The workspace.** pnpm, strict TypeScript, ESLint, Prettier, Vitest with coverage thresholds for each file, fast-check, API Extractor, TypeDoc, Changesets and REUSE. `pnpm run ci` is the script the CI job runs.
- **Guards.** Pure packages cannot do I/O or read the clock: they have no ambient types, ESLint forbids every route to the clock, randomness and the environment, dependency-cruiser enforces the layers of BUILD.md 3.1, and a run-time trap catches the rest. `scripts/check-guards.ts` proves on every run that the guards still reject violations.
- **`@oip/schema`.** A JSON Schema, a TypeScript type and a compiled validator for all 29 record types of core 11, plus `Proof`, `Policy` and extension records. The schemas are exported to [spec/schemas/](spec/schemas/). Every positive vector record validates; both malformed `record` cases are rejected. Validation never throws and its answer is bounded, whatever it is given.
- **`@oip/conformance`.** A typed loader for the vectors, a runner for each kind of case, and the positive checks. Cases the implementation cannot answer yet are pending (87 of them), and turn green milestone by milestone.
- **Differential testing.** `oip_vectors.py --judge` gives the Python checker's verdict on any case; `PythonJudge` keeps it open as one process. A nightly job runs a long campaign.
- **Clause traceability.** [spec/clauses.json](spec/clauses.json) lists all 184 numbered clauses. Tests cite them with `clause("L1 6.4")`. `pnpm spec:coverage` fails if a clause owed by a completed milestone has no passing test from a package of that milestone. It gates 176 of the 184; the other 8 state no requirement.
- **CI.** Lint, types, generated files, API reports, spec coverage, tests on Node 24 and the newest Node, the Python checker, REUSE, CodeQL, dependency review, OpenSSF Scorecard. Actions are pinned by SHA.
- **Governance.** CONTRIBUTING (with the DCO), the Contributor Covenant, SECURITY, GOVERNANCE with the OEP process, an OEP template, issue forms and a PR template.
- **Decisions.** [ADR-0001](docs/adr/0001-tooling.md) tooling, [ADR-0002](docs/adr/0002-cryptography-libraries.md) cryptography libraries, [ADR-0003](docs/adr/0003-evidence-model.md) the evidence model, [ADR-0004](docs/adr/0004-error-model.md) the error model.
- **Review.** [reviews/build/M0-foundations.md](reviews/build/M0-foundations.md).

### What M1 delivered

- **`@oip/core`**, the rules of OIP Core, Sections 1 to 8 and 10 ([README](packages/core/README.md)):
  - a strict parser for the JSON profile: no duplicate member names, valid Unicode with no noncharacters, safe integers judged by value, nesting of at most 64. `JSON.parse` is not used for records;
  - canonical form (RFC 8785), content IDs in their one spelling, key hashes;
  - Multikey; Ed25519 under the one rule of core 4.4, with the library in its strict mode and the order of `A` and `R` checked on top;
  - `eddsa-jcs-2022` proofs: create, verify one, verify a set, each proof on its own;
  - references, timestamps as nanosecond instants (no `Date`), durations, exact decimal comparison, critical extensions, the limits on size and depth, and the problem types with `OipError`.
- **Every acceptance criterion of BUILD.md M1**, each with a test:
  - every JCS output, content ID, address, key hash and `proofValue` in the vectors reproduces, and all 56 proofs verify;
  - non-canonical content-ID spellings are rejected;
  - the Ed25519 negative cases are rejected and honest signatures beside them accepted;
  - changing any byte of any vector record makes verification fail;
  - the parser is run on 10⁶ generated inputs in every test run, against an oracle that shares nothing with it;
  - the first two budgets are measured ([ADR-0006](docs/adr/0006-performance-budgets.md), and E12 below);
  - the mutation score of `@oip/core` is 98.5% (threshold 85%); the files of `@oip/schema` that M1 changed score 95.5%.
- **Conformance.** The suite gained the M1 checks and a new kind of case, `json`. The differential tests compare the two parsers on generated texts under the rule "same". The vectors now hold 17 must-accept cases, 80 negative cases and 30 controls, all generated by the Python checker.
- **Stryker**: `pnpm mutation`, and a weekly workflow.
- **Decisions.** [ADR-0005](docs/adr/0005-cryptography-libraries-as-adopted.md) the libraries as adopted, [ADR-0006](docs/adr/0006-performance-budgets.md) budgets as measured, [ADR-0007](docs/adr/0007-programming-errors.md) a wrong argument is a `TypeError`.
- **Specification.** [OEP-0001](oeps/oep-0001-core-clarifications.md) settles Q1 to Q8 and five more points, as one change: text, CHANGELOG, generator and vectors, paper.
- **Review.** [reviews/build/M1-core.md](reviews/build/M1-core.md). Four reviews: two of the milestone (27 findings, one of them High: a rule M1 had itself added to the specification would have let anyone stop a log from being served), one of the fixes, and one of a single mechanism the fixes added. All findings are closed or queued. 1,060 tests pass.

### What M1 found that later milestones need to know

- **Verification costs about 2 ms a signature** in the portable implementation, almost all of it Ed25519 in JavaScript: 4 ms for a record with two proofs, 2 s for the signatures of a 1,000-event log. The starting budgets of BUILD.md 3.8 (2 ms and 1 s) stay as targets for the servers. M5 meets them with a native Ed25519 that applies core 4.4 exactly; ADR-0006 gives the argument.
- **The Ed25519 library accepts three things core 4.4 forbids**, even in its strict mode: a mixed-order key, `R` the identity, and a mixed-order `R`. The wrapper rejects them. Only `@oip/core` may call the library.
- **Signing reaches the random number generator** (the library masks the secret scalar) and stays deterministic. Tests of pure code that sign must allow randomness: `withAmbientTrapped(run, { randomness: true })`.
- **A judge returns a result; a function that computes throws.** `parseRecord`, `verifyProofs` and every `parse…`, `decode…` and `is…` never throw. `contentId`, `canonicalize`, `createProof` and `withProofs` throw `OipError` on a value outside the JSON profile, and a wrong argument is a `TypeError`.
- **`verifyProofs` returns three lists**, `verified`, `rejected` and `issues`, and no `ok`. Count distinct keys among `verified`, never entries.
- **Validators return a plain copy. Use the copy**, never the value that was passed in: it was read once, through property descriptors, and nothing else about it is known.
- **A container is limited part by part, and never as a whole** (core 1.6, 1.9): each record it carries, and the container without the members that hold them. `containerParts` in `@oip/schema` takes one apart. The one limit on a whole input is the reader's own, the length of the text (`maxLength`, 8 MiB by default). Anything that reads a page of a log or a feed must follow the same rule, or one junk entry in an event's `proof` stops the page. A server endpoint that accepts one record should pass a `maxLength` near the size limit, and a client refused a page should ask for a shorter one.
- **`validateParsedRecord` is for a parser, and for nothing else.** It lets `parseRecord` validate what it has just parsed without copying it again. Every other value goes through `validateRecord`, which always copies.
- **Do not keep the object read from the wire in a store.** Its strings can hold the whole source text in memory. Store the canonical form (M5).
- **A size is counted, never written out** (`canonicalSizeUpTo` in `@oip/core`), and memory is measured in tests after a collection (`heapKeptBy` in `@oip/testkit`).
- **A server that stores proofs should merge only proofs that verify.** A junk entry in `proof` never counts, but it travels with the record and takes one of its 256 places.
- **`createProof` refuses a malformed record** before the signer is asked. `createProofSync` makes a proof without a promise, for a signer that holds its key in memory; test generators should use it.
- **`parseExtensionRecord`** reads a record of a type an extension defines. `parseRecord` refuses those and says so.
- **Mutation testing counts every package's tests.** It works on a copy of the repository, and a package used to reach its neighbours through `node_modules`, which leads back to the original: a mutant in `@oip/schema` never met the tests of `@oip/core`, and was counted as surviving them. Each package's tests now resolve the workspace packages by path (`scripts/lib/source-aliases.ts`). A new package's `vitest.config.ts` must use `sourceAliases` too.
- **A full mutation run of one package takes one to two hours** on four cores, because a mutant in code that every record passes through is covered by nearly every test. Run it by file or by line range (`--mutate "packages/schema/src/validate.ts:1-300"`), and keep each run under the two-hour limit of a background command. The comparison campaigns are cut down for these runs in `stryker.config.mjs`.
- **A refusal is tested for what it says**, not only for being a refusal: `packages/schema/test/issues.test.ts` reads the path, the message and the clause. Mutation testing showed that the schema tests had asserted verdicts alone.
- **CI runs on every push to any branch**, so run `pnpm run ci` before each push, not only the last one.

### Starting M2

- Read BUILD.md "M2. Identity", [ADR-0003](docs/adr/0003-evidence-model.md), core Section 9 and Layer 1, Sections 3 to 9.
- **Settle Q9 first.** The differential test for logs cannot start until it has one answer. The Python checker's `verify_log` now applies core 1 and core 5.1 to each event, which is part of the answer.
- Build on `@oip/core`: `verifyProofs` for signatures, `parseVerificationMethod` for the two kinds of reference, `keyHash` for pre-rotation, `contentId` and `mindAddress` for addresses, `parseTimestamp` and `CLOCK_SKEW` for time.
- core 6.2 is owed by M2 in `plan.json`: which kind of reference a proof must use depends on whose key it is.
- The positive checks and the `log` cases of the vectors that turn green in M2 are listed in `packages/conformance/src/runner.ts` and [docs/conformance/coverage.md](docs/conformance/coverage.md).
- Measure the second budget properly: replaying a 1,000-event log, not only its signatures.
- Run Stryker on the packages a milestone changes before its review, not after, by file: `pnpm mutation --mutate "packages/identity/src/log.ts"`.
- Run the rest of `@oip/schema` through mutation testing with every package's tests counted. Only the four files M1 changed have been; the others are M0's, and their earlier scores counted the package's own tests alone.
- When M2 is done, add `"M2"` to `completed` in [docs/conformance/plan.json](docs/conformance/plan.json).

## Specification feedback queue

Gaps and ambiguities that the build has found. Q1 to Q8 were settled in M1 by [OEP-0001](oeps/oep-0001-core-clarifications.md). Each is fixed in the milestone named, as one change: specification text, CHANGELOG, generator and vectors, and the technical paper, with a short OEP ([GOVERNANCE.md](GOVERNANCE.md)).

| # | Needed by | Question | Until it is settled |
|---|---|---|---|
| Q9 | **M2** | **Must each identity event be a well-formed record for its log to verify?** L1 4 does not say so. The Python checker verifies a signed genesis with 9 homes, 17 aliases or a malformed `expires`; the schemas reject it. An address is the hash of its genesis, so this must have one answer. Also: the syntax of an "HTTPS origin". | The schemas reject such events. The differential test for logs must not start before this is settled. |
| Q10 | M2 | Are controllers and key entries closed objects (L1 3.4, 3.5)? Both implementations reject unknown members there; core 1.7 says readers ignore them. | Closed. |
| Q11 | M2 | Do `keys`, `invocation`, `agreement`, `homes`, `alsoKnownAs` and `revoked` apply on `Fork` and `Retire`? L1 3.8 and 3.10 do not list them; L1 4.5 applies them to every event. | Validated on every later event. |
| Q12 | M2 | Is `recovery` reserved only at the top level of an event, or anywhere in it? | Top level. |
| Q13 | M2 | May a container or a `Sealed` record carry `created`? Is `Sealed` a container (core 11 against core 1.6)? | Allowed and not required. |
| Q14 | M3 | Does a proof whose `authority` is malformed still count for its signer (core 5.2, 5.4; L2 7.1)? | Yes, as in the Python checker: `authority` is checked for shape only. |
| Q15 | M3 | "Statements nest at most 8 deep": both implementations allow nine levels, counting the outermost as depth 0. A vector at the boundary is needed. | Nine levels. |
| Q16 | M3 | "Beginning `/oip`": both implementations read it by path segment, so `/oipx/pay` is not reserved. | By segment. |
| Q17 | M3 | Six policy vectors (`policy-negative-amount`, five `policy-not-decimal-*`) are rejected as malformed records and never reach a policy, so the rule that a comparison on a non-decimal is an error (L1 11.3) has no vector. Add one on a member that is not an amount. | The rule is tested only by unit tests. |
| Q18 | M3, M4 | In the `{ … }` notation, is a member with no "optional" mark required? It matters for an endpoint's `priority`, `Resume.lastSent`, a result's `hints`, a power's `policy`, a role's `purpose` and `powers`, and a budget's `currency`. | Accepted with or without them; this implementation always writes them. |
| Q19 | M3, M4 | May an "integer" be zero or negative, for `Location.seq`, `quantity`, `maxHops` and a query's `limit`? | Any integer. |
| Q20 | M4 | A `Hello` "carries a single proof": a limit, or a description? | Not limited by the schema. |
| Q21 | M4 | `to: { "subject": … }` is reserved: is such a packet rejected or ignored? May `to` combine forms? | Well formed; no receiver accepts it. |
| Q22 | M4 | The types of `confidentiality`, `jurisdiction`, `context.summary` and the members of `generatedBy` are not given. | Any JSON value. |
| Q23 | M4 | How an anchor's attestation is carried and verified is not specified (L1 10.6; core 9.4, item 3), though it is one of the four kinds of evidence. | Not implemented. |
| Q24 | M2 | The vectors give each negative case's reason as prose. BUILD.md asks that each be "rejected, for its stated reason". Give each case the clause it breaks, so that a verdict's reason can be checked. | Only the 11 controls show that a case fails for its reason. |
| Q25 | M4 | How much may a `Sealed` record exceed the size limit? core 1.6 says "by its encoding overhead" and gives no number. | `ciphertext` of at most 1,398,123 characters (a packet of 1 MiB with the cipher's tag, in base64url), and 1 MiB for the rest of the record. |
| Q26 | M4 | A low-order X25519 key encodes as a valid Multikey (core 4.2). Sealing to one gives a shared secret of zeros, which RFC 9180 says to reject. The specification should say so. | Nothing seals yet. |
| Q27 | M5 | Should receivers be required to reject duplicate member names? core 1.1 says SHOULD. A MUST would let the vectors include the case. | Both implementations reject them. |
| Q28 | M5 | Is there a limit on the text of a record, as distinct from its canonical form? White space and escapes are unbounded. | 8 MiB of text by default, reported as an implementation limit, and set by the reader. |
| Q29 | M5 | How should the vectors carry cases too large to write out, such as a record of exactly 1 MiB? Each would add a megabyte to the file. | The two implementations are compared at the size limit in the differential tests; no vector is at it. |

## Done earlier (on `main`, Bitcoin-timestamped)

### Papers, published on Zenodo with permanent DOIs

| Paper | DOI | PDF | Source |
|---|---|---|---|
| Founding paper, Version 1.1 | [10.5281/zenodo.24301206](https://doi.org/10.5281/zenodo.24301206) | [PDF](papers/pdf/01-founding-paper.pdf) | [Markdown](papers/01-founding-paper.md) |
| Technical architecture, Draft 2 | [10.5281/zenodo.24301209](https://doi.org/10.5281/zenodo.24301209) | [PDF](papers/pdf/02-technical-architecture.pdf) | [Markdown](papers/02-technical-architecture.md) |

- The PDFs in the repository are the exact files deposited on Zenodo, typeset by [papers/build/](papers/build/).
- The two records link to each other and to this repository.
- The concept DOIs, which always resolve to the latest version, are [10.5281/zenodo.24301205](https://doi.org/10.5281/zenodo.24301205) (founding paper) and [10.5281/zenodo.24301208](https://doi.org/10.5281/zenodo.24301208) (technical architecture).

### Specifications and checks

- **Normative specifications**, revision 2026-11-17 (Draft), in [spec/](spec/): core, Layer 1 Mind Network, Layer 2 Mind Web and Layer 0 Bridge. Every change since the first revision is in [spec/CHANGELOG.md](spec/CHANGELOG.md).
- **Test vectors** in [spec/test-vectors/](spec/test-vectors/), with a Python implementation that generates and checks them:
  - positive cases;
  - 5 must-accept cases;
  - 55 negative cases, each with its reason;
  - 11 controls that show each negative fails only for that reason.

  All pass.
- **Three independent reviews**, and the fixes they led to, in [reviews/](reviews/). Every finding is addressed in revision 2026-11-17.

### Supporting work

- **Research**: four tracks, about 27,000 words with sources, in [research/](research/).
- **Philosophy, licences and README.** Code is Apache-2.0; papers and specifications are CC BY 4.0.
- **[BUILD.md](BUILD.md)** is the full plan, and **[CLAUDE.md](CLAUDE.md)** is the operating manual that every Claude Code session in this repository loads automatically.

## Next steps, in order

1. **Build v1 in Claude Code**, from [BUILD.md](BUILD.md), continuing with M2. To continue, see "How to resume" below.
2. **Gates as they come up:**
   - npm organisation (G1);
   - domain (G2);
   - hosting for the public infrastructure (G3);
   - Zenodo GitHub link (G4);
   - external audit (G5, optional);
   - public listings (G6);
   - GitHub organisation (G7, optional).

   Each is prepared to the last click before Eks is asked.
3. **Website.**
   - Before writing it, research world-class copywriting and information design: the guides and methods of the best copywriters, editors and information designers on presenting ideas so they land.
   - Apply what that research finds to the site, to how the papers, the code and the philosophy are presented, and to the docs.
   - The site should be maximally clear, with the papers, the build, the GitHub repository and the philosophy.
4. **Outreach**, once the website is live.

## Open decisions for Eks

**M1 is ready to merge after M0** ([its pull request](https://github.com/wonderben-code/open-intelligence-protocol/pull/2)); it needs your word on E12 and E13.

**Two clicks block the merge of M0** ([pull request 1](https://github.com/wonderben-code/open-intelligence-protocol/pull/1)): E11 and, on the same settings page, E1. Everything else on that pull request is green.

**Small things only you can do or decide.** Each is ready to the last click.

| # | What | Why | Exactly what to do |
|---|---|---|---|
| E1 | Switch on private vulnerability reporting | [SECURITY.md](SECURITY.md) names it as the only way to report a vulnerability, and it is off | Repository **Settings → Code security → Private vulnerability reporting → Enable** |
| E2 | A private contact for conduct reports | The Code of Conduct needs one; GitHub has no private messages | Give an email address; it replaces the `TODO(Eks)` comment in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| E3 | The DCO and the build's own commits | [CONTRIBUTING.md](CONTRIBUTING.md) asks for `Signed-off-by` on every commit. A sign-off is a personal certification, so the build's commits, made for you by an agent, carry none | Choose: apply the DCO to contributors other than you (my recommendation; one sentence in CONTRIBUTING), or sign off the build's commits yourself |
| E4 | Confirm what was written in your name | [GOVERNANCE.md](GOVERNANCE.md) says the maintainer makes final decisions and there is no committee yet. [SECURITY.md](SECURITY.md) promises an acknowledgement in 3 working days, a plan in 30 days and disclosure at 90 | Read the two files; say "fine" or what to change |
| E5 | A short OEP for every specification fix | GOVERNANCE.md, following Section 12 of the technical paper, asks for an OEP for any change to normative text. The build's own fixes (Q1 to Q24) would each carry a short one. [CLAUDE.md](CLAUDE.md) does not mention this | Say whether the build may write and accept those OEPs for you, or whether build-time fixes are exempt |
| E6 | Licences of two kinds of file | Documentation outside `papers/` and `spec/` is marked CC BY 4.0, which [LICENSE-DOCS.md](LICENSE-DOCS.md) does not yet say. The JSON Schemas in `spec/schemas/` are offered under Apache-2.0 or CC BY 4.0, at the user's choice, because they are generated from Apache code and live in `spec/` | Say "fine", or which you prefer. [REUSE.toml](REUSE.toml) is where it is recorded |
| E7 | Four areas with no milestone in BUILD.md | The plan lists them in v1 but no milestone builds them | Confirm my recommendation: a gateway that bridges an MCP server (L0 2.1) in M9; verifying aliases (L1 5.3, L0 4) in M6; checkpoint anchors (L1 10.6) in M4, after Q23; `@oip/did-resolver` in M9 |
| E8 | Labels and issues | BUILD.md asks for issues labelled by layer and milestone. The labels `spec` and `oep`, which the issue forms use, do not exist yet. Issues I open would appear under your name | Say whether I should file Q1 to Q24 as issues. Create the labels `spec`, `oep`, `core`, `layer-0`, `layer-1`, `layer-2` and `M1` to `M14` (Issues → Labels), or say that I may |
| E9 | The two Bitcoin timestamp workflows | They use `actions/checkout@v4` and an unpinned `pip install`. BUILD.md says to leave them as they are, and OpenSSF Scorecard will mark them down | Say whether I may pin them by commit SHA, changing nothing else |
| E10 | Branch protection for `main` | Nothing yet stops a merge with CI red | **Settings → Branches → Add rule** for `main`: require the checks "Every check (pnpm run ci)", "Test (Node 24)" and "Test (Node latest)". Do not require linear history: `main` takes merge commits |
| **E11** | **Switch on the dependency graph** | The dependency-review check fails on every pull request until it is on: "Dependency review is not supported on this repository". It is the only red check on the M0 pull request | Repository **Settings → Code security → Dependency graph → Enable**. Then re-run the "Dependency review" check on the pull request, or tell me and I will |
| **E12** | **The first two performance budgets** | BUILD.md 3.8 starts from 2 ms to verify a record with two proofs and 1 s for a 1,000-event log. The portable implementation measures 3.9 ms and 2 s: almost all of it is Ed25519 in JavaScript, with the extra check core 4.4 requires. Nothing was traded for speed | Read [ADR-0006](docs/adr/0006-performance-budgets.md) (5 minutes). Say "fine" to its plan: the portable package is gated at 6 ms and 3 s, and at fixed ratios to the bare library; the starting budgets stay as the targets for the servers, which meet them in M5 with a native Ed25519 that applies core 4.4 exactly. Or say what you would rather have |
| **E13** | **Accept OEP-0001** | It changes normative text: thirteen points, most of them the reading both implementations already followed, and two new limits (64 levels of nesting, 64 characters for a duration). The reviews shaped it: a container is limited part by part and never as a whole. It is on the [M1 pull request](https://github.com/wonderben-code/open-intelligence-protocol/pull/2) with status Review | Read [the OEP](oeps/oep-0001-core-clarifications.md) (10 minutes). Say "accepted", or what to change. Merging the pull request is the acceptance; I then set its status to Accepted |

**The gates of BUILD.md, Section 8, as before:**

- npm organisation name (G1): `@oip` if it is available, otherwise `@openintelligence`.
- Domain name for the website (G2).
- Hosting and accounts for the public resolver, indexer and host (G3).
- Optional: an external security audit before 1.0 (G5), and a GitHub organisation for the project (G7).

## How to resume

**To continue the v1 build in a new Claude Code session** (on this repository, with push access), paste:

> Continue the OIP v1 build from PROGRESS.md.

**Other routes in:**
- In Claude, continue in the chat named "Open Intelligence Protocol (OIP)".
- To re-check the specifications' vectors: `python3 spec/test-vectors/oip_vectors.py --check`.
- To run every check CI runs: `pnpm install && pnpm run ci`.
