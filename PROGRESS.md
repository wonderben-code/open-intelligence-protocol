# Progress

This file is the live status of the Open Intelligence Protocol project, so that any session can resume exactly where the last one stopped.

**Last updated:** 17 November 2026 (UTC+7)

## Where the v1 build stands

| Milestone | Status |
|---|---|
| **M0. Foundations** | **Done**, pending merge of [its pull request](https://github.com/wonderben-code/open-intelligence-protocol/pull/1), which waits on one repository setting (E11 below). Two independent reviews; every finding fixed, queued or handed to Eks ([reviews/build/M0-foundations.md](reviews/build/M0-foundations.md)) |
| **M1. Core** | **Next.** Start here |
| M2 to M14 | Not started |

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

### Starting M1

- Read BUILD.md "M1. Core", [ADR-0002](docs/adr/0002-cryptography-libraries.md) and core Sections 1 to 8 and 10.
- A probe during M0 showed that `canonicalize`, `@noble/curves` 2.4.0 and `@scure/base` reproduce the JCS example, Amina's address and all 56 proofs of the positive vectors. It also showed that the library alone accepts the `signature-r-identity` case, so the order checks of core 4.4 must be applied on top, as ADR-0002 says.
- **First task: set up Stryker**, for `@oip/schema` as well as `@oip/core`. M1 is the first milestone with a mutation threshold, and the M0 review showed what hand-made mutants find.
- Settle Q1 to Q8 below as M1 reaches them. Each is one change: specification, CHANGELOG, generator and vectors, paper, and a short OEP.
- Pure packages may not name `Date` at all (ADR-0001). Parse timestamps by hand into a bigint of nanoseconds (ADR-0003).
- Add each new pure dependency to `PURE_DEPENDENCIES` in `.dependency-cruiser.cjs`.
- When M1 is done, add `"M1"` to `completed` in [docs/conformance/plan.json](docs/conformance/plan.json).

## Specification feedback queue

Gaps and ambiguities that the build has found. Each is fixed in the milestone named, as one change: specification text, CHANGELOG, generator and vectors, and the technical paper, with a short OEP ([GOVERNANCE.md](GOVERNANCE.md)).

| # | Needed by | Question | Until it is settled |
|---|---|---|---|
| Q1 | M1 | The specification sets no limit on nesting depth (core 1, L1 19). Two conforming implementations can disagree about a deeply nested record. | `@oip/schema` applies its own limit of 64 and says so in the issue. |
| Q2 | M1 | Do the limits on every value (core 1.2, 1.6, nesting) apply to the entries of `proof`? Is an entry that is not an object a bad proof (core 5.5, 12) or a malformed record (core 5.1)? `proof` is outside every signature, so anyone relaying a record can add to it. | The limits apply to the whole record; the Python checker still counts such a record. |
| Q3 | M1 | Is year 0000 a valid timestamp (core 1.4)? RFC 3339 allows it; the Python checker rejects it. | The schemas accept it; the differential test leaves it out. |
| Q4 | M1 | The Python judge's `record` check accepts NaN, duplicate member names, fractions and integers beyond 2⁵³. It must apply core 1 before verdicts are compared under the rule "same". | Records are compared under "no laxer". |
| Q5 | M1 | Must a key hash have the canonical form of a content ID (core 3.2, 3.4)? Both implementations require it. | Required. |
| Q6 | M1 | May `kind`, and other strings, be empty? Both implementations reject an empty `kind`; the text does not. | `kind` needs one character; other strings may be empty. |
| Q7 | M1 | How does a reader treat a record whose type an extension defines (core 7 against core 11), and how are such types named? Does an `ext` name outside the three forms make a record malformed? May `critical` repeat a namespace? | `validateExtensionRecord` checks the common members and accepts any type name. |
| Q8 | M1 | Is `"-0"` a decimal between 0 and 1? Decimals compare numerically. | Accepted. |
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

1. **Build v1 in Claude Code**, from [BUILD.md](BUILD.md), continuing with M1. To continue, see "How to resume" below.
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
