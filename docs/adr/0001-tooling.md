# ADR-0001: The workspace, the build and the checks

**Status:** Accepted, 17 November 2026 (M0)

## Context

[BUILD.md](../../BUILD.md), Section 4, names the tools for the reference implementation and asks that each be checked at M0 for its current version, maintenance, licence and security history. Section 2 says which checks CI must enforce. Several of the named tools have had major releases since the plan was written. This record says what was adopted, at which version, and where the plan was adjusted.

## Decision

### The workspace

| Concern         | Choice                         | Version at M0                | Licence                                | Notes                                                                               |
| --------------- | ------------------------------ | ---------------------------- | -------------------------------------- | ----------------------------------------------------------------------------------- |
| Runtime         | Node.js                        | 24 (`.node-version`)         | MIT                                    | CI also tests the newest Node.js                                                    |
| Package manager | pnpm                           | 12.19.0 (`packageManager`)   | MIT                                    | A pnpm 10 or later on the PATH switches to the pinned version by itself             |
| Language        | TypeScript                     | 6.0.3                        | Apache-2.0                             | See "TypeScript 6, not 7" below                                                     |
| Tests           | Vitest, with V8 coverage       | 5.1.0                        | MIT                                    |                                                                                     |
| Property tests  | fast-check                     | 4.10.2                       | MIT                                    |                                                                                     |
| Lint            | ESLint with typescript-eslint  | 10.14.0, 8.72.2              | MIT                                    | `strictTypeChecked` and `stylisticTypeChecked`                                      |
| Format          | Prettier                       | 3.9.10                       | MIT                                    |                                                                                     |
| Layering        | dependency-cruiser             | 18.7.2                       | MIT                                    |                                                                                     |
| API reports     | API Extractor                  | 7.60.1                       | MIT                                    |                                                                                     |
| API reference   | TypeDoc                        | 0.28.20                      | Apache-2.0                             |                                                                                     |
| Versioning      | Changesets                     | 3.0.3                        | MIT                                    |                                                                                     |
| Licensing       | REUSE                          | 6.3.0 (pinned by hash in CI) | GPL-3.0-or-later (a tool, not shipped) |                                                                                     |
| Node.js types   | `@types/node`                  | 24.19.2                      | MIT                                    | For tests, scripts and the packages that do I/O. Pure packages are built without it |
| ESLint support  | `@eslint/js`, `globals`        | 10.0.1, 17.14.0              | MIT                                    | ESLint's own recommended rules, and the list of Node.js globals for scripts         |
| Changelogs      | `@changesets/changelog-github` | 1.0.1                        | MIT                                    | Links each changelog entry to its pull request                                      |

All of these are development dependencies. None is shipped in a package.

### Runtime dependencies of the packages

| Package       | Dependency | Version | Licence | Why                                                                               |
| ------------- | ---------- | ------- | ------- | --------------------------------------------------------------------------------- |
| `@oip/schema` | `typebox`  | 1.4.6   | MIT     | One source for a JSON Schema and its TypeScript type. No dependencies of its own. |

`ajv` (8.20.0, MIT) is a development dependency of `@oip/schema`. It compiles the validators when the schemas change. The published package does not depend on it: the two runtime helpers Ajv's output calls are replaced by `src/runtime.ts`.

A pure package may import only the npm packages listed in `PURE_DEPENDENCIES` in `.dependency-cruiser.cjs`. Adding one needs an ADR.

### How the pieces fit

- **ESM only, strict TypeScript.** The base configuration turns on `strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess` and `erasableSyntaxOnly`. With the last, Node.js runs the build scripts as TypeScript directly, so the repository needs no script runner.
- **No ambient types.** The base configuration sets `types` to an empty list and `lib` to ES2023. A pure package therefore cannot name `process`, `Buffer`, `fetch` or `document`: the code does not compile. Packages that do I/O add `node` to `types` themselves.
- **Sources, not builds, during development.** Each package exports its source under the custom condition `@oip/source`. TypeScript, Vitest and dependency-cruiser use that condition, so `pnpm install && pnpm test` works with nothing built. Consumers of a published package do not set the condition and get `dist`.
- **Imports name `.ts` files.** `rewriteRelativeImportExtensions` rewrites them to `.js` in the build output. Declaration files keep the `.ts` names, which TypeScript resolves to the `.d.ts` files beside them; an outside project was type-checked against the built package to confirm it.
- **`tsc -b` builds.** `tsconfig.build.json` in each package is a composite project for `src`; `tsconfig.json` in each package type-checks everything, tests included, without emitting.

### Checks, and what enforces them

| Check                                                | Command                                        | Enforced in CI                                  |
| ---------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------- |
| Everything below, in order                           | `pnpm run ci`                                  | yes: it is the main job                         |
| Lint, format, layering                               | `pnpm lint`                                    | yes                                             |
| The guards still reject violations                   | `scripts/check-guards.ts`, part of `pnpm lint` | yes                                             |
| Types                                                | `pnpm typecheck`                               | yes                                             |
| Generated files are current                          | `pnpm generated:check`                         | yes                                             |
| API reports are current, from a clean build          | `pnpm api:check`                               | yes                                             |
| Clause coverage, and `coverage.md` is current        | `pnpm spec:coverage`                           | yes                                             |
| The Python checker regenerates the vectors unchanged | `python3 spec/test-vectors/oip_vectors.py`     | yes                                             |
| Tests and coverage thresholds, for each file         | `pnpm test:coverage`                           | yes, on Node 24 and the newest Node             |
| Golden vectors                                       | `pnpm test:vectors`                            | yes, on both                                    |
| Differential testing                                 | `pnpm test:differential`                       | yes, as part of the tests; a longer run nightly |
| Licensing                                            | `reuse lint`                                   | yes                                             |
| CodeQL, dependency review, OpenSSF Scorecard         | workflows                                      | yes, on pull requests and on `main`             |

**Purity** is enforced four ways, because each catches what the others miss:

1. **No ambient types** in the build (above), so `process`, `fetch` or `crypto` do not compile.
2. **ESLint rules** for the source of pure packages. They forbid every name through which the clock, randomness, the locale, the environment or the network can be reached, and the names that reach those under another name (`globalThis`, `Reflect`, `eval`, dynamic `import()`). `Date` is forbidden outright: an instant is a number of nanoseconds passed in as a parameter ([ADR-0003](0003-evidence-model.md)), and a rule that lists the dangerous uses of `Date` one by one is easy to walk round. Comments cannot switch these rules off (`noInlineConfig`).
3. **dependency-cruiser rules** for the layers, for Node.js built-ins and for the npm packages a pure package may import. The packages and their layers are listed once, in `scripts/layers.cjs`. A package that is not listed fails the lint.
4. **A run-time trap.** `withAmbientTrapped` in `@oip/testkit` replaces the clock and the sources of randomness with traps while a pure package's functions run. It catches what no static rule can: an impure dependency, or a route the rules did not think of.

**The guards are tested.** A lint rule that stops matching looks the same as clean code. `scripts/check-guards.ts` gives each guard a file or a line it must reject, and fails if it does not: six layering fixtures and two dozen purity probes, among them every bypass the M0 review found. Writing it found a real gap: an exclude pattern hid every dependency whose entry point is in a `dist` directory.

**One script is the gate.** `pnpm run ci` (`scripts/ci.ts`) runs every check in order, and the main CI job runs exactly that script, so what passes locally is what CI checks. It starts from a clean build, because the API reports need one: TypeScript can order the members of a union differently in an incremental build, and the report then differs.

### Supply chain

- `minimumReleaseAge` in `pnpm-workspace.yaml` holds back any release younger than seven days. Dependabot waits the same seven days.
- The lockfile is frozen in CI.
- GitHub Actions are pinned by commit SHA. The Python tools CI installs (the vector checker's `cryptography`, and REUSE) are pinned with hashes.
- Workflows start from `contents: read` and add only the permissions a job needs.

## Where this differs from BUILD.md

- **TypeScript 6, not 7.** TypeScript 7.0 is the current release, but typescript-eslint, TypeDoc and API Extractor all require a version below 6.1 today. TypeScript 6.0.3 is the newest version all three accept. Move to 7 when they do.
- **TypeBox 1.x.** The plan names TypeBox; the package is now published as `typebox` (1.x), and `@sinclair/typebox` (0.34) is in maintenance. TypeBox still writes tuples in the draft-07 form, so the few tuples in the schemas (policy statements, pairs of conflicting events) are written as JSON Schema 2020-12 by hand.
- **Mutation testing starts at M1.** Stryker is in the plan's tool list, but no M0 criterion uses it, and M1 is the first milestone with a mutation threshold. Setting it up, for `@oip/schema` as well as `@oip/core`, is the first task of M1. For M0, the review ran 195 hand-made mutants against the schema tests, and the tests were extended until every surviving group was killed ([reviews/build/M0-foundations.md](../../reviews/build/M0-foundations.md)).
- **`pnpm run docs`, not `pnpm docs`.** `pnpm docs` is pnpm's own command for opening a package's documentation. The root script is still called `docs`, as the plan asks.
- **Vitest 5 benchmarks.** A benchmark now runs inside a test, through the test's `bench`. `pnpm bench` runs them with the verbose reporter, which prints the timings.

## Consequences

- A contributor needs only Node.js 24 and pnpm. Python 3 with `cryptography` is needed for the differential tests, which are skipped without it (and required in CI).
- The compiled validators are a generated file of about 560 kB (about 50 kB compressed), checked in. This is the cost of never building code at run time. If it is too much for the Explorer's bundle (M11), the generator can split it by record type.
- The public types of `@oip/schema` are expressed with TypeBox's `Static`, so its type-level API is part of ours until the API freeze (M6) decides otherwise.
- The schemas' `$id`s are URNs (`urn:oip:schema:<name>`), so they do not depend on a domain name (gate G2).
