# ADR-0001: The workspace, the build and the checks

**Status:** Accepted, 17 November 2026 (M0)

## Context

[BUILD.md](../../BUILD.md), Section 4, names the tools for the reference implementation and asks that each be checked at M0 for its current version, maintenance, licence and security history. Section 2 says which checks CI must enforce. Several of the named tools have had major releases since the plan was written. This record says what was adopted, at which version, and where the plan was adjusted.

## Decision

### The workspace

| Concern         | Choice                        | Version at M0              | Licence                                | Notes                                                                   |
| --------------- | ----------------------------- | -------------------------- | -------------------------------------- | ----------------------------------------------------------------------- |
| Runtime         | Node.js                       | 24 (`.node-version`)       | MIT                                    | CI also tests the newest Node.js                                        |
| Package manager | pnpm                          | 12.19.0 (`packageManager`) | MIT                                    | A pnpm 10 or later on the PATH switches to the pinned version by itself |
| Language        | TypeScript                    | 6.0.3                      | Apache-2.0                             | See "TypeScript 6, not 7" below                                         |
| Tests           | Vitest, with V8 coverage      | 5.1.0                      | MIT                                    |                                                                         |
| Property tests  | fast-check                    | 4.10.2                     | MIT                                    |                                                                         |
| Lint            | ESLint with typescript-eslint | 10.14.0, 8.72.2            | MIT                                    | `strictTypeChecked` and `stylisticTypeChecked`                          |
| Format          | Prettier                      | 3.9.10                     | MIT                                    |                                                                         |
| Layering        | dependency-cruiser            | 18.7.2                     | MIT                                    |                                                                         |
| API reports     | API Extractor                 | 7.60.1                     | MIT                                    |                                                                         |
| API reference   | TypeDoc                       | 0.28.20                    | Apache-2.0                             |                                                                         |
| Versioning      | Changesets                    | 3.0.3                      | MIT                                    |                                                                         |
| Licensing       | REUSE                         | 6.x (CI action)            | GPL-3.0-or-later (a tool, not shipped) |                                                                         |

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

| Check                                        | Command                                        | Enforced in CI                      |
| -------------------------------------------- | ---------------------------------------------- | ----------------------------------- |
| Lint, format, layering                       | `pnpm lint`                                    | yes                                 |
| The guards still reject violations           | `scripts/check-guards.ts`, part of `pnpm lint` | yes                                 |
| Types                                        | `pnpm typecheck`                               | yes                                 |
| Tests and coverage thresholds                | `pnpm test:coverage`                           | yes, on Node 24 and the newest Node |
| Golden vectors                               | `pnpm test:vectors`                            | yes                                 |
| Differential testing                         | `pnpm test:differential`                       | yes, and a longer run nightly       |
| Clause coverage                              | `pnpm spec:coverage`                           | yes                                 |
| Generated files are current                  | `pnpm generated:check`                         | yes                                 |
| API reports are current                      | `pnpm api:check`                               | yes                                 |
| Python vector checker                        | `python3 spec/test-vectors/oip_vectors.py`     | yes                                 |
| Licensing                                    | `reuse lint`                                   | yes                                 |
| CodeQL, dependency review, OpenSSF Scorecard | workflows                                      | yes                                 |

**Purity** is enforced three ways, because each catches what the others miss: the missing ambient types (above); ESLint rules that forbid `Date.now()`, `new Date()` with no argument, `Math.random()` and Node.js built-ins in pure packages; and dependency-cruiser rules for the layers.

**The guards are tested.** A lint rule that stops matching looks the same as clean code. `scripts/check-guards.ts` gives each guard a file or a line it must reject, and fails if it does not. Writing it found a real gap: an exclude pattern hid every dependency whose entry point is in a `dist` directory.

### Supply chain

- `minimumReleaseAge` in `pnpm-workspace.yaml` holds back any release younger than seven days. Dependabot waits the same seven days.
- The lockfile is frozen in CI.
- GitHub Actions are pinned by commit SHA. The Python checker's dependency is pinned with hashes.
- Workflows start from `contents: read` and add only the permissions a job needs.

## Where this differs from BUILD.md

- **TypeScript 6, not 7.** TypeScript 7.0 is the current release, but typescript-eslint, TypeDoc and API Extractor all require a version below 6.1 today. TypeScript 6.0.3 is the newest version all three accept. Move to 7 when they do.
- **TypeBox 1.x.** The plan names TypeBox; the package is now published as `typebox` (1.x), and `@sinclair/typebox` (0.34) is in maintenance. TypeBox still writes tuples in the draft-07 form, so the few tuples in the schemas (policy statements, pairs of conflicting events) are written as JSON Schema 2020-12 by hand.
- **Mutation testing starts at M1.** Stryker is in the plan's tool list, but no M0 criterion uses it, and M1 is the first milestone with a mutation threshold. It is set up there, with the code it measures.
- **`pnpm run docs`, not `pnpm docs`.** `pnpm docs` is pnpm's own command for opening a package's documentation. The root script is still called `docs`, as the plan asks.
- **Vitest 5 benchmarks.** A benchmark now runs inside a test, through the test's `bench`. `pnpm bench` runs them with the verbose reporter, which prints the timings.

## Consequences

- A contributor needs only Node.js 24 and pnpm. Python 3 with `cryptography` is needed for the differential tests, which are skipped without it (and required in CI).
- The compiled validators are a generated file of about 560 kB (about 50 kB compressed), checked in. This is the cost of never building code at run time. If it is too much for the Explorer's bundle (M11), the generator can split it by record type.
- The public types of `@oip/schema` are expressed with TypeBox's `Static`, so its type-level API is part of ours until the API freeze (M6) decides otherwise.
- The schemas' `$id`s are URNs (`urn:oip:schema:<name>`), so they do not depend on a domain name (gate G2).
