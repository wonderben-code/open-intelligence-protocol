# M0 review: Foundations

**Reviewed:** 17 November 2026 · **Diff:** `631e93d..4469164`, then the fixes below · **Specification revision:** 2026-11-17

[BUILD.md](../../BUILD.md), Section 7, asks for a fresh review at the end of each milestone, by an agent whose only context is the repository, the specification and the milestone's diff. M0 had two, run in parallel, each with its own area:

- **Review A: conformance.** Every schema and structural rule against the specification, member by member; the vector harness against the Python checker; the clause extraction.
- **Review B: security, test quality, and whether the gates enforce what they claim.** Hostile input, mutation of the code under the tests, bypasses of the purity and layering guards, the workflows, the documentation's claims.

Both were read-only. Each proved its findings with probes it ran. This file records every finding and what was done about it. Nothing was waived: a finding is **fixed**, or it is **queued** as a question the specification must answer, with the milestone that needs the answer, or it is **for Eks**.

## Verdicts

- **Review A:** M0 meets its acceptance criteria, with no Critical finding. One High finding, which is a gap in the specification and not in the code: the two implementations disagree on whether some properly signed identity logs are valid. It must be settled before M2.
- **Review B:** "M0 is not ready to merge." CI was red on a clean build for two reasons, and the validator could be made to throw, or to abort the process, by input well inside the protocol's size limit. The foundations were otherwise sound: every pattern is linear-time, the generator fails loudly on a bad schema, pins and permissions are right, and the vectors reproduce byte for byte.

Review B was right, and the milestone was not merged until every item below was closed.

## Review A: conformance

| # | Severity | Finding | Disposition |
|---|---|---|---|
| A1 | High | The specification does not say that each identity event must be a well-formed record for its log to verify (L1 4). The Python checker's `verify_log` therefore accepts a signed genesis with 9 homes, 17 aliases, a malformed `expires` or a bad extension name, and the schemas reject it. An address is the hash of its genesis, so the two would disagree about such a mind for ever. | **Queued, blocks M2** (Q9). A specification change: a clause in L1 4, the syntax of an HTTPS origin, the checker, and negative `log` vectors. |
| A2 | Medium | "Nobody can invalidate a record by adding a bad proof" was only partly true: an entry of `proof` that is not an object, or that holds a fraction or nests too deeply, makes the whole record malformed here, and the Python checker still counts the record. | **README corrected** to say exactly what holds. The question itself is **queued for M1** (Q2). |
| A3 | Medium | `validateProof` rejected a whole proof when an inline record in `authority` was malformed. Such a proof still counts for its signer's own mind (L2 7.1). | **Fixed.** `authority` is checked for shape only (1 to 8 entries, each a string or an object). The chain or charter is judged when it is evaluated. The remaining question is **queued for M3** (Q14). |
| A4 | Medium | The nesting limit of 64 rejects records the specification allows; L1 19 has no such limit. | **Queued for M1** (Q1). The limit stays as a documented implementation limit until the specification sets one. |
| A5 | Medium | A record of a type an extension defines (core 7) was rejected as malformed, with no way to tell it from garbage. | **Fixed.** `validateExtensionRecord` checks the members every record shares. `validateRecord` says where to take such a record. |
| A6 | Medium | `PythonJudge` matched verdicts to the wrong cases after a name containing U+2028 or U+2029, which a line reader treats as line breaks. | **Fixed.** Verdicts are ASCII only and framed by a line feed alone, and each must echo the name of the case asked about. |
| A7 | Medium | The coverage gate covered only the 83 clauses that contain a key word. Most of the verification algorithms (L1 4, 6; L2 7, 8) are written without one. | **Fixed.** The gate covers every clause not listed as informative: 176 of 184. |
| A8 | Medium | `plan.json` gave some MUST clauses to milestones that cannot satisfy them, and some areas have no owner in BUILD.md. | **Fixed** for the clauses (the keystore, the resolver, the host and the client now own theirs). The areas with no owner are **for Eks** (E7). |
| A9 | Medium | Year 0000: the schemas accept it, as RFC 3339 does; the Python checker rejects it. The differential test left it out and pointed at a queue that did not exist. | **Queued for M1** (Q3), and the queue now exists in [PROGRESS.md](../../PROGRESS.md). |
| A10 | Low | Three single-record rules were missing. | **Fixed** for two: after the genesis a mind is not its own member (L1 3.4), and an event does not list a key it revokes (L1 4.5). The third, a packet's lifetime, needs timestamp arithmetic and is owed by M4; the README says so. |
| A11 | Low | The Multikey patterns do not check the multicodec prefix exactly. | **Fixed** in words: the patterns are documented as necessary, not sufficient; `@oip/core` decodes keys in M1. |
| A12 | Low | `critical` had to have unique entries; the specification does not say so. | **Fixed.** |
| A13 | Low | Readings stricter or laxer than the text: empty strings rejected, "integer" read as non-negative, maxima derived but not stated, a score of `-0` rejected, types assumed for members the text does not type. | **Fixed**: where the text gives no limit, validation adds none. Where the notation is ambiguous about whether a member is required, validation accepts both. The ambiguities are **queued** (Q18, Q19, Q20 to Q22). |
| A14 | Low | The runner counted any exception as a rejection, so an adapter that crashed on everything passed all 51 negative cases. | **Fixed.** A throw fails the case, whatever the case requires. |
| A15 | Low | The documentation did not say that a `seen` map is partial. | **Fixed** in the adapter, the package README and the vectors' README. |
| A16 | Low | `--judge --lines` died on a line nested too deeply to parse. | **Fixed**, with a test. |
| A17 | Low | Issues cited the record's defining clause, not the clause broken, and a failed choice between shapes reported the first shape's complaint. | **Fixed.** An issue cites the clause that defines the value's syntax or the common member at fault, and the most specific fault comes first. |
| A18 | Low | Clause extraction put the anchor before L0 3.3 into L0 3.2, and summaries lost `<placeholders>`. | **Fixed.** |
| A19 | Low | `parseVectors` ignored members it did not know, so a misspelt `extraLogs` would have changed a case unnoticed. | **Fixed.** Unknown members and wrongly shaped ones are errors. |
| A20 | Low | core 1.1 was half enforced: unpaired surrogates were accepted. | **Fixed.** Duplicate member names can only be seen in the bytes, and are owed by M1. |
| A21 | Note | `$` in a pattern matches before a final newline in Python's `re`. Six policy vectors never reach a policy. The Python judge is lax on core 1. `spec/README.md`'s three MUSTs are not in `clauses.json`. | **Fixed** in `spec/schemas/README.md` (patterns are ECMAScript) and `docs/conformance/README.md` (the vector gate enforces those three). The vectors and the judge are **queued** (Q4, Q17). |

## Review B: security, tests and gates

| # | Severity | Finding | Disposition |
|---|---|---|---|
| B1 | High | CI was red at the reviewed commit for two reasons. The API report differed on a clean build, because TypeScript orders a union's members differently in an incremental build. And one test assumed that `JSON.stringify` throws on a 200,000-deep array, which the newest Node.js does not. | **Fixed.** `api` and `api:check` build from clean. The judge accepts "could not parse" as an answer that is still in step, and the test holds either way. `pnpm run ci` is now the script the CI job runs, so local and CI results cannot differ by omission. |
| B2 | High | `validateRecord` threw `RangeError` on plain JSON under 0.5 MiB: 126,000 violations were spread as function arguments. | **Fixed.** A validation reports at most 32 issues and builds them without spreading. Regression tests cover the reviewer's inputs. |
| B3 | Medium | Issue output was unbounded: a 153 KiB charter produced 391 MiB of issues. | **Fixed.** At most 32 issues, paths of at most 256 characters, quoted input cut at 64. A test bounds the serialised answer. |
| B4 | Medium | `validateRecordOfType("constructor", "a string")` returned `ok`: the map of validators had a prototype. | **Fixed.** The type is checked at run time and the map has no prototype. |
| B5 | Medium | Values that did not come from JSON text could abort the process (an array with 2²⁷ holes), take exponential time (shared references), skip the limits (non-enumerable or inherited members) or throw (getters, proxies). | **Fixed.** Validation accepts only plain JSON data, reads descriptors instead of calling accessors, budgets the values it reads, and answers a rejection whatever it is given. |
| B6 | Medium | The nightly differential campaign could not finish inside its fixed timeout. | **Fixed.** The timeout scales with the number of cases. |
| B7 | Medium | 73 of 195 hand-made mutants survived. Two causes: the test took the list of required members from the schema it was testing, and the limit tests used one repeated key, so the duplicate rule rejected them and not the limit. | **Fixed** with `test/tables.test.ts`: tables written by hand from the specification for required members, every limit at the limit and one beyond with distinct values, and 91 members that have a syntax, each with a good value and seven bad ones. Named survivors (Retire skipping the identity rules, the first event of a pair, nesting through `and`, `or`, `all`, `any`, the prototype chain in `critical`) each have a test. Stryker is the first task of M1. |
| B8 | Medium | `pnpm spec:coverage` passed when a test file could not load, and one citing test anywhere satisfied a clause. | **Fixed.** A failed run fails the gate. A clause counts as tested only when a package of the milestone that owes it, or a later one, has a passing test for it; an earlier citation shows as "tested in part". |
| B9 | Medium | The purity guards were deny-lists with many ways round: `globalThis.Date.now()`, `Reflect.construct(Date, [])`, an alias of `Date`, `Intl`, dynamic `import()`, `eval`, `eslint-disable` comments, `.mts` files, a package missing from the layer list. | **Fixed.** `Date`, `Intl`, `globalThis`, `Reflect`, `Function` and the rest are forbidden outright in pure packages; comments cannot disable the rules; the rules cover `.mts`, `.cts` and `.tsx`; an unlisted package fails the lint. `check-guards` now feeds the guards every bypass the reviewer found. A run-time trap (`withAmbientTrapped`) catches what static rules cannot. |
| B10 | Medium | SECURITY.md's only reporting channel, GitHub private vulnerability reporting, is not switched on. | **For Eks** (E1). |
| B11 | Low | `parseSelector` threw on an 8 MiB quoted name, and parsed a huge index to `Infinity`. | **Fixed.** A one-pass scanner with no recursion; an index beyond any array has one fixed value. |
| B12 | Low | "85% elsewhere" was one aggregate, so an untested file could hide. | **Fixed.** The thresholds apply to each file. The generated validators stay excluded: they are exercised through `validateRecord`, not measured. |
| B13 | Low | The runner read a non-boolean answer as "does not hold", so an adapter that returned `undefined` passed 51 of 55 negative cases. No case's reason is checked. | **Fixed** for the first: only `true` or `false` is a verdict. The second is **queued** (Q24): the vectors give reasons as prose, and need a clause per case before a reason can be checked. |
| B14 | Low | The differential generator never reached 11 record types and mutated at most four levels deep. | **Fixed.** It starts from a sample of all 29 types and goes six levels deep. |
| B15 | Low | `@oip/schema` exported a path that did not exist, and shipped API Extractor's working file. | **Fixed.** |
| B16 | Low | Documentation claims that were false or unverified. | **Fixed** where the claim was the project's to keep: ADR-0004's "never throws" is now true, `pnpm run ci` is what CI runs, workflows start from `contents: read`, the README no longer claims runtimes CI does not test, ADR-0001 names every development dependency. The DCO claim is **for Eks** (E3). |
| B17 | Note | CodeQL, dependency review, Scorecard and the nightly job had never run. Same-repository pull requests skipped every CI job. The timestamp workflows use unpinned actions. The REUSE action built from a floating image tag. | **Fixed**: pull requests run CI in their own right, and REUSE is installed by hash. CodeQL then ran on the pull request and passed for TypeScript, Python and the workflows. Dependency review ran and failed for one reason: the repository's dependency graph is switched off, which is **for Eks** (E11). Scorecard runs on `main`. The timestamp workflows are **for Eks** (E9): BUILD.md says to leave them as they are. |
| B18 | Note | Fixtures and workflows had no SPDX header. `validateExtensionRecord` accepts any type name. A `Merge` event in a container was reported as a controller fault. | **Fixed**: headers added, and containers dispatch on `type`, so a `Merge` event is reported as that. Naming rules for extension types are **queued** (Q7). |

## What the reviews checked and found sound

- **Value syntaxes.** Timestamps against the calendar for all 4.62 million dates, durations against the specification's own pattern on 5.38 million strings, decimals on 1.1 million. No differences.
- **Record types.** All 29, `Proof` and `Policy`, member by member, with about 800 crafted values.
- **The exported schemas** under an independent validator (python-jsonschema): all 104 vector records and their proofs accepted, and the same verdicts as the compiled validators on 794 probes.
- **Regular expressions.** All 25 patterns on adversarial input up to 1 MiB: linear, worst case 18.6 ms.
- **The generator.** It rejects unknown keywords and unresolved references, and is deterministic.
- **The vectors.** `vectors.json` changed only by `baseline`; the checker regenerates it byte for byte.
- **The runner** matches the Python checker's rules for every section and kind.
- **Supply chain.** Every action pin matches its tag; no script injection; credentials are not persisted; the lockfile installs frozen.
- **Clauses.** An independent extractor reproduces all 184, with the same key words and digests.
- **Secrets.** Nothing logs or prints key material.

## What was not covered

- Browsers, Deno and Bun: no M0 code is tested there yet. They join the CI matrix with the client (M6).
- The generated validators were tested by behaviour, not read line by line (17,000 lines).
- Branch-protection settings.

## After the fixes

Every check in `pnpm run ci` passes from a clean build: 587 tests, branch coverage 95.8%, 6 layering fixtures and 24 purity probes rejected by the guards, 36 generated files current, and the Python checker regenerates the vectors unchanged.

The questions for the specification (Q1 to Q24) and the items for Eks (E1 to E11) are in [PROGRESS.md](../../PROGRESS.md).
