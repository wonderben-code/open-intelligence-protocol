# Contributing to the Open Intelligence Protocol

This repository holds the papers, the normative specifications, the test vectors and the v1 reference implementation of the Open Intelligence Protocol (OIP). Implementations in any language, critiques, test vectors, bridges and proposals are all welcome.

This guide says how to set up, which rules apply, and how a change reaches `main`.

- **Conduct.** Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Vulnerabilities.** Report them privately, as [SECURITY.md](SECURITY.md) describes. Never open a public issue for one.
- **Changes to the protocol.** These go through an OIP Enhancement Proposal (OEP). See [GOVERNANCE.md](GOVERNANCE.md).

## 1. Ways to contribute

| You want to                                                                            | Do this                                                                                                              |
| -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Ask what a clause means, or report an ambiguity, a gap or a mistake in a specification | Open an issue with the **Specification question** form                                                               |
| Report a defect in the reference implementation                                        | Open an issue with the **Bug report** form                                                                           |
| Propose a change to the protocol                                                       | Write an OEP ([GOVERNANCE.md](GOVERNANCE.md)); the **OEP proposal** issue form is there to test the idea first       |
| Fix or improve code, tests or documentation                                            | Open a pull request                                                                                                  |
| Build another implementation                                                           | Start from [spec/README.md](spec/README.md) and the [test vectors](spec/test-vectors/), and tell us what was unclear |

The v1 reference implementation is being built milestone by milestone, in the order [BUILD.md](BUILD.md) gives. [PROGRESS.md](PROGRESS.md) says where it stands. Before you start a large piece of work, open an issue, so that it does not collide with a milestone in progress.

## 2. Repository map

```
papers/        founding and technical papers (Markdown), the PDFs as archived on Zenodo, and the PDF build
spec/          normative specifications, CHANGELOG and test vectors (with the Python checker)
oeps/          OIP Enhancement Proposals and their template
research/      research notes behind the design
reviews/       independent reviews and the fixes they led to; build reviews go in reviews/build/
packages/      the reference implementation
apps/          OIP Explorer
examples/      the demo network and focused examples
docs/          ADRs (docs/adr/), guides, threat models, conformance coverage
site/          the public website (a later stage)
timestamps/    OpenTimestamps proofs for every push to main, committed by a bot; do not edit
```

Some of these directories appear only when their milestone lands.

## 3. Prerequisites

- **Git.**
- **Node.js 24 or later.** The `.node-version` file names the version to develop on.
- **pnpm**, at the version pinned in the `packageManager` field of `package.json`. Corepack reads that field: run `corepack enable` once and `pnpm` resolves to the pinned version. If your Node.js does not include Corepack, install that pnpm version another way (see <https://pnpm.io/installation>).
- **Python 3 with the `cryptography` package**, for the vector checker: `python3 -m pip install cryptography`.

## 4. Commands

```
pnpm install          # install dependencies
pnpm build            # build every package
pnpm test             # run the tests
pnpm test:vectors     # run the golden vectors, by case kind
pnpm lint             # lint
pnpm typecheck        # type-check
pnpm spec:coverage    # show which specification clauses have tests

python3 spec/test-vectors/oip_vectors.py --check   # check the vectors with the independent Python implementation
```

Run all of them before you open a pull request. CI runs the same checks, and a pull request is merged only when CI is green.

Some files are generated, and CI fails if they are out of date. Regenerate them and commit the result:

```
pnpm schemas          # after changing a schema: spec/schemas and the compiled validators
pnpm spec:clauses     # after changing a specification: spec/clauses.json
pnpm api              # after changing a public API: the API reports in packages/*/etc
pnpm spec:coverage    # after adding tests: docs/conformance/coverage.md
```

Other commands: `pnpm test:differential` compares verdicts with the Python checker; `pnpm bench` runs the benchmarks; `pnpm run docs` builds the API reference (`pnpm docs` is pnpm's own command).

## 5. The specification is normative

- **`spec/*.md` is normative.** The papers explain the design. If a paper and a specification disagree, the specification wins and the paper is corrected.
- **`spec/test-vectors/vectors.json` holds the golden values.** An independent Python implementation, `spec/test-vectors/oip_vectors.py`, generates and checks them. The reference implementation reproduces them byte for byte. Never edit a golden value by hand.
- **Code never diverges from the specification silently.** Read the relevant clauses before you write code. If the code shows that the specification is wrong, unclear or incomplete, the specification is fixed; the code does not quietly do something else.
- **Record formats change only through a specification revision.**

### How a specification change is made

There are two routes.

**An editorial fix** changes no requirement: a typo, a broken link, clearer wording of a rule that stays the same. Open a pull request. If the technical paper repeats the wording, correct it there in the same pull request.

**Any other change** alters a record format, a verification rule or other normative text. It is one change with four parts, which land together in the same pull request:

1. the specification text in `spec/`;
2. an entry in [spec/CHANGELOG.md](spec/CHANGELOG.md);
3. the Python generator and the vectors. Change `oip_vectors.py`, then run `python3 spec/test-vectors/oip_vectors.py`, which regenerates `vectors.json` and checks it;
4. the technical paper, `papers/02-technical-architecture.md`. Change the Markdown only. The PDFs in `papers/pdf/` are the files archived on Zenodo, and they are replaced only when a new version is published there.

If one of the four parts needs no change, say so in the pull request.

Such a change also needs an OEP. [GOVERNANCE.md](GOVERNANCE.md) describes the process. The OEP for a small correction can be short, and it can travel in the same pull request as the four parts. A larger change is discussed as an OEP first, before anyone writes the four parts.

If you are not sure which route applies, ask with the **Specification question** issue form.

## 6. Rules that are never broken

These rules hold for every change. A pull request that breaks one is not merged.

1. **Cryptography.** Do not implement a cryptographic primitive. Use the audited libraries the project has adopted, which are recorded in `docs/adr/`. Ed25519 verification follows core 4.4 exactly: `S < L`, canonical encodings, and `A` and `R` of order exactly L. Where a library's default is more permissive, wrap it.
2. **Numbers.** No floats in records. A decimal quantity is a string, and it is compared and computed with exact arithmetic (core 1.2, 1.3).
3. **Validate, verify, then use.** Everything that arrives from outside is untrusted until it has passed its schema, the core rules and verification. No other code touches it first.
4. **Secrets.** Never log, print or return a private key or any other secret. Keep secrets out of error messages, test output and a model's context.
5. **Purity.** The pure packages (`schema`, `core`, `identity`, `delegation`, `web`, `net`) do no I/O and never read the clock. The current time and the evidence are parameters. A package depends only on packages below it ([BUILD.md](BUILD.md), Section 3.1).
6. **Traceability.** Every requirement has a test that cites its clause, for example `clause("L1 6.4")`. Clauses are named by document and number: `core 4.4`, `L1 6.4`, `L2 8.3`, `L0 2.2`.
7. **Dependencies.** Keep them few and audited. Each one is justified in an ADR in `docs/adr/`. A pull request that adds a dependency adds or updates its ADR.

A decision that is hard to reverse also gets an ADR in `docs/adr/`, whether or not it adds a dependency.

## 7. Tests

- A test cites the clause it enforces (rule 6). `pnpm spec:coverage` reports the clauses that have no test.
- A negative test says why the input is rejected. Where you can, pair it with a control: the same input, changed only in the respect the reason names, which is accepted. The test vectors follow this convention.
- Parsers and verifiers get property-based tests.
- Do not weaken or delete a test to make a change pass. If a test is wrong, say why in the pull request.
- The full quality bar is in [BUILD.md](BUILD.md), Section 2.

## 8. Branches and pull requests

Every push to `main` is timestamped on the Bitcoin blockchain through OpenTimestamps, and a bot then commits the proof to `timestamps/`. The history of `main` is a public record, so it is never rewritten.

- **Branch.** Fork the repository, or, if you have write access, create a branch in it. Work on a branch, never on `main`. The v1 build uses one branch per milestone, for example `m2-identity`.
- **Commit small and often.** One topic per pull request.
- **Stay up to date by merging.** Fetch, then merge `main` into your branch. The bot adds a commit to `main` after every push to it, so a local copy goes stale quickly: fetch before you merge or push. Never rebase commits that are already on `main`.
- **Open a pull request to `main`** and fill in the template. Link the issue or the OEP.
- **Review.** [CODEOWNERS](.github/CODEOWNERS) names the reviewer. Changes under `spec/` also follow Section 5 above.
- **Merge.** A pull request is merged when CI is green and the review is done. It is merged with a merge commit, never squashed or rebased, so the commits that were reviewed stay in the history of `main`.
- **Never force-push `main`.**

## 9. Changesets

Every pull request that changes a package adds a changeset. Run:

```
pnpm changeset
```

Choose the packages you changed and the kind of version bump, following semantic versioning, and write one or two sentences for the people who use the package. Commit the file it creates in `.changeset/`. A pull request that changes no package (specification, papers, CI, repository documentation) needs no changeset.

## 10. Commit messages

- The summary line is in the imperative: "Reject non-canonical content IDs", not "Rejected" or "Rejects". Keep it to about 72 characters.
- Leave a blank line, then write a body that says **why**. The diff already shows what changed.
- Cite the clause or the issue where it helps.
- End with your sign-off (Section 11).

```
Reject Multikeys of the wrong length

core 4.2 requires the prefix and the length of a Multikey to match the
expected key type. The decoder checked only the prefix, so a truncated
key reached the verifier.

Signed-off-by: Ada Example <ada@example.org>
```

## 11. Sign your work: the Developer Certificate of Origin

OIP uses the Developer Certificate of Origin (DCO) 1.1 in place of a contributor licence agreement. The DCO is a short statement that you have the right to submit your contribution under the project's licences. The text is at <https://developercertificate.org> and is reproduced here:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

You certify this by adding a `Signed-off-by` trailer to every commit:

```
Signed-off-by: Ada Example <ada@example.org>
```

Git adds the trailer for you when you commit with `-s`:

```
git commit -s
```

- The name and address come from `user.name` and `user.email` in your Git configuration. They must identify you.
- Every commit in a pull request needs the trailer. A pull request with unsigned commits is not merged.
- To sign the last commit after the fact, run `git commit --amend -s`. To sign every commit on your own unmerged branch, run `git rebase --signoff main`. Both rewrite your branch, which is fine before it is merged.
- The sign-off is a person's statement. If a tool or an AI assistant helped to write the change, the person who submits it signs off and answers for it.
- The sign-off is public and permanent, as clause (d) says. Commits on `main` are also timestamped.

## 12. Licensing

- **Code** is licensed under the [Apache License 2.0](LICENSE).
- **Papers, specifications and documentation** are licensed under [CC BY 4.0](LICENSE-DOCS.md). OEPs are too.

You keep the copyright in your contribution. By contributing, you license it under the licence that covers the files you change, and your sign-off is the record that you may do so.

Every source file starts with an SPDX header in a comment:

```
// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0
```

Use `#` in place of `//` in Python and shell files. Files that carry no header, such as Markdown and JSON, are covered centrally in `REUSE.toml`. CI runs `reuse lint`, which fails if any file has no licence information. To run it yourself, install the [REUSE tool](https://reuse.software) and run `reuse lint` at the root of the repository.

## 13. Questions

Open an issue with the form that fits best. For anything that touches security, use [SECURITY.md](SECURITY.md) instead.
