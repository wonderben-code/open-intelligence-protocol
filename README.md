# Open Intelligence Protocol (OIP)

[![Founding paper DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24301206.svg)](https://doi.org/10.5281/zenodo.24301206)
[![Technical architecture DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24301209.svg)](https://doi.org/10.5281/zenodo.24301209)

**The internet connected machines. The web connected documents. OIP connects minds.**

The Open Intelligence Protocol is a free, open, layered protocol stack for coordination between minds: human, artificial and institutional. With it, any mind can:

- find others and understand what they want;
- make verifiable commitments and keep them;
- organise into collectives;

all while staying fully connected to everything on today's internet.

It was created by **Ekram Alam** on 30 October 2026.

**Status:** specification revision 2026-11-17 (Draft); both papers are published on Zenodo. The reference implementation is being built to the plan in [BUILD.md](BUILD.md): the foundations (M0) are in place, and [PROGRESS.md](PROGRESS.md) says what comes next.

## The stack

| Layer | Name | Role |
|---|---|---|
| 0 | **Bridge** | Makes everything that already exists (websites, APIs, email, payments, MCP servers, A2A agents) a first-class participant. OIP is a superset, not a replacement. |
| 1 | **Mind Network** | Permanent `did:oip` addresses, identity logs with pre-rotation, lineage between minds, collectives, delegation, capability routing, context packets, and continuity across moves. |
| 2 | **Mind Web** | Linked, signed primitives: Participant, Intent, Offer, Commitment, Receipt and Collective. |

## Read

- **Founding paper**: the vision, the stack and the principles. Available as [Markdown](papers/01-founding-paper.md) or [PDF](papers/pdf/01-founding-paper.pdf); DOI [10.5281/zenodo.24301206](https://doi.org/10.5281/zenodo.24301206).
- **Technical architecture paper**: how OIP works, and why. Available as [Markdown](papers/02-technical-architecture.md) or [PDF](papers/pdf/02-technical-architecture.pdf); DOI [10.5281/zenodo.24301209](https://doi.org/10.5281/zenodo.24301209).
- **[Specifications](spec/)**: the normative rules for each layer.
- **[Test vectors](spec/test-vectors/)**: deterministic golden values with a checker, including attack cases that every implementation must reject.
- **[Reviews](reviews/)**:
  - two independent reviews of the first revision;
  - an independent check of the fixes;
  - how each finding was fixed.
- **[Research notes](research/)**: the survey of existing protocols and standards behind the design.
- **[Philosophy](PHILOSOPHY.md)**.

## Build

The v1 reference implementation is planned in **[BUILD.md](BUILD.md)**. It is a complete, production-grade TypeScript implementation of all three layers:

- an SDK and the `oip` command;
- host, resolver and indexer servers;
- an MCP server, so that any MCP-capable assistant can join;
- an A2A bridge;
- a conformance suite;
- OIP Explorer.

Progress is tracked in [PROGRESS.md](PROGRESS.md).

To work on it, you need Node.js 24 and pnpm:

```
pnpm install
pnpm test          # the tests, in a few seconds
pnpm run ci        # every check CI runs, from a clean build
```

[CONTRIBUTING.md](CONTRIBUTING.md) explains how to contribute, [docs/adr/](docs/adr/) records the decisions behind the build, and [docs/conformance/coverage.md](docs/conformance/coverage.md) shows which clauses of the specifications the code enforces today.

## Repository

```
papers/      founding and technical papers, with their PDFs and the build that typesets them
spec/        normative specifications, JSON Schemas and test vectors
research/    research notes behind the design
reviews/     independent reviews and the fixes they led to; reviews/build/ has one per milestone
BUILD.md     the plan for the v1 reference implementation
CLAUDE.md    how coding agents work in this repository
PROGRESS.md  where the project stands
packages/    the reference implementation (in progress)
docs/        decision records and conformance coverage
oeps/        OIP Enhancement Proposals
site/        the public website (coming)
```

## Cite

> Alam, E. (2026). *The Open Intelligence Protocol: A Founding Paper for the Network of Minds* (Version 1.1). Zenodo. https://doi.org/10.5281/zenodo.24301206

> Alam, E. (2026). *The Open Intelligence Protocol: Technical Architecture* (Draft 2, specification revision 2026-11-17). Zenodo. https://doi.org/10.5281/zenodo.24301209

GitHub's "Cite this repository" button uses [CITATION.cff](CITATION.cff).

## Licence

Code is under the [Apache License 2.0](LICENSE). Papers and specifications are under [CC BY 4.0](LICENSE-DOCS.md). Free for everyone, forever.

## Provenance

Every push to `main` is timestamped on the Bitcoin blockchain through OpenTimestamps (see `.github/workflows/bitcoin-timestamp.yml`), and branch heads are stamped every six hours. The proofs are stored in `timestamps/`. Both papers are archived on Zenodo with permanent DOIs.
