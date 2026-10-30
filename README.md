# Open Intelligence Protocol (OIP)

**The internet connected machines. The web connected documents. OIP connects minds.**

The Open Intelligence Protocol is a free, open, layered protocol stack for coordination between minds — human, artificial and institutional. It lets any mind find others, understand what they want, make verifiable commitments, keep them, and organise into collectives, while staying fully connected to everything on today's internet.

Created by **Ekram Alam**, 30 October 2026.

**Status:** specification revision 2026-10-31 (Draft). The reference implementation is being built from [BUILD.md](BUILD.md).

## The stack

| Layer | Name | Role |
|---|---|---|
| 0 | **Bridge** | Makes everything that already exists — websites, APIs, email, payments, MCP servers, A2A agents — a first-class participant. A superset, not a replacement. |
| 1 | **Mind Network** | Permanent `did:oip` addresses, identity logs with pre-rotation, fork and merge lineage, collectives, delegation, capability routing, context packets and continuity across moves. |
| 2 | **Mind Web** | Linked, signed primitives: Participant, Intent, Offer, Commitment, Receipt, Collective. |

## Read

- [Founding paper](papers/01-founding-paper.md) — the vision, the stack and the principles
- [Technical architecture paper](papers/02-technical-architecture.md) — how it works, and why
- [Specifications](spec/) — the normative rules for each layer
- [Test vectors](spec/test-vectors/) — deterministic golden values with an independent checker
- [Research notes](research/) — the survey of existing protocols and standards behind the design
- [Philosophy](PHILOSOPHY.md)

## Repository

```
papers/      founding and technical papers
spec/        normative specifications and test vectors
research/    research notes behind the design
BUILD.md     brief for the v1 reference implementation
packages/    reference implementation (in progress)
site/        the public website (coming)
```

## Licence

Code: [Apache License 2.0](LICENSE). Papers and specifications: [CC BY 4.0](LICENSE-DOCS.md). Free for everyone, forever.

## Provenance

Every push to `main` is timestamped on the Bitcoin blockchain via OpenTimestamps (see `.github/workflows/bitcoin-timestamp.yml`), and branch heads are stamped every six hours; proofs are stored in `timestamps/`.
