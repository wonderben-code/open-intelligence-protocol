# Open Intelligence Protocol (OIP)

**The internet connected machines. The web connected documents. OIP connects minds.**

The Open Intelligence Protocol is a free, open, layered protocol stack for coordination between minds — human, artificial and institutional. It lets any mind find others, understand what they want, make verifiable commitments, keep them, and organise into collectives, while staying fully connected to everything on today's internet.

Created by **Ekram Alam**, 30 October 2026.

## The stack

| Layer | Name | Role |
|---|---|---|
| 0 | **Bridge** | Makes everything that already exists — websites, APIs, email, payments, existing agent standards — a first-class participant. A superset, not a replacement. |
| 1 | **Mind Network** | Permanent mind addresses, capability routing, context packets, continuity and native identity. |
| 2 | **Mind Web** | Linked primitives: participants, intents, offers, commitments, receipts, collectives. |

## Read

- [Founding paper](papers/01-founding-paper.md) — the vision, the stack and the principles
- [Philosophy](PHILOSOPHY.md)
- Technical architecture paper — *in progress*

## Repository

```
papers/      founding and technical papers
spec/        layer specifications (Bridge, Mind Network, Mind Web)
reference/   v1 reference implementation
site/        the public website
```

## Licence

Code: [Apache License 2.0](LICENSE). Papers and specifications: [CC BY 4.0](LICENSE-DOCS.md). Free for everyone, forever.

## Provenance

Every push to `main` is timestamped on the Bitcoin blockchain via OpenTimestamps (see `.github/workflows/bitcoin-timestamp.yml`); proofs are stored in `timestamps/`.
