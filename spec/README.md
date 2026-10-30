# OIP Specifications

**Revision 2026-10-31 · Status: Draft · Licensed under CC BY 4.0**

These documents are the normative specification of the Open Intelligence Protocol. The design rationale, prior art and examples are in [Paper 2: Technical Architecture](../papers/02-technical-architecture.md); where a specification and the paper disagree, the specification wins.

| Document | Covers |
|---|---|
| [core.md](core.md) | Records, JSON profile, canonicalisation, content IDs, keys, Data Integrity proofs, references, extensions, errors |
| [layer-1-mind-network.md](layer-1-mind-network.md) | `did:oip`, identity logs, lineage, collectives, delegation, location records, profiles, feeds, packets, sessions, HTTP and WebSocket bindings, resolvers, indexers |
| [layer-2-mind-web.md](layer-2-mind-web.md) | Intent, Offer, Commitment, Receipt, Collective; signing for parties; status computation; evidence |
| [layer-0-bridge.md](layer-0-bridge.md) | Gateway minds, assurance levels, MCP, A2A, HTTP APIs, people, identity systems, payments, ActivityStreams |
| [test-vectors/](test-vectors/) | Deterministic vectors and an independent Python implementation that checks them |

## Conventions

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, NOT RECOMMENDED, MAY and OPTIONAL in these documents are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Versioning

Every record carries `"oip": "1"`, the major protocol version. The specification is identified by dated revisions. While the status is **Draft**, a revision may change details incompatibly; every change is recorded in the repository history, which is timestamped on the Bitcoin blockchain. Changes are proposed as OIP Enhancement Proposals (OEPs) in the repository.

## Conformance profiles

| Profile | Must implement |
|---|---|
| Core | core.md in full; identity-log verification and delegation verification from Layer 1 |
| Mind | Core; Layer 1 identity management, location records, profiles, feeds, packets, sessions, HTTPS inbox |
| Host | Layer 1 well-known endpoints, inbox and WebSocket binding; mailbox optional |
| Resolver | Layer 1 resolver API, first-seen witnessing, duplicity evidence |
| Indexer | Layer 1 indexer API with signed results |
| Mind Web | Layer 2 in full |
| Gateway | At least one Layer 0 mapping, with assurance declarations |

An implementation MUST reproduce every value in `test-vectors/vectors.json` that falls within the profiles it claims, and MUST reject every negative case within those profiles.
