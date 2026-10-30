# Progress

Live status of the Open Intelligence Protocol project, so any session can resume exactly where the last one stopped.

**Last updated:** 30 October 2026, 12:10 (UTC+7)

## Done (on `main`, Bitcoin-timestamped)

- **Founding paper**: [papers/01-founding-paper.md](papers/01-founding-paper.md)
- **Research** (four tracks, about 27,000 words with sources): [research/](research/)
  - agent protocols landscape, identity and trust, networking and routing, commitments and coordination
- **Technical architecture paper** (draft, about 14,000 words): [papers/02-technical-architecture.md](papers/02-technical-architecture.md)
- **Normative specifications**, revision 2026-10-30 (Draft): [spec/](spec/)
  - core, Layer 1 Mind Network, Layer 2 Mind Web, Layer 0 Bridge
- **Test vectors** with an independent Python implementation that generates and checks them; all checks pass: [spec/test-vectors/](spec/test-vectors/)
- **Build brief** for the v1 reference implementation: [BUILD.md](BUILD.md)
- **Supporting files**: philosophy, licences (Apache-2.0 for code, CC BY 4.0 for papers and specs), README

## In progress

- **Two independent reviews**, one of the technical paper and one of the specifications. Their findings are being written to [reviews/](reviews/) as they go.
- **Next action:** apply the review findings to the paper, the specs and the test vectors together; record the changes in [spec/CHANGELOG.md](spec/CHANGELOG.md); regenerate and re-check the vectors; push.

## Fixes already identified (apply with the review fixes)

1. Paper, Appendix B: add the record types `Hello`, `Bundle`, `FeedPage`, `DuplicityEvidence` and `Forwarded`, and the WebSocket messages `Challenge` and `Welcome`.
2. Paper, Section 5.5: say that a collective's membership for "acting as one" is taken as of the record's creation time, matching spec Layer 1, Section 9.4.
3. Paper, Section 5.9 table: `expires` is required for packets sent outside a session.
4. Spec Layer 1, Section 14.2 versus the vectors: the vector packet is the first in its session but does not carry the `Session` record. Relax 14.2 so any verb may open a session, and include the `Session` record as a content part in the vector packet.

## Next steps, in order

1. Apply the review fixes and push (this chat).
2. Publish both papers on Zenodo for permanent DOIs. **[Eks]**
3. Build v1 in **Claude Code** from [BUILD.md](BUILD.md), milestones M1 to M9, with effort set to high.
4. M10: choose hosting for the public resolver, indexer and host. **[Eks decision]**
5. Design and build the website: maximally clear, with the papers, the build, the GitHub repo and the philosophy.
6. Outreach, once the website is live.

## Open decisions for Eks

- Hosting and accounts for the public infrastructure (M10).
- A domain name for the website, which will also give the A2A extension a permanent URI.
- When to publish the papers on Zenodo.

## How to resume

- In Claude: continue in the chat named **"Open Intelligence Protocol (OIP)"**.
- In Claude Code: open this repository and read this file, then [BUILD.md](BUILD.md).
