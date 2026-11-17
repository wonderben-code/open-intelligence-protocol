# Progress

Live status of the Open Intelligence Protocol project, so any session can resume exactly where the last one stopped.

**Last updated:** 17 November 2026 (UTC+7)

## Done (on `main`, Bitcoin-timestamped)

- **Founding paper**: [papers/01-founding-paper.md](papers/01-founding-paper.md)
- **Research** (four tracks, about 27,000 words with sources): [research/](research/)
- **Technical architecture paper**, Draft 2 (about 18,000 words), aligned with specification revision 2026-11-17: [papers/02-technical-architecture.md](papers/02-technical-architecture.md)
- **Normative specifications**, revision 2026-11-17 (Draft): [spec/](spec/), with every change since the first revision in [spec/CHANGELOG.md](spec/CHANGELOG.md)
  - core, Layer 1 Mind Network, Layer 2 Mind Web, Layer 0 Bridge
- **Three independent reviews**, and the fixes they led to: [reviews/](reviews/)
  - [paper review](reviews/2026-10-30-paper-review.md) and [specification review](reviews/2026-10-30-spec-review.md) of the first revision, with the reviewer's independent checker and probes, and the [fix design](reviews/2026-10-30-fix-design.md)
  - an [independent check of the fixes](reviews/2026-11-17-fix-verification.md) before publication, with its [probe scripts](reviews/fix-verification-workfiles/)
  - every finding of all three is addressed in revision 2026-11-17; the main changes are evidence-based time (per signature, with witness times for key changes), one key-validity rule, majority thresholds, invocation keys for collectives judged at each event's time, delegations carried in proofs as exact chains, strict policies that fail closed, payer and payee in prices, strict Ed25519, fixed collective heights, and duplicity resolved by first-seen evidence
- **Test vectors** with a Python implementation that generates and checks them: [spec/test-vectors/](spec/test-vectors/)
  - positive cases (including two agents signing one commitment for their principals, and every status of Intents, Offers and Commitments), 5 must-accept cases, 55 negative cases each with its reason, and 11 controls showing that each negative fails only for that reason; all pass
- **Build brief** for the v1 reference implementation, updated for revision 2026-11-17: [BUILD.md](BUILD.md)
- **Supporting files**: philosophy, licences (Apache-2.0 for code, CC BY 4.0 for papers and specs), README

## Next steps, in order

1. **Publish both papers on Zenodo** for permanent DOIs. Claude prepares the files and metadata; **[Eks]** clicks publish.
2. **Build v1 in Claude Code** from [BUILD.md](BUILD.md), milestones M1 to M9, with Opus at high effort.
3. **M10:** choose hosting for the public resolver, indexer and host. **[Eks decision]**
4. **Website:** maximally clear, with the papers, the build, the GitHub repo and the philosophy.
5. **Outreach**, once the website is live.

## Open decisions for Eks

- Hosting and accounts for the public infrastructure (M10).
- A domain name for the website, which will also give the A2A extension a permanent URI.
- When to publish the papers on Zenodo.

## How to resume

- In Claude: continue in the chat named **"Open Intelligence Protocol (OIP)"**.
- In Claude Code: open this repository and read this file, then [BUILD.md](BUILD.md).
- To re-check everything: `python3 spec/test-vectors/oip_vectors.py --check`.
