# Progress

This file is the live status of the Open Intelligence Protocol project, so that any session can resume exactly where the last one stopped.

**Last updated:** 17 November 2026 (UTC+7)

## Done (on `main`, Bitcoin-timestamped)

### Papers, published on Zenodo with permanent DOIs

| Paper | DOI | PDF | Source |
|---|---|---|---|
| Founding paper, Version 1.1 | [10.5281/zenodo.24301206](https://doi.org/10.5281/zenodo.24301206) | [PDF](papers/pdf/01-founding-paper.pdf) | [Markdown](papers/01-founding-paper.md) |
| Technical architecture, Draft 2 | [10.5281/zenodo.24301209](https://doi.org/10.5281/zenodo.24301209) | [PDF](papers/pdf/02-technical-architecture.pdf) | [Markdown](papers/02-technical-architecture.md) |

- The PDFs in the repository are the exact files deposited on Zenodo, typeset by [papers/build/](papers/build/).
- The two records link to each other and to this repository.
- The concept DOIs, which always resolve to the latest version, are [10.5281/zenodo.24301205](https://doi.org/10.5281/zenodo.24301205) (founding paper) and [10.5281/zenodo.24301208](https://doi.org/10.5281/zenodo.24301208) (technical architecture).

### Specifications and checks

- **Normative specifications**, revision 2026-11-17 (Draft), in [spec/](spec/): core, Layer 1 Mind Network, Layer 2 Mind Web and Layer 0 Bridge. Every change since the first revision is in [spec/CHANGELOG.md](spec/CHANGELOG.md).
- **Test vectors** in [spec/test-vectors/](spec/test-vectors/), with a Python implementation that generates and checks them:
  - positive cases;
  - 5 must-accept cases;
  - 55 negative cases, each with its reason;
  - 11 controls that show each negative fails only for that reason.
  
  All pass.
- **Three independent reviews**, and the fixes they led to, in [reviews/](reviews/). Every finding is addressed in revision 2026-11-17.

### Supporting work

- **Research**: four tracks, about 27,000 words with sources, in [research/](research/).
- **Philosophy, licences and README.** Code is Apache-2.0; papers and specifications are CC BY 4.0.

### The v1 build, ready to start

- **[BUILD.md](BUILD.md)** is the full plan: the quality bar, the architecture, the technology, milestones M0 to M14 with acceptance criteria, workstreams, how the work runs, and Eks's gates G1 to G8.
- **[CLAUDE.md](CLAUDE.md)** is the operating manual that every Claude Code session in this repository loads automatically.

## Next steps, in order

1. **Build v1 in Claude Code**, from [BUILD.md](BUILD.md), milestone by milestone from M0. Use Opus, or the strongest model available, at high effort. To start, see "How to resume" below.
2. **Gates as they come up:**
   - npm organisation (G1);
   - domain (G2);
   - hosting for the public infrastructure (G3);
   - Zenodo GitHub link (G4);
   - external audit (G5, optional);
   - public listings (G6);
   - GitHub organisation (G7, optional).

   Each is prepared to the last click before Eks is asked.
3. **Website.**
   - Before writing it, research world-class copywriting and information design: the guides and methods of the best copywriters, editors and information designers on presenting ideas so they land.
   - Apply what that research finds to the site, to how the papers, the code and the philosophy are presented, and to the docs.
   - The site should be maximally clear, with the papers, the build, the GitHub repository and the philosophy.
4. **Outreach**, once the website is live.

## Open decisions for Eks

- npm organisation name (G1): `@oip` if it is available, otherwise `@openintelligence`.
- Domain name for the website (G2).
- Hosting and accounts for the public resolver, indexer and host (G3).
- Optional: an external security audit before 1.0 (G5), and a GitHub organisation for the project (G7).

## How to resume

**To start the v1 build in a new Claude Code session** (on this repository, with push access), paste:

> You're the lead engineer for the Open Intelligence Protocol's v1 reference implementation. Read CLAUDE.md, PROGRESS.md and BUILD.md, then build v1 milestone by milestone, starting with M0. Work autonomously to the quality bar in BUILD.md, and stop only for the gates that need Eks.

**To continue in a later session**, paste:

> Continue the OIP v1 build from PROGRESS.md.

**Other routes in:**
- In Claude, continue in the chat named "Open Intelligence Protocol (OIP)".
- To re-check the specifications' vectors: `python3 spec/test-vectors/oip_vectors.py --check`.
