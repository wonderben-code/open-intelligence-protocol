# Security policy

The Open Intelligence Protocol (OIP) is a protocol for signed, verifiable records. A flaw in the protocol is as serious as a flaw in the code. Both are handled under this policy.

## Supported versions

The reference implementation has not reached 1.0. Until it does, only the latest commit on `main` is supported. Fixes land on `main`, and nothing is backported.

| Version                                | Supported |
| -------------------------------------- | --------- |
| The latest `main`                      | Yes       |
| Any earlier commit, tag or pre-release | No        |

For the specifications, the supported text is the current revision in [spec/](spec/) on `main`.

This section will be revised when 1.0 is released.

## Reporting a vulnerability

**Report privately. Do not open a public issue, pull request or comment.**

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab and choose **Report a vulnerability**, or go straight to <https://github.com/wonderben-code/open-intelligence-protocol/security/advisories/new>.
2. Fill in the form. Only you and the maintainer can see the report.

If you are not sure whether something is a vulnerability, report it privately anyway.

## What to include

- **The affected part.** For code: the package, and its version or commit. For a specification: the document, the clause (for example `L1 6.4`) and the revision. For a test vector: the case.
- **The impact.** What an attacker can do, and what the attacker needs first: which keys, which position in the network, which timing.
- **A reproduction.** The smallest steps, code, records or logs that show the problem. For a protocol flaw, the most useful form is a case in the format of the test vectors: a record or a log, its evidence times, the verdict the specification gives and the verdict it should give.
- **The environment**, where it matters: Node.js version, operating system, browser or other runtime.
- **A fix or a mitigation**, if you have one.
- **Credit.** Say whether you want to be named in the advisory, and how.

Do not include real private keys or other people's data. The public test-vector keys are enough to show almost any flaw.

## What to expect

These are targets. The project has one maintainer today, and he will say so if a target is going to be missed.

| Step                                          | Target                                                    |
| --------------------------------------------- | --------------------------------------------------------- |
| Acknowledgement of your report                | Within 3 working days                                     |
| An assessment, and a fix or a plan with dates | Within 30 days                                            |
| Public disclosure                             | Coordinated with you; 90 days after the report by default |

- **Coordinated disclosure.** The advisory is published when the fix is released, or 90 days after the report, whichever comes first. The date can move by agreement, for example when a fix to the protocol needs other implementations to update first.
- **Credit.** Reporters are credited in the advisory unless they ask not to be.
- **Protocol flaws.** A flaw in a specification is fixed in a specification revision, with an entry in [spec/CHANGELOG.md](spec/CHANGELOG.md), new negative test vectors and an updated technical paper. The fix may be prepared in private. Its OIP Enhancement Proposal is published with the fix ([GOVERNANCE.md](GOVERNANCE.md)).
- **No bounty.** There is no bug bounty at present.

## Scope

In scope:

- **The reference implementation** in this repository: the packages in `packages/` and the applications in `apps/`.
- **The specifications** in [spec/](spec/). A protocol flaw is a security issue. Examples: a record that verifies but should not; a way to backdate a signature past a key removal, a revocation or an expiry; a rule on which two conforming implementations can reach different verdicts; a missing limit that lets one input exhaust a verifier.
- **The test vectors** in [spec/test-vectors/](spec/test-vectors/), with the Python implementation that generates and checks them. Examples: a case with the wrong verdict; a golden value that does not follow from the specification; a checker that accepts what the specification rejects.

Out of scope:

- **The test-vector keys.** They are public by design (see below).
- **Other implementations, and services run by other people.** Report those to their authors or operators. If the cause lies in a specification or in the reference implementation, it is in scope here.
- **Flaws in dependencies that do not affect how OIP uses them.** Report those upstream. If the way OIP uses a dependency makes a flaw exploitable, it is in scope here.
- **Limits that the design already states.** Section 8 of the [technical architecture paper](papers/02-technical-architecture.md) lists the threats and what the protocol does and does not do about each. Better mitigations are welcome as OEPs.
- **Content that is authenticated but harmful.** OIP proves who sent a packet. It does not prove that acting on its content is wise (L1 12.5). A reference tool that treats packet content as authority, or that lets it reach a key, is in scope.
- **Social engineering and physical attacks** on people or their devices.
- **Reports from automated scanners** that show no impact.

## The test-vector keys are public

Every key in [spec/test-vectors/vectors.json](spec/test-vectors/vectors.json) is derived from a public seed: Ed25519 keys from `SHA-256("oip-test-vector:" + label)`, and X25519 keys from `SHA-256("oip-test-vector-x25519:" + label)`. The seeds are listed in the file under `keys`. They exist so that anyone can reproduce the vectors byte for byte.

These keys are for testing only. Finding them is not a vulnerability. Never use them for anything real.

## Where the security rules live

The security-relevant design rules are normative text in the specifications, not conventions of this implementation:

| Rule                                                                                                                     | Where                |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------- |
| Strict Ed25519 verification: `S < L`, canonical encodings, and `A` and `R` of order exactly L                            | core 4.4             |
| Time by evidence: every time rule is judged on evidence of when a signature existed, never on the signer's own `created` | core 9               |
| Limits on size, count and depth                                                                                          | L1 19, with core 1.6 |
| Packet content is data, never authority                                                                                  | L1 12.5              |

The security analysis of the protocol is in Section 8 of the technical architecture paper. Threat models for each service and tool of the reference implementation will live in `docs/threat-models/`.
