# ADR-0005: The cryptography libraries as adopted in `@oip/core`

**Status:** Accepted, 17 November 2026 (M1). It records what [ADR-0002](0002-cryptography-libraries.md) asked M1 to check, and what M1 found.

## Context

ADR-0002 chose the libraries and said that each adoption re-checks the facts. M1 adopts four of them in `@oip/core`: `@noble/curves`, `@noble/hashes`, `@scure/base` and `canonicalize`.

## What was checked

### Versions and audits

The audit facts are as the libraries' own READMEs state them at the versions installed.

| Library         | Installed | Audits the library reports                                                                                                                                                                                                                                   |
| --------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `@noble/curves` | 2.4.0     | Trail of Bits at 2.3.0 (August 2026, scope: everything); Cure53 at 1.6.0 (September 2024, including ed25519 and its low-level modules); Kudelski Security at 1.2.0; Trail of Bits at 0.7.3. The installed version is one minor release after the last audit. |
| `@noble/hashes` | 2.4.0     | Cure53 at 1.0.0 (January 2022, including SHA-2). The authors report regular self-audits since April 2026. The installed version is well after the independent audit.                                                                                         |
| `@scure/base`   | 2.4.0     | Cure53 at 1.0.0 (January 2022); self-audited at 2.2.0 (April 2026).                                                                                                                                                                                          |
| `canonicalize`  | 5.1.0     | None. It is one file of about two hundred lines, which was read in full for this record.                                                                                                                                                                     |

An audit of an earlier version is evidence about a library's design and its maintainers, not a guarantee about the installed version. The tests below are what OIP relies on.

### Against published vectors

- **Ed25519.** RFC 8032, Section 7.1: tests 1, 2, 3 and SHA(abc) reproduce (public key, signature, verification).
- **SHA-256.** The FIPS 180-4 examples reproduce, and the library agrees with the platform's SHA-256 on generated inputs.
- **Canonical JSON.** The sorting example of RFC 8785, Section 3.2.3, the escaping rules of 3.2.2.2 and the example in the OIP vectors reproduce. An independent serialiser written for the tests agrees with the library on generated values and on every record of the vectors.
- **Everything together.** All 56 proofs of the positive vectors verify and reproduce byte for byte from their test keys.

### What the Ed25519 library accepts on its own

With `{ zip215: false }` the library checks `S < L`, rejects non-canonical encodings of `A` and `R`, rejects a small-order `A`, and checks the cofactored equation. It accepts:

- a public key with a small-order component (a mixed-order key);
- a signature whose `R` is the identity point;
- a signature whose `R` has a small-order component.

The tests build each of these with a known secret scalar, show that the library accepts it, and show that `verifyEd25519` rejects it. So core 4.4 needs exactly the two checks ADR-0002 planned, the order of `A` and the order of `R`, and both are in `packages/core/src/ed25519.ts`.

No point of order L has a second, non-canonical encoding: that needs a y-coordinate below 19, and no point with one has order L. The tests show this for all 38 candidates. The rule on canonical encodings therefore only ever rejects points that the order rule rejects too. The library is still called in its strict mode.

## Decisions

1. **The order check of `R` uses the library's own subgroup test**, `isTorsionFree()`, on the point decoded in strict mode, together with `is0()`. It costs one scalar multiplication per signature ([ADR-0006](0006-performance-budgets.md)). The alternative, checking the cofactorless equation with the library's point arithmetic, would make `R`'s check free but would mean assembling the verification equation ourselves. That is implementing a primitive, which this project does not do.

2. **The order check of a public key is remembered**, in a bounded least-recently-used memo of 4,096 keys. The memo never changes an answer, and its bound keeps a flood of distinct keys from growing memory.

3. **Signing reaches the platform's random number generator, and the signature does not depend on it.** `@noble/curves` 2.x masks secret scalars with a random multiple of the group order, as a defence against side channels, when the platform has a generator. RFC 8032 signing stays deterministic: a test replaces the generator with one that returns constant bytes and gets the same signature. The purity rule of this project is about results: pure packages do no I/O and never read the clock, so that the same input always gives the same output. Blinding keeps that property, so it stays on. Verification, parsing and hashing read no randomness at all, and a test traps the generator to show it.

4. **Nothing reaches the canonical-JSON library without passing the JSON profile first.** `canonicalize` also writes floats, and calls `toJSON` where it finds one. `@oip/schema` exports the profile check as `validateJson`, and every path into the serialiser goes through it. The check requires arrays to be plain arrays, so that no `toJSON` can sit on one.

5. **JSON is parsed by `@oip/core`'s own parser, not `JSON.parse`.** `JSON.parse` keeps the last of two members with the same name, and turns numbers into floats before anyone can judge them. The parser is not cryptography; it is tested against an oracle that shares nothing with it, on a million generated inputs per run.

## Consequences

- Each verification costs three scalar multiplications where the library alone does two.
- A new version of a library is adopted by running the same tests. The crafted signatures will show at once if its strict mode changes.
- If `canonicalize` ever differs from RFC 8785 within OIP's profile, the tests' independent serialiser is the evidence, and a serialiser over validated values replaces it, as ADR-0002 allows.
