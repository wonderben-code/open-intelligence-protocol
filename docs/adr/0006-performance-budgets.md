# ADR-0006: Performance budgets, as measured in M1

**Status:** Accepted, 17 November 2026 (M1). M5 measures the remaining budgets and revisits these.

## Context

[BUILD.md](../../BUILD.md), Section 3.8, gives starting budgets and asks M1 to measure the first two on a reference machine, record the results here and adjust if needed:

| Operation                                                        | Starting budget       |
| ---------------------------------------------------------------- | --------------------- |
| Verify a record with two proofs (public-key order checks cached) | 2 ms median, one core |
| Verify a 1,000-event identity log                                | 1 s                   |

## Measurements

Machine: a cloud container with an Intel Xeon at 2.30 GHz, Node.js 24.22, one core. The numbers are medians from `pnpm bench` (`packages/core/bench/verify.bench.ts`).

| Operation                                                          | Time               |
| ------------------------------------------------------------------ | ------------------ |
| Read a Commitment with two proofs from text and verify both proofs | 3.9 ms             |
| The same, already parsed                                           | 3.7 ms             |
| One signature under core 4.4 (public key seen before)              | 1.9 ms             |
| The library's own verification of that signature                   | 1.1 ms             |
| The order check of a public key not seen before                    | 0.8 ms             |
| The same check for a key seen before                               | 0.001 ms           |
| Parse and validate the record                                      | 0.05 ms            |
| Canonical form; content ID                                         | 0.013 ms; 0.022 ms |
| Create a proof (sign, then verify the result)                      | 2.8 ms             |
| Read and verify one identity event                                 | 2.0 ms             |

Verification is Ed25519, almost entirely: parsing, validation and hashing are under 3% of the time. A signature costs three scalar multiplications in JavaScript big-integer arithmetic: two in the library, and one for the order check of `R` that core 4.4 requires ([ADR-0005](0005-cryptography-libraries-as-adopted.md)).

The signatures of a 1,000-event identity log therefore take about 2 s. Replaying the log itself is measured in M2, with `@oip/identity`.

## Decision

1. **The portable implementation gets its own budgets**, which a regression must not exceed, on this reference machine:

   | Operation                                                | Budget                               |
   | -------------------------------------------------------- | ------------------------------------ |
   | Verify a record with two proofs, read from text          | 6 ms, and 4.6 times the bare library |
   | Verify the signatures of an identity log of 1,000 events | 3 s, and 2.3 times per event         |
   | The order check of a public key seen before              | 0.05 ms                              |
   | `verifyEd25519` against the library's bare verification  | a ratio of 2.0                       |

   `pnpm bench` asserts them all, and CI runs it. The limits in milliseconds are ceilings with room for a slower machine. The ratios are the regression checks: they compare this package with the library's bare verification of one signature in the same run, so they hold on any machine, and they are set within 15% of what is measured (1.8, 4.0 and 2.0).

   The budgets in milliseconds are three times the starting budgets of BUILD.md 3.8. That is a miss, stated plainly, and not a new target: item 2 says how the starting budgets are met.

   A limit in milliseconds is compared with the fastest sample of a run, not the median: on a shared machine other work only ever adds time, so the fastest sample is the steadiest measure of what the code costs, and a regression moves it as surely as it moves the median. Medians on this machine varied between 3.9 ms and 5.4 ms from run to run for the first row, while the fastest sample stayed at 3.7 ms.

   A ratio is of medians. The two fastest samples of a ratio are taken at different moments, and measured so the first ratio moved between 1.5 and 2.0 on one machine, where the medians gave 1.5 to 1.8, idle or busy. Each ratio is measured in three rounds, the library's bare verification anew in each, and the middle ratio is compared: other work on the machine during one measurement moves one round, up or down, and can neither fail a build nor hide a regression. The identity package compares a log of 1,000 events with one event measured before it and after it, and takes the faster.

   The ratio does not depend on the machine: core 4.4 adds one scalar multiplication to the library's two, which measures at about 1.8, and a second one would pass 2.5.

2. **The starting budgets stay as the targets for the servers**, where throughput matters (M5). They need a native Ed25519, and one is available without weakening core 4.4:

   - OpenSSL, through `node:crypto`, checks `S < L` and the cofactorless equation by comparing the encoding of `[S]B − [k]A` with `R`.
   - If `A` has order L, then `[S]B − [k]A` is in the prime-order subgroup, so an `R` that equals it is canonical and has no small-order component.
   - What remains of core 4.4 is that `A` has order L, which is already checked and remembered, and that `R` is not the identity, which is a comparison of 32 bytes.

   So "OpenSSL accepts, `A` has order L, and `R` is not the identity" is the rule of core 4.4 exactly. The engine belongs to a Node-only package, never to a pure one. It is adopted only with the tests of `@oip/core` run against it unchanged, including every crafted signature, and with differential runs against the portable implementation. Until then the portable path is the only one.

3. **Nothing is traded for speed.** The order check of `R` is not dropped, and the verification equation is not assembled from point arithmetic to make it cheaper.

## Consequences

- A record with two proofs verifies in about 4 ms, and a client that verifies a mind's whole history pays about 2 ms per signature. That is acceptable for clients and tools.
- The servers of M5 are expected to need the native engine to meet their budgets (p99 of 25 ms at 500 requests per second on one core).
- A verifier can be made to do 256 signature checks by one record. With forged signatures that is about 0.9 s on this machine, since each costs the order check of `R` and the library's verification before it fails. `verifyProofs` verifies a proof that is repeated in a record once, so the cost is per distinct proof. The limits on a record bound the rest of the work: 1 MiB, 64 levels, and about a million values. Rate limits in the services (BUILD.md 3.7) bound how often anyone can ask for it, and the servers of M5 should verify a record's proofs lazily, stopping when the threshold they need is met.

## Measured in M2

The second budget is now measured in full, with `@oip/identity`: verifying an identity log of 1,000 events end to end, each event read, validated, hashed, checked against the one before it and its signature verified.

| Operation                                  | Measured            | Gate in `packages/identity/bench/log.bench.ts`   |
| ------------------------------------------ | ------------------- | ------------------------------------------------ |
| Verify an identity log of 1,000 events     | 1.8 s               | 3.5 s, and 1.4 times a thousand signature checks |
| Ask a book again for a log it has verified | under a microsecond | 0.05 ms                                          |

The whole log costs 1.08 times the signature checks of its events: replaying adds under a tenth. So the conclusion above stands unchanged for logs. The starting budget of 1 s is missed by the portable implementation for the same reason and by the same factor as the first budget, and the same native engine closes it (decision E12 in [PROGRESS.md](../../PROGRESS.md)).

One cost is new. A verifier keeps a verified log in memory, with the state after each event. A state is of bounded size ([ADR-0008](0008-holding-logs.md)), so what is kept grows with the log and no faster.

## Measured in M3

BUILD.md 3.8 has no row for delegation or for Layer 2, so these have no ceiling in milliseconds. They are measured as ratios against judging one record with one proof, which is one signature check and the reading around it, in the same run. A ratio holds on any machine, and says what the rules add to the signatures a verifier must check in any case. Each is measured in three rounds and the middle one is compared.

| Operation                                                                                    | Measured | Gate  | In                                         |
| -------------------------------------------------------------------------------------------- | -------- | ----- | ------------------------------------------ |
| A record whose proof carries the longest chain whole (eight delegations), judged and counted | 10       | 11.5  | `packages/delegation/bench/chain.bench.ts` |
| The same with the chain named by reference, the delegations held                             | 1.2      | 1.5   | `packages/delegation/bench/chain.bench.ts` |
| A policy of five statements, with a connective and a quantifier, for one record              | 0.005    | 0.007 | `packages/delegation/bench/chain.bench.ts` |
| A record signed for a collective through a charter role, judged and counted                  | 1.1      | 1.3   | `packages/web/bench/status.bench.ts`       |
| The status of a Commitment with two parties and four Receipts                                | 0.075    | 0.1   | `packages/web/bench/status.bench.ts`       |
| The status of an Intent that an accepted Commitment closes                                   | 0.015    | 0.02  | `packages/web/bench/status.bench.ts`       |

A chain given whole costs its signatures: nine, the record's and each delegation's, and a tenth of one for the rules. Named by reference, with the delegations judged when they were taken in, the eight links cost a fifth of a signature. Status checks no signature at all: the records it reads were judged when the verifier took them in, and the logs it asks about are verified once and remembered. So the conclusion above stands for these too. What a server must make fast is the signature, and nothing in these packages needs another design to be fast.
