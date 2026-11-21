# ADR-0015: The servers' budgets, as measured in M5, and signatures that are checked once

**Status:** Accepted, 20 November 2026 (M5).

## Context

[BUILD.md](../../BUILD.md), Section 3.8, has seven budgets. M1 measured the first two, which are of verification itself ([ADR-0006](0006-performance-budgets.md)). The other five are of the services, and M5 is to measure them on a reference machine and record the results:

| Operation                                         | Budget                                             |
| ------------------------------------------------- | -------------------------------------------------- |
| Resolver: resolve a known mind                    | p99 of 25 ms at 500 requests a second, on one core |
| Resolver: accept a published bundle               | p99 of 100 ms                                      |
| Indexer: a capability query over 100,000 profiles | p99 of 100 ms                                      |
| Packet delivery over a WebSocket, on one machine  | p99 of 20 ms                                       |
| Cold start of a server container                  | 2 s                                                |

ADR-0006 measured the portable Ed25519 at about 2 ms for a signature: 4 ms for a record with two proofs and 2 s for a log of a thousand events, against starting budgets of 2 ms and 1 s. It gave the portable implementation budgets of its own, kept the starting budgets as the targets for the servers, and set out how a native Ed25519 could meet them without weakening core 4.4. It expected the five budgets below to need the native one too.

## How they are measured

Each service runs as a process of its own, from its source, with its database on disk and its log at the default level, and is asked over a socket of the same machine (`packages/*/bench/load.bench.ts`, with `@oip/testkit/load`).

- **The load is an open loop.** Requests leave at a steady rate, whatever the service does, and each is timed from the moment it was due. A request that waited for the one before it has waited, and the wait is counted. A loop that sends the next request when the last is answered hides the stalls a percentile is there to show.
- **Three rounds, and the middle.** Other work on the machine during one round moves that round. The middle 99th percentile is what is held to the budget, as the middle ratio is in ADR-0006.
- **The resolver** holds fifty minds, each with a log of three events, and is asked for them in turn at 500 requests a second for six seconds. A bundle that is published is of a mind it has not seen, with a genesis and an update: two signatures to check. Twenty a second for five seconds.
- **The indexer** holds 100,000 profiles, each with a text of twelve words out of five thousand, some common and most rare, and three tags. They are put into the index without the indexer, which would check 100,000 signatures first; a query checks none. A query asks for two words, and one in four also for a tag, fifty a second for six seconds. Each answer is signed.
- **The host** has a sender on one socket and the mind's own instance on another. A packet is timed from when it was due to be sent to when the instance has it: in between the host has judged it as its recipient would (Layer 1, 12.4), recorded the first sight of its proof, kept it in the mailbox and sent it on. Fifty a second for six seconds.
- **A container** is timed from `docker start` to a `200` from `/readyz` ([ADR-0014](0014-containers.md)).

## What the first measurement showed

The first run had a published bundle at a median of 45 ms, for two signatures that take five. A commit of the database takes half a millisecond on the machine, so the time was not the disk.

**The resolver verified each published log four to five times over.** It read the log to see how far it verifies, witnessed it, checked that what it held was what it had judged, and counted the proofs it keeps: each of them verifies every signature, and each is right to. A bundle published a second time, with nothing new in it, cost all of it again. A resolve after a publication verified the log once more.

On a public `PUT` that is more than a slow path. Anyone can send a resolver a log it already holds. A known log of a thousand events kept it busy for about ten seconds each time, and a resolver answers nothing else while it verifies.

## Decision

1. **A signature that verified is remembered** (`@oip/core`). `verifyEd25519` keeps a yes under a hash of the signature, the message and the key together, in the bounded memo that already keeps the keys whose order was checked, and gives it at once when the same three come again. 16,384 signatures are kept, and the least recently used are forgotten.

   - **Only a yes is kept.** A no is worked out each time, so a check that was cut short can never leave an honest signature marked as bad ([ADR-0010](0010-checks-cut-short.md)).
   - **Nothing but time depends on it.** Verification is a function of those three byte strings, and the hash covers every byte of them: the signature and the key have fixed lengths, so the three are told apart wherever the message ends. The verdict of core 4.4 is what it was for every input, and every test of `@oip/core` passes unchanged.
   - **It is in the pure package**, where the key memo is, and so serves every verifier: a client that is sent a longer copy of a log it has read pays for the new events.
   - **A benchmark that times the checking of a signature forgets first** (`forgetVerifiedSignatures`), so that it times the check and not the memory.

2. **The five budgets of the services stand as they are, and are met by the portable Ed25519.** `pnpm bench` holds each service to the four that are under load, and CI runs it. The `containers` job of CI holds each image to the fifth: it stops and starts each container three times, and the fastest start must be ready within two seconds (`scripts/container-start.ts`).

3. **The native Ed25519 of ADR-0006, item 2, is its own decision: [ADR-0016](0016-native-ed25519.md).** These five budgets do not need it. The first two rows of BUILD.md 3.8 do: with the portable library a service verifies a record with two proofs in 4 ms and a new log of a thousand events in 2 s, where the targets are 2 ms and 1 s.

## Measurements

Machine: the cloud container of ADR-0006, four cores, Node.js 24.22. The p50 and p99 of each of three rounds, in milliseconds.

| Operation                                | The portable library                  | OpenSSL (ADR-0016), the default     | Budget (p99) |
| ---------------------------------------- | ------------------------------------- | ----------------------------------- | ------------ |
| Resolve a known mind, 500 a second       | 0.81/5.97, 0.75/2.35, 0.77/2.30       | 0.79/5.66, 0.70/2.45, 0.72/2.96     | 25           |
| Accept a published bundle                | 13.94/27.40, 15.46/35.09, 15.63/25.92 | 10.04/14.60, 9.72/18.81, 9.28/17.84 | 100          |
| A capability query over 100,000 profiles | 8.73/31.00, 8.63/24.89, 8.02/28.13    | 6.70/27.18, 6.46/23.86, 6.10/22.48  | 100          |
| Delivery of a packet over a WebSocket    | 3.76/36.56, 3.75/6.03, 3.76/7.98      | 1.97/5.74, 2.18/3.30, 1.98/4.16     | 20           |

The middle 99th percentiles with the portable library are 2.4, 27, 28 and 8 ms: each budget is met with room to spare. A container is ready within 0.5 to 1.2 s of its start (ADR-0014), against 2 s.

Before signatures were remembered, on the same machine while it did other work, a published bundle measured a median of 45 ms and a 99th percentile of 67 to 99 ms, and a delivery a 99th percentile of 14 to 25 ms.

In one process, without HTTP, with the portable library, by the number of events in a log. The middle of three, in milliseconds:

| Events | Their signatures alone | Published, before | Published again, before | Published, now | Published again, now |
| ------ | ---------------------- | ----------------- | ----------------------- | -------------- | -------------------- |
| 1      | 2 to 3                 | 10.7              | 11.8                    | 6.0            | 2.0                  |
| 2      | 4 to 5                 | 19.0              | 21.7                    | 9.1            | 2.8                  |
| 12     | 23 to 28               | 104               | 128                     | 39             | 11                   |
| 100    | 206 to 226             | 968               | 1,176                   | 276            | 63                   |

A log that is new costs its signatures once, and the order check of each key it brings. One that is known costs its reading and its hashing: about half a millisecond for each event.

## Consequences

- **A log seen for the first time is still verified in one piece**, and a service answers nothing else meanwhile: about 2 ms for each event with the portable library, and a quarter of a millisecond with OpenSSL (ADR-0016). A resolver that expects long logs from strangers lowers the number of events it takes in one bundle.
- **The memory is bounded**: 16,384 names of 64 characters, a few megabytes. A flood of distinct signatures can push honest ones out of it, which costs time and nothing else.
- **The load tests start three processes and take about a minute and a half.** They run with the other benchmarks, and their budgets are in milliseconds, so a machine that is busy can miss one. As ADR-0006 says of a ratio: a failure is run again before it is believed.
- **The ratios of ADR-0006 are measured as before.** Each benchmark of M1 to M4 forgets what is remembered before each sample.

## Alternatives

- **Verify once in the resolver, and pass the verdict along.** The four passes are four questions, asked by code that does not trust what the pass before it concluded: how far a stranger's copy verifies, what a witness may record, whether the store holds what was judged. Passing one verdict through all of them would join what is separate on purpose. Remembering the arithmetic keeps each question whole and makes its answer cheap.
- **A memo of verified events in the log book.** Whether an event verifies depends on the event before it, on the proofs every copy carries, on its members' logs and on the evidence of time. A signature depends on three byte strings.
- **The native Ed25519 instead.** It makes each check cheaper and leaves four of them where one is needed. With both, a new log costs little more than a known one, and a known one costs its reading.
