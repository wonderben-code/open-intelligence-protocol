# ADR-0020: Benchmark ratios are measured turn about

**Status:** Accepted, 20 November 2026 (M5). It replaces the way [ADR-0006](0006-performance-budgets.md) measures a ratio. The numbers 0017 to 0019 belong to decisions of M6, which arrive with that milestone.

## Context

The regression checks of `pnpm bench` are ratios: a piece of work against one signature check in the same run, so that they hold on any machine (ADR-0006). ADR-0006 measured the two sides one after the other, about a second each, in three rounds, and compared the middle ratio. It said that work on the machine during two rounds would move the middle, and that a failure was to be run again before it was believed.

On 20 November the benchmarks failed three times in a row on the reference machine, with no change to the code they measure. Each run failed a different check:

| Run | Check                                            | Measured | Budget |
| --- | ------------------------------------------------ | -------- | ------ |
| 1   | `verifyEd25519` over the library, in `@oip/core` | 2.02     | 2.0    |
| 2   | A log over its signatures, in `@oip/identity`    | 1.50     | 1.4    |
| 2   | A packet received over one judged, in `@oip/net` | 1.65     | 1.3    |
| 3   | The status of a Commitment, in `@oip/web`        | 0.067    | 0.065  |

The machine was idle but for the benchmarks. It is a cloud container on a shared host, and that day its speed changed by half and more for seconds at a time:

- A loop of fixed arithmetic took 3.0 ms at its fastest, 3.4 ms at the median and 4.6 ms at the 99th percentile.
- The fastest sample of one benchmark was 1.9 ms in one round and 3.4 ms two rounds later.

Two sides measured a second apart meet different weather, and their ratio says as much about the weather as about the code. Three rounds do not help when the weather changes on the scale of one measurement. Nor does the fastest sample: it moved as the medians did.

A gate that fails a good build more often than not teaches whoever runs it to run it again without looking. The runners of CI are shared in the same way.

## Decision

1. **A ratio is measured turn about.** `ratiosOver` of `@oip/testkit/ratio` takes one sample of the reference and one of each piece of work, then one of each again, starting with another piece each turn. Each turn gives a ratio for each piece, whose two sides ran within milliseconds of each other. The middle of a piece's ratios over all the turns is what is compared with its budget.

2. **A sample is long enough to time.** Each piece is run for a tenth of a second before it is measured. Work faster than a quarter of a millisecond is run several times for one sample. The turns go on for two seconds, with 15 at least and 400 at most.

3. **Work that takes seconds is given few turns.** A log of 1,000 events is verified seven times, and the one event it is compared with is sampled for a fifth of a second beside each. Such a turn is long enough for the weather to change within it, so that ratio moves more than the others, and its budget has more room.

4. **A ceiling in milliseconds is compared with the fastest sample**, as ADR-0006 decided. Where the same measurement gives a ratio and a ceiling, `fastest` is the fastest sample of it.

5. **What was measured is written to the output of the run.** The figures of every run are in its log, whether it passed or not. Before, a ratio was seen only when it failed.

6. **Three budgets have more room.**

   | Budget                                     | Was   | Is    | Measures at    | What it is there to catch             |
   | ------------------------------------------ | ----- | ----- | -------------- | ------------------------------------- |
   | A log over its signatures, `@oip/identity` | 1.4   | 1.5   | 0.93 to 1.2    | A signature checked twice: over 2     |
   | The status of a Commitment, `@oip/web`     | 0.065 | 0.09  | 0.05 to 0.07   | The content IDs worked out twice: 0.1 |
   | The status of an Intent, `@oip/web`        | 0.03  | 0.036 | 0.022 to 0.026 | The same: 0.044                       |

   The two of `@oip/web` compare hashing with arithmetic, and the two do not slow alike on a shared machine. Taking turns does not cancel that. The other budgets stay as they were.

7. **The ratio of OpenSSL to the portable library in `@oip/server` is measured as before**, in three rounds. Turn about, each sample would change the engine and time the change. It measures at 0.05 against a budget of 0.2.

## Consequences

Three runs in a row on the same machine, the same day:

| Ratio                                         | Run 1 | Run 2 | Run 3 | Budget |
| --------------------------------------------- | ----- | ----- | ----- | ------ |
| `verifyEd25519` over the library              | 1.74  | 1.73  | 1.73  | 2.0    |
| A record with two proofs over the library     | 3.93  | 3.91  | 3.89  | 4.6    |
| An identity event over the library            | 2.00  | 2.01  | 1.97  | 2.3    |
| A log of 1,000 events over its signatures     | 1.02  | 0.93  | 1.20  | 1.5    |
| A log verified again over the first time      | 0.066 | 0.049 | 0.051 | 0.2    |
| A chain of eight given whole, over one record | 9.64  | 9.73  | 9.58  | 11.5   |
| A chain of eight named                        | 1.29  | 1.30  | 1.29  | 1.5    |
| A policy of five statements                   | 0.004 | 0.003 | 0.003 | 0.007  |
| A packet received                             | 1.02  | 1.02  | 1.03  | 1.3    |
| The place of a packet in its chain            | 0.013 | 0.013 | 0.013 | 0.05   |
| A sealed packet opened and judged             | 2.61  | 2.70  | 2.68  | 3.3    |
| A feed of 50 entries, for each                | 0.97  | 0.99  | 1.01  | 1.3    |
| A signed request                              | 0.98  | 0.98  | 0.99  | 1.3    |
| A record signed through a role                | 1.08  | 1.09  | 1.08  | 1.3    |
| The status of a Commitment                    | 0.061 | 0.071 | 0.062 | 0.09   |
| The status of an Intent                       | 0.024 | 0.026 | 0.024 | 0.036  |

The three were measured before item 6, with the log verified five times. Runs 1 and 3 passed the budgets as they were. Run 2 failed one, the status of a Commitment, at 0.071 against 0.065. With the budgets of item 6 all three pass.

- **The ratios are those ADR-0006 recorded on a quiet machine.** The measurement changed, and what is measured did not.
- **A ratio that moves now says something.** Most stay within two parts in a hundred from run to run. The checks can be read as what they are: one scalar multiplication more is 1.7, and a second signature is 1.0 more.
- **What taking turns does not cancel** is weather that slows one kind of work more than another, and weather that changes within one turn. Item 6 gives room for both.
- **The load tests and the ceilings in milliseconds still need a machine that is otherwise free** (ADR-0015). They are measured against a clock, and nothing cancels a slow machine there. Their budgets have room for a slower machine, and not for a busy one.
- **The tables of the benchmark runner are gone for these tests**, with their percentiles. The lines of item 5 take their place.

## Alternatives

- **The ratio of the two fastest samples.** ADR-0006 tried it and found it moved more than the medians. On 20 November the fastest samples moved by as much as the medians, round to round.
- **More rounds, or running a failed check again.** It costs minutes, and it is a gate that is run until it passes.
- **Budgets wide enough for the weather.** The packet received measured 1.65 against a figure of 1.0. A budget above that would pass a second signature check, which is what the budget is there to catch.
- **A machine of its own for the benchmarks.** Contributors do not have one, and CI does not either.
