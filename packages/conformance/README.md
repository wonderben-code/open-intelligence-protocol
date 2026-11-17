# @oip/conformance

The conformance suite of the [Open Intelligence Protocol](../../README.md): the golden test vectors, run against any implementation through an adapter.

The specification says what a conforming implementation must do with the vectors ([spec/README.md](../../spec/README.md)): reproduce every value, accept every must-accept case and every control, and reject every negative case. This package checks exactly that.

- A typed loader for [`spec/test-vectors/vectors.json`](../../spec/test-vectors/README.md).
- A runner for each kind of case: `log`, `countsFor`, `sentFor`, `status`, `assurance`, `record` and `json`.
- Differential testing against the independent Python checker, [`oip_vectors.py`](../../spec/test-vectors/oip_vectors.py).

From M5 it will also run over the wire, by profile, against any implementation's endpoints.

## Use

Write an adapter with the methods your implementation has so far. A case that needs a method you have not written is reported as **pending**, never as passed, so the report shows how far you have come.

```ts
import { type ConformanceAdapter, loadVectors, runVectors, tally } from "@oip/conformance";

/**
 * Runs the golden vectors against an implementation that so far only knows
 * whether a record is well formed, and reports how it did.
 */
export function report(recordIsWellFormed: (record: unknown) => boolean): string[] {
  const adapter: ConformanceAdapter = { name: "my implementation", recordIsWellFormed };
  const results = runVectors(adapter, loadVectors());
  const { pass, fail, pending } = tally(results);
  return [
    `${adapter.name}: ${pass} passed, ${fail} failed, ${pending} pending`,
    ...results
      .filter((result) => result.outcome === "fail")
      .map((result) => `FAIL ${result.section} ${result.name}: ${result.detail ?? ""}`),
  ];
}
```

This is [`examples/run-vectors.ts`](examples/run-vectors.ts); a test runs it and checks that this page shows it unchanged. Given a function that accepts everything, it reports the seven malformed records it should have rejected:

```
my implementation: 11 passed, 7 failed, 112 pending
FAIL negative packet-short-nonce: must be rejected. A packet nonce has 8 to 64 characters.
FAIL negative delegation-to-self: must be rejected. A delegation's delegate must differ from its author.
FAIL negative proof-entry-not-an-object: must be rejected. Every entry of `proof` is an object (core 5.1). A proof that does not verify never counts and does not make the record malformed (core 5.5); an entry that is not an object at all does.
FAIL negative extension-name-not-a-namespace: must be rejected. A member of `ext` is named by a reverse-DNS namespace, one of the short names the specification lists, or a name under `oip.` (core 8.1). Any other name makes the record malformed.
FAIL negative unknown-type-without-critical-extension: must be rejected. A record whose type this revision does not define is defined by an extension, and lists that extension in `critical` (core 7). Without it nobody can say what the record is.
FAIL negative record-nested-65-deep: must be rejected. One level more than core 1.9 allows.
FAIL negative container-carries-a-record-nested-65-deep: must be rejected. The same page with the event one level deeper. The event is not a valid record (core 1.9), so the page is not well formed.
```

## The adapter

| Method                                     | Kind of case    | Question                                                                                     |
| ------------------------------------------ | --------------- | -------------------------------------------------------------------------------------------- |
| `recordIsWellFormed(record)`               | `record`        | Is the value a well-formed record?                                                           |
| `jsonIsWithinProfile(text)`                | `json`          | Is the text JSON within the profile of core Section 1?                                       |
| `logVerifies(log, view)`                   | `log`           | Does the identity log verify (Layer 1, Section 4)?                                           |
| `countsFor(record, mind, view)`            | `countsFor`     | Does the record count for the mind (Layer 2, 7.1)?                                           |
| `sentFor(packet, mind, view)`              | `sentFor`       | Does the packet count as sent on the mind's behalf (Layer 1, 11.2)?                          |
| `status(of, records, at, view)`            | `status`        | What is the record's status at that time (Layer 2, Section 8)?                               |
| `assurance(profile, view)`                 | `assurance`     | What is the profile's assurance level (Layer 0, 1.3)?                                        |
| `canonicalize(value)`                      | positive checks | What is the canonical form of the value (core Section 2)?                                    |
| `contentId(record)`                        | positive checks | What is the record's content ID (core 3.1)?                                                  |
| `keyHash(multikey)`                        | positive checks | What is the key hash of the Multikey string (core 3.4)?                                      |
| `createProof(record, request, privateKey)` | positive checks | What proof does this test key make on the record (core 5.3)?                                 |
| `proofVerifies(record, proof)`             | positive checks | Does the proof verify: its members, its purpose and its signature under core 4.4 (core 5.4)? |

`view` is what the verifier holds for the case:

- `logs` and `records`: the **baseline**, the logs and records every case starts from. `vectors.json` names them in `baseline`.
- `extraLogs`: logs that replace the baseline logs of the same minds.
- `branches`: further, conflicting branches of a mind's log.
- `extraRecords`: records the case adds.
- `seen`: the verifier's evidence of time (core 9.4), by proof digest or by an identity event's content ID. The map is partial: a proof or an event it does not name is taken to have been obtained at its own `created` time. When `seen` is `undefined`, that holds for every proof and event.

An adapter method answers; it does not throw. The suite fails any case on which a method throws, negative cases included: crashing on an attack is not rejecting it. If your implementation signals rejection with an exception, catch that exception, and only that one, in the adapter and return `false`.

## What a case requires

| Section               | The claim must                                                                                 |
| --------------------- | ---------------------------------------------------------------------------------------------- |
| `valid` (must-accept) | hold                                                                                           |
| `controls`            | hold                                                                                           |
| `negative`            | not hold, except for `status` and `assurance` cases, whose `expect` is already the safe result |

## Differential testing

`PythonJudge` keeps the Python checker open as one process and asks it for a verdict on any case in the vectors' format. `compareVerdicts` judges a case both ways and returns the disagreement, if any.

```
pnpm test:differential                             # a short campaign
OIP_DIFFERENTIAL_RUNS=200000 pnpm test:differential   # a long one
```

It needs Python 3 with the `cryptography` package. Without them the tests are skipped, unless `OIP_REQUIRE_PYTHON` is set, as it is in CI.

At M0 the generated cases are mutated records, compared under the rule "no laxer": whatever the schemas accept, the Python checker's structural checks accept. From M2 the cases are generated identity logs, compared under the rule "same".

## In this repository

```
pnpm test:vectors      # the golden vectors against the reference implementation, by kind
pnpm spec:coverage     # writes docs/conformance/coverage.md, with the state of every kind
```

The reference implementation's adapter is `referenceAdapter`. It grows with each milestone; [docs/conformance/coverage.md](../../docs/conformance/coverage.md) shows which kinds of case it answers today.

The API report is [`etc/conformance.api.md`](etc/conformance.api.md).
