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

This is [`examples/run-vectors.ts`](examples/run-vectors.ts); a test runs it and checks that this page shows it unchanged. Given a function that accepts everything, it reports the 13 malformed records it should have rejected:

```
my implementation: 20 passed, 13 failed, 155 pending
FAIL negative packet-short-nonce: must be rejected. A packet nonce has 8 to 64 characters.
FAIL negative delegation-to-self: must be rejected. A delegation's delegate must differ from its author.
FAIL negative proof-entry-not-an-object: must be rejected. Every entry of `proof` is an object (core 5.1). A proof that does not verify never counts and does not make the record malformed (core 5.5); an entry that is not an object at all does.
FAIL negative extension-name-not-a-namespace: must be rejected. A member of `ext` is named by a reverse-DNS namespace, one of the short names the specification lists, or a name under `oip.` (core 8.1). Any other name makes the record malformed.
FAIL negative unknown-type-without-critical-extension: must be rejected. A record whose type this revision does not define is defined by an extension, and lists that extension in `critical` (core 7). Without it nobody can say what the record is.
FAIL negative extension-type-without-created: must be rejected. `created` is required in every record except the containers and `Sealed` (core 7), and those are types of this specification. A record of a type an extension defines carries it like any other.
FAIL negative duration-of-65-characters: must be rejected. One character more than core 1.5 allows. Without the limit a duration could have a million digits, and a reader that computes with it would do arithmetic on numbers of that size.
FAIL negative record-nested-65-deep: must be rejected. One level more than core 1.9 allows.
FAIL negative container-carries-a-record-nested-65-deep: must be rejected. The same page with the event one level deeper. The event is not a valid record (core 1.9), so the page is not well formed.
FAIL negative duplicity-evidence-carries-a-record-nested-65-deep: must be rejected. The same evidence with the event one level deeper.
FAIL negative feed-page-carries-a-record-nested-65-deep: must be rejected. The rule for containers holds for a `FeedPage` and the entries it carries.
FAIL negative bundle-carries-a-location-nested-65-deep: must be rejected. A `Bundle` carries records in three members: `log`, `location` and `participant`. Each is held to the limit.
FAIL negative container-nested-65-deep-without-its-records: must be rejected. The limit also applies to the container without the members that hold its records: here a member of the page's own nests 65 deep.
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

## The reference adapter is a test harness

`referenceAdapter` answers each kind of case with the reference implementation. It does so under the convention of the vectors: where a case gives no evidence, every proof and identity event is taken as seen at its own `created`, and every log as known in full. That convention is what makes a file of fixed cases possible. It is also the one assumption a verifier must never make about anything that arrives from outside (core 9.2). Use the adapter in conformance and differential tests, and nowhere else; a verifier uses `@oip/identity` with its own evidence.

## Differential testing

`PythonJudge` keeps the Python checker open as one process and asks it for a verdict on any case in the vectors' format. `compareVerdicts` judges a case both ways and returns the disagreement, if any.

```
pnpm test:differential                                    # every differential test, a short campaign of each
OIP_DIFFERENTIAL_RUNS=200000 pnpm test:differential       # a long campaign of records and JSON texts
OIP_DIFFERENTIAL_LOGS=6700 pnpm test:differential:logs    # the identity campaign, as every pull request runs it
```

It needs Python 3 with the `cryptography` package. Without them the tests are skipped, unless `OIP_REQUIRE_PYTHON` is set, as it is in CI.

At M0 the generated cases are mutated records, compared under the rule "no laxer": whatever the schemas accept, the Python checker's structural checks accept. From M2 they are also identity cases, compared under the rule "same":

- logs of key-controlled minds, of collectives, and of collectives that have collectives as members, each with something done to it: an event moved or dropped, a member changed with or without signing again, a key that was not committed to, a proof or evidence of another time;
- records signed by a mind's own keys, records pinned to one of two or three branches of a log, and records signed under a collective's threshold while its members change;
- lineages, acknowledged by a `Fork` event, by a `Lineage` record, or not at all.

For one case in four the two implementations also resolve the DID document of the mind the case is about, and the documents must be equal, so a state replayed wrongly shows even where both accept the log.

`pnpm run ci` runs the identity campaign at 6,700: 10,888 logs, 5,025 records and 838 lineages. The nightly workflow runs a million logs. The name of each test gives the number of cases it ran, and the test fails if another number ran.

## In this repository

```
pnpm test:vectors      # the golden vectors against the reference implementation, by kind
pnpm spec:coverage     # writes docs/conformance/coverage.md, with the state of every kind
```

The reference implementation's adapter is `referenceAdapter`. It grows with each milestone; [docs/conformance/coverage.md](../../docs/conformance/coverage.md) shows which kinds of case it answers today.

The API report is [`etc/conformance.api.md`](etc/conformance.api.md).
