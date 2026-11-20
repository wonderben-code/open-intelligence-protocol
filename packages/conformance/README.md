# @oip/conformance

The conformance suite of the [Open Intelligence Protocol](../../README.md): the golden test vectors, run against any implementation through an adapter, and the service profiles, run against any implementation [over the wire](#over-the-wire).

The specification says what a conforming implementation must do with the vectors ([spec/README.md](../../spec/README.md)): reproduce every value, accept every must-accept case and every control, and reject every negative case. This package checks exactly that.

- A typed loader for [`spec/test-vectors/vectors.json`](../../spec/test-vectors/README.md).
- A runner for each kind of case: `log`, `countsFor`, `sentFor`, `status`, `assurance`, `record` and `json`, and the eight kinds of the Mind Network: `feed`, `checkpoint`, `receive`, `chain`, `hello`, `ack`, `location` and `participant`.
- Differential testing against the independent Python checker, [`oip_vectors.py`](../../spec/test-vectors/oip_vectors.py).

- The Resolver, Host and Indexer profiles as checks over HTTP, server-sent events and WebSocket, with a report that is JSON, and the command `oip-conformance`.

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

This is [`examples/run-vectors.ts`](examples/run-vectors.ts); a test runs it and checks that this page shows it unchanged. Given a function that accepts everything, it reports the 17 malformed records it should have rejected:

```
my implementation: 23 passed, 17 failed, 333 pending
FAIL negative packet-short-nonce: must be rejected. A packet nonce has 8 to 64 characters.
FAIL negative delegation-to-self: must be rejected. A delegation's delegate must differ from its author.
FAIL negative policy-nested-nine-deep: must be rejected. A statement of a policy is at depth 0, and no statement is deeper than 8 (Layer 1, 11.3). Here a comparison stands under nine negations.
FAIL negative delegation-with-a-reserved-command: must be rejected. Under `/oip` there are five commands, and every other command whose first segment is `oip` is reserved (Layer 1, 11.2).
FAIL negative offer-with-a-quantity-of-zero: must be rejected. An Offer's `quantity` says how many times it can be taken up, and is at least 1 (Layer 2, 4.2). An Offer of nothing is no Offer.
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
FAIL negative packet-without-a-sender: must be rejected. A packet names its sender in `from` (Layer 1, 12.1). This one has none.
```

## The adapter

| Method                                     | Kind of case    | Question                                                                                           |
| ------------------------------------------ | --------------- | -------------------------------------------------------------------------------------------------- |
| `recordIsWellFormed(record)`               | `record`        | Is the value a well-formed record?                                                                 |
| `jsonIsWithinProfile(text)`                | `json`          | Is the text JSON within the profile of core Section 1?                                             |
| `logVerifies(log, view)`                   | `log`           | Does the identity log verify (Layer 1, Section 4)?                                                 |
| `countsFor(record, mind, view)`            | `countsFor`     | Does the record count for the mind (Layer 2, 7.1)?                                                 |
| `sentFor(packet, mind, view)`              | `sentFor`       | Does the packet count as sent on the mind's behalf (Layer 1, 11.2)?                                |
| `status(of, records, at, view)`            | `status`        | What is the record's status at that time (Layer 2, Section 8)?                                     |
| `assurance(profile, view)`                 | `assurance`     | What is the profile's assurance level (Layer 0, 1.3)?                                              |
| `feed(case, view)`                         | `feed`          | How far do the entries verify as their author's feed (Layer 1, Section 10)?                        |
| `checkpoint(case, view)`                   | `checkpoint`    | Is the checkpoint valid for that feed, and which proofs does it cover (Layer 1, 10.5)?             |
| `receive(case, view)`                      | `receive`       | Does the receiver accept what arrived, at that time on its clock (Layer 1, 12.4)?                  |
| `chain(case, view)`                        | `chain`         | What does a participant hold of each sending chain, once the packets have arrived (Layer 1, 14.3)? |
| `hello(case, view)`                        | `hello`         | Which mind does the `Hello` authenticate to that server (Layer 1, 13.3)?                           |
| `ack(case, view)`                          | `ack`           | Which proofs is the `Ack` evidence for (Layer 1, 13.2)?                                            |
| `location(case, view)`                     | `location`      | Which location record of its author is current (Layer 1, 15.2)?                                    |
| `participant(case, view)`                  | `participant`   | Which profile of its author is current (Layer 1, 16.4)?                                            |
| `canonicalize(value)`                      | positive checks | What is the canonical form of the value (core Section 2)?                                          |
| `contentId(record)`                        | positive checks | What is the record's content ID (core 3.1)?                                                        |
| `keyHash(multikey)`                        | positive checks | What is the key hash of the Multikey string (core 3.4)?                                            |
| `createProof(record, request, privateKey)` | positive checks | What proof does this test key make on the record (core 5.3)?                                       |
| `proofVerifies(record, proof)`             | positive checks | Does the proof verify: its members, its purpose and its signature under core 4.4 (core 5.4)?       |

The eight methods of the Mind Network take the case itself and answer with `{ holds, value }`: whether the case's claim holds, and what the implementation worked out on the way (how many entries verified, which proofs a checkpoint covers, what is held of each chain). The suite reads `holds`. A differential test compares `value` too.

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
OIP_DIFFERENTIAL_NETWORK=500 pnpm test:differential:network  # the Mind Network, as every pull request runs it
```

It needs Python 3 with the `cryptography` package. Without them the tests are skipped, unless `OIP_REQUIRE_PYTHON` is set, as it is in CI.

At M0 the generated cases are mutated records, compared under the rule "no laxer": whatever the schemas accept, the Python checker's structural checks accept. From M2 they are also identity cases, compared under the rule "same":

- logs of key-controlled minds, of collectives, and of collectives that have collectives as members, each with something done to it: an event moved or dropped, a member changed with or without signing again, a key that was not committed to, a proof or evidence of another time;
- records signed by a mind's own keys, records pinned to one of two or three branches of a log, and records signed under a collective's threshold while its members change;
- lineages, acknowledged by a `Fork` event, by a `Lineage` record, or not at all.

For one case in four the two implementations also resolve the DID document of the mind the case is about, and the documents must be equal, so a state replayed wrongly shows even where both accept the log. For every log, both say how far it verifies and whether the event after that is invalid or undecided (Layer 1, 4.9), and the answers must be equal: the checker classes an event from the text of 4.9, apart from its own verification.

`pnpm run ci` runs the identity campaign at 6,700: 10,888 logs, 5,025 records and 838 lineages. The nightly workflow runs a million logs. The name of each test gives the number of cases it ran, and the test fails if another number ran.

From M4 they are also cases of the Mind Network, under the rule "same":

- feeds and checkpoints, with entries forked, dropped, misplaced, signed by a stranger or held in copies;
- packets that arrive, with each date on either side of its limit, addressed to a list, a query or a subject, as themselves or forwarded by a broker;
- the packets of a session in an order the generator chose, with links forked, missing or given twice, and a first packet with or without the `Session` record;
- `Hello` records, acknowledgements, sets of location records, and profiles.

Both implementations also say what they found, and that is compared: how many entries verify and which equivocate, which proofs a checkpoint or an `Ack` covers, the chain a receiver holds and how many packets wait behind a gap, the record that is current. A receiver that takes packets as they come names the first two links it finds at one place of a chain. The checker gives the links at every place, and the two the receiver names must be among them.

`pnpm run ci` runs this campaign at 500: 6,000 cases. The nightly workflow runs 240,000.

## Over the wire

A resolver, a host and an indexer are services, so their profiles ([spec/README.md](../../spec/README.md)) are tested by asking one as its clients do. The suite needs nothing of the implementation but its URL.

```
npx oip-conformance resolver https://resolver.example
npx oip-conformance host http://127.0.0.1:8080 --origin https://host.example --json > report.json
```

The suite makes minds of its own for each run, with fresh keys, and publishes them to the implementation. So run it against a deployment that may hold them. Nothing a run makes is shared with another run: its minds, its words and its tags are its own.

Each check cites the clauses it holds the implementation to, and ends in one of four ways:

| Outcome          | Meaning                                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `pass`           | The implementation did what the clauses ask.                                                                                   |
| `fail`           | It did not. `detail` says what was required and what happened.                                                                 |
| `not-applicable` | The clauses ask it only of an implementation that offers something this one does not, such as a mailbox.                       |
| `skipped`        | The check could not be made: a check it builds on did not pass, or the suite was not given what it needs. `detail` says which. |

A report says that an implementation `conforms` only if every check of level `MUST` passed or did not apply. A check that was skipped proves nothing, so a report with one does not say it. Checks of level `SHOULD` are reported and do not decide.

| Profile    | What is checked                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resolver` | Layer 1, Section 17: publication; the `Bundle` and its `firstSeen` times, which are kept; a location record, and one that the mind did not sign; what is taken of a log with an event that does not verify or cannot be read; duplicity, the log that is served after it, and the evidence; the stream, from a cursor and live; signed publication where the resolver requires it (13.3); what is refused as malformed (core 1 and 10.2). |
| `host`     | Layer 1, Section 13: the well-known `Bundle`, `LogPage`, `FeedPage` and records; the inbox, with what it takes, what it refuses, a duplicate and a `Sealed` record; the `Ack` of a host that signs for a mind; the mailbox, drained and emptied by its owner alone (13.3, 13.5); the WebSocket binding, from the challenge to the mail a mind's own instance is sent (13.4).                                                              |
| `indexer`  | Layer 1, Section 18: submission; the capability query and its `QueryResult`, whose signature is judged by the indexer's own log; what a query finds by word, kind and tag; that nothing is listed which its author did not sign; no result for constraints or evidence nobody can have checked; the limit; brokered delivery, where the indexer offers it (18.5).                                                                         |

The specification leaves some things to an implementation, and the suite is told of them:

- **Another origin.** A signed request and a `Hello` name the origin the implementation knows itself by (13.3). Where the suite reaches a test deployment by another address, give that origin as `origin`.
- **A host's own interface.** How a mind comes to be served by a host, and how it brings the host its feed and its records, is the host's business ([OEP-0005](../../oeps/oep-0005-service-clarifications.md), open question 3). `hostProfile` takes a `setup` that does it for the host under test. Unless one is given, it is `referenceHostSetup`: the interface of `@oip/host`, which must then run with `OIP_HOST_OPEN` set.
- **An indexer's own log.** `indexerProfile` asks the indexer for the `Bundle` of its own mind at the well-known path, as the reference indexer serves it. Give `bundle` where it is found another way.
- **An inbox to watch.** What an indexer forwards arrives at other minds' inboxes. Give `inbox`, an endpoint the indexer can reach and the suite can read, and the suite checks what arrives there. Without one those checks are skipped, and the report says so. The command cannot be given one: use the library, or give the command `--allow-skipped`, with which it ends with 0 where no required check failed.

From a program:

```ts
import { runWire, type WireOptions, type WireProfile } from "@oip/conformance";

/**
 * Runs a profile against an implementation over the wire, and reports how
 * it did: a line with the sum, and a line for each check that failed.
 */
export async function report(profile: WireProfile, options: WireOptions): Promise<string[]> {
  const { checks, summary, conforms } = await runWire(profile, options);
  return [
    `the ${profile} at ${options.origin ?? options.target}: ${summary.pass} passed, ${summary.fail} failed, ` +
      `${summary.skipped} skipped, ${summary["not-applicable"]} not applicable: ` +
      (conforms ? "it conforms" : "not shown to conform"),
    ...checks
      .filter((check) => check.outcome === "fail")
      .map((check) => `FAIL ${check.id} [${check.clauses.join(", ")}]: ${check.detail ?? ""}`),
  ];
}
```

Against the reference resolver, with its defaults, it gives:

```
the resolver at https://resolver.example: 26 passed, 0 failed, 0 skipped, 1 not applicable: it conforms
```

The one check that does not apply is of a resolver that requires signed publication, which this one does not unless it is told to (17.3).

What the suite does not check is what only time or the operator can show: that a mailbox keeps an item for 30 days, that a rate limit holds, that a first-seen time survives a restart. The reference services have tests of their own for those.

The suite is tested against itself. In this repository each profile is run against the reference service, and then against that service with a fault planted between the two: a proxy that changes one thing the service is asked or answers, as an implementation with that fault would. Each fault must fail the checks it breaks. A check that no fault can make fail checks nothing.

## In this repository

```
pnpm test:vectors      # the golden vectors against the reference implementation, by kind
pnpm spec:coverage     # writes docs/conformance/coverage.md, with the state of every kind
```

The reference implementation's adapter is `referenceAdapter`. It grows with each milestone; [docs/conformance/coverage.md](../../docs/conformance/coverage.md) shows which kinds of case it answers today.

The API report is [`etc/conformance.api.md`](etc/conformance.api.md).
