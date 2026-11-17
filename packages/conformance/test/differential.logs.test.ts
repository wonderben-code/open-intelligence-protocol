// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Differential testing of identity against the independent Python checker
 * (M2): generated identity logs, and records signed by the minds they
 * describe. Both implementations decide these completely, so the rule is
 * "same": both accept, or both reject.
 *
 * A case is a log that a test mind wrote, or one of its members' logs, with
 * something done to it: an event moved or dropped, a member changed with or
 * without signing again, the wrong key, evidence of another time. Most of
 * what is generated does not verify, and some does; what matters is that the
 * two verdicts agree on every case.
 */

import { contentId, formatTimestamp, proofDigest } from "@oip/core";
import {
  agreementKey,
  at,
  Collective,
  intentBy,
  KeyMind,
  locationBy,
  type Mind,
  rawSign,
  signer,
  T,
  unchecked,
} from "@oip/testkit/minds";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  compareVerdicts,
  type JsonObject,
  loadVectors,
  PythonJudge,
  pythonJudgeUnavailable,
  referenceAdapter,
  type VectorCase,
} from "../src/index.ts";

const unavailable = pythonJudgeUnavailable();
const required = process.env["OIP_REQUIRE_PYTHON"] !== undefined;
// A short campaign with the ordinary tests; `pnpm test:differential` runs the
// 10,000 that BUILD.md asks of every pull request, and the nightly job more.
const RUNS = Number(process.env["OIP_DIFFERENTIAL_LOGS"] ?? 300);
// About 25 ms a case; ten times that, so a slow runner does not fail the campaign.
const TIMEOUT = Math.max(120_000, RUNS * 250);

const vectors = loadVectors();

type Events = JsonObject[];

/** What an event may change. Each is a member of an Update, by the mind's own keys. */
const CHANGES = [
  "nothing",
  "another operational key",
  "a second operational key",
  "no operational key",
  "the operational key as invocation key",
  "no invocation key",
  "revoke the operational key",
  "revoke it as compromised",
  "the first key again",
  "homes",
  "aliases",
  "another agreement key",
] as const;

function fieldsFor(mind: Mind, change: (typeof CHANGES)[number], seconds: number): JsonObject {
  const key = (n: number) => ({ key: mind.operational(n).publicKey });
  switch (change) {
    case "nothing":
      return {};
    case "another operational key":
      return { keys: [key(1)] };
    case "a second operational key":
      return { keys: [key(0), key(1)] };
    case "no operational key":
      return { keys: [] };
    case "the operational key as invocation key":
      return { invocation: [key(0)] };
    case "no invocation key":
      return { invocation: [] };
    case "revoke the operational key":
      return { revoked: [key(0)] };
    case "revoke it as compromised":
      return { revoked: [{ ...key(0), compromisedSince: T(seconds - 50) }] };
    case "the first key again":
      return { keys: [key(0)] };
    case "homes":
      return { homes: ["https://one.example", "https://two.example:8443"] };
    case "aliases":
      return { alsoKnownAs: ["dns:mind.example", "at://mind.example"] };
    case "another agreement key":
      return { agreement: [{ key: agreementKey(`${mind.name}/agreement/1`) }] };
  }
}

interface Step {
  readonly kind: "update" | "fork" | "retire";
  readonly gap: number;
  readonly change: (typeof CHANGES)[number];
}

const step: fc.Arbitrary<Step> = fc.record({
  kind: fc.constantFrom("update", "update", "update", "update", "fork", "retire"),
  gap: fc.constantFrom(0, 1, 60, 3600),
  change: fc.constantFrom(...CHANGES),
});

const names = fc.constantFrom("ada", "bea", "cy", "dee");

/** A key-controlled mind that has lived through some steps. Not every such log verifies. */
function live(name: string, steps: readonly Step[], start = 100): KeyMind {
  const mind = new KeyMind(name, start);
  let seconds = start;
  for (const { kind, gap, change } of steps) {
    seconds += gap;
    const fields = fieldsFor(mind, change, seconds);
    if (kind === "update") mind.update(seconds, fields);
    else if (kind === "fork")
      mind.fork(seconds, { ...fields, child: new KeyMind("child").address });
    else mind.retire(seconds, fields);
  }
  return mind;
}

/** Members put in an event and signed for by the control key whose turn it is: well formed or not. */
const RAW_CHANGES: readonly JsonObject[] = [
  { seq: 7 },
  { seq: 0 },
  { seq: true },
  { seq: "1" },
  { prev: "bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna" },
  { mind: "did:oip:bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna" },
  { created: "2020-01-01T00:00:00Z" },
  { created: "2026-02-30T00:00:00Z" },
  { created: "soon" },
  { expires: "never" },
  { expires: "2027-01-01T00:00:00Z" },
  { type: "Merge" },
  { type: "Genesis" },
  { type: "Rename" },
  { recovery: {} },
  { height: 1 },
  { kind: "" },
  { kind: "collective" },
  { kind: "x".repeat(65) },
  { controller: undefined },
  {
    controller: {
      members: ["did:oip:bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna"],
      threshold: 1,
    },
  },
  { controller: { keys: [], next: [] } },
  { homes: Array.from({ length: 9 }, (_, n) => `https://home${n}.example`) },
  { homes: Array.from({ length: 8 }, (_, n) => `https://home${n}.example`) },
  { homes: ["https://UPPER.example"] },
  { homes: ["https://a.example/"] },
  { homes: ["https://a.example/path"] },
  { homes: ["https://a.example:443"] },
  { homes: ["https://a.example:8443"] },
  { homes: ["https://a.example:65536"] },
  { homes: ["https://a.example:0443"] },
  { homes: ["https://user@a.example"] },
  { homes: ["https://a..example"] },
  { homes: ["https://-a.example"] },
  { homes: ["https://a.example."] },
  { homes: ["https://[::1]"] },
  { homes: ["https://xn--bcher-kva.example", "https://127.0.0.1", "https://localhost:8443"] },
  { homes: [`https://${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`] },
  { homes: [`https://${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(62)}`] },
  { homes: [`https://${"a".repeat(64)}.example`] },
  { homes: ["http://a.example"] },
  { homes: "https://a.example" },
  { alsoKnownAs: Array.from({ length: 17 }, (_, n) => `dns:n${n}.example`) },
  { alsoKnownAs: Array.from({ length: 16 }, (_, n) => `dns:n${n}.example`) },
  { alsoKnownAs: [5] },
  { keys: [{ key: "z6MkeTG3bFFSLYVU7VqhgZxqr6YzpaGrQtFMh1uvqGy1vDnP" }] },
  { keys: [{ key: "zNotAKey" }] },
  { keys: [{ key: signer("extra").publicKey, label: "x".repeat(65) }] },
  { keys: [{ key: signer("extra").publicKey, label: "x".repeat(64) }] },
  { keys: [{ key: signer("extra").publicKey, colour: "red" }] },
  { keys: [{ key: signer("extra").publicKey }, { key: signer("extra").publicKey }] },
  { keys: Array.from({ length: 65 }, (_, n) => ({ key: signer(`k${n}`).publicKey })) },
  { invocation: Array.from({ length: 17 }, (_, n) => ({ key: signer(`k${n}`).publicKey })) },
  { agreement: [{ key: signer("extra").publicKey }] },
  { agreement: [{ key: agreementKey("extra") }] },
  { revoked: [{ key: "zNotAKey" }] },
  { revoked: [{ key: signer("extra").publicKey, compromisedSince: "then" }] },
  { revoked: [{ key: signer("extra").publicKey, other: 1 }] },
  { revoked: {} },
  { parents: [{ mind: "did:oip:nobody", at: "0-x" }] },
  { parents: [] },
  { inherits: [] },
  { inherits: { funds: "half" } },
  { ext: { "com.example": { v: 1 } } },
  { ext: { "bad name": {} } },
  { ext: { "com.example": 5 } },
  { critical: ["com.example"] },
  { ext: { "com.example": {} }, critical: ["com.example"] },
  { child: "nobody" },
  { successor: "nobody" },
  { reason: 5 },
  { terms: [] },
  { note: "a member no reader of this revision knows" },
  { oip: "2" },
  { proof: [] },
];

type Twist =
  | { readonly kind: "none" | "swap" | "drop" | "repeat" | "truncate" | "wrong key" | "no proofs" }
  | { readonly kind: "unsigned"; readonly member: JsonObject }
  | { readonly kind: "raw"; readonly member: JsonObject }
  | { readonly kind: "purpose" };

const twist: fc.Arbitrary<Twist> = fc.oneof(
  { weight: 3, arbitrary: fc.constant<Twist>({ kind: "none" }) },
  {
    weight: 3,
    arbitrary: fc.constantFrom<Twist>(
      { kind: "swap" },
      { kind: "drop" },
      { kind: "repeat" },
      { kind: "truncate" },
      { kind: "wrong key" },
      { kind: "no proofs" },
      { kind: "purpose" },
    ),
  },
  {
    weight: 2,
    arbitrary: fc
      .constantFrom(...RAW_CHANGES)
      .map((member): Twist => ({ kind: "unsigned", member })),
  },
  {
    weight: 8,
    arbitrary: fc.constantFrom(...RAW_CHANGES).map((member): Twist => ({ kind: "raw", member })),
  },
);

/** A member given as `undefined` is left out, as JSON has no such value. */
function withMembers(event: JsonObject, member: JsonObject): JsonObject {
  return Object.fromEntries(
    Object.entries({ ...event, ...member }).filter(([, value]) => value !== undefined),
  );
}

/** The log of a key-controlled mind with one thing done to it, at an event chosen by `pick`. */
function twisted(mind: KeyMind, change: Twist, pick: number): Events {
  const events = mind.events as unknown as Events;
  const i = pick % events.length;
  const j = (i + 1) % events.length;
  const event = events[i]!;
  const replaced = (replacement: JsonObject) => events.map((e, n) => (n === i ? replacement : e));
  switch (change.kind) {
    case "none":
      return events;
    case "swap":
      return events.map((e, n) => (n === i ? events[j]! : n === j ? event : e));
    case "drop":
      return events.length === 1 ? events : events.filter((_, n) => n !== i);
    case "repeat":
      return [...events.slice(0, i + 1), ...events.slice(i)];
    case "truncate":
      return events.slice(0, i + 1);
    case "wrong key":
      return replaced(rawSign(event, [{ control: signer(`${mind.name}/intruder`) }]));
    case "no proofs":
      return replaced(withMembers(event, { proof: undefined }));
    case "purpose":
      return replaced(
        rawSign(event, [{ control: mind.control(i) }], { purpose: "assertionMethod" }),
      );
    case "unsigned":
      return replaced(withMembers(event, change.member));
    case "raw":
      return replaced(rawSign(withMembers(event, change.member), [{ control: mind.control(i) }]));
  }
}

/** Evidence for some events at other times than their own: `[event, seconds from its date]`. */
const DELTAS = [-301, -300, -1, 1, 299, 100_000] as const;

function seenFor(
  events: Events,
  picks: readonly (readonly [number, number])[],
): Record<string, string> {
  const seen: Record<string, string> = {};
  for (const [pick, delta] of picks) {
    const event = events[pick % events.length]!;
    const created = Date.parse(String(event["created"]));
    if (Number.isNaN(created)) continue;
    try {
      seen[contentId(event)] = formatTimestamp(
        BigInt(created) * 1_000_000n + BigInt(delta) * 1_000_000_000n,
      );
    } catch {
      // An event with no content ID has no evidence.
    }
  }
  return seen;
}

const seenPicks = fc.array(fc.tuple(fc.nat(8), fc.constantFrom(...DELTAS)), { maxLength: 2 });

/** A `log` case about a key-controlled mind. */
const keyLogCase: fc.Arbitrary<VectorCase> = fc
  .record({
    name: names,
    steps: fc.array(step, { maxLength: 4 }),
    change: twist,
    pick: fc.nat(8),
    seen: seenPicks,
  })
  .map(({ name, steps, change, pick, seen }) => {
    const log = unchecked(() => twisted(live(name, steps), change, pick));
    return { kind: "log", name: "generated", log, seen: seenFor(log, seen) };
  });

/**
 * A `log` case about a collective: up to three people found it, and it lives
 * through updates signed by some of them, while one of them changes or
 * retires its own keys. Evidence may place any event at another time.
 */
const collectiveLogCase: fc.Arbitrary<VectorCase> = fc
  .record({
    size: fc.constantFrom(1, 2, 3),
    threshold: fc.constantFrom(1, 2, 3),
    height: fc.constantFrom(undefined, undefined, 1, 2, 5),
    memberSteps: fc.array(step, { maxLength: 2 }),
    memberStart: fc.constantFrom(0, 150, 400),
    updates: fc.array(
      fc.record({
        gap: fc.constantFrom(1, 100, 1000),
        signers: fc.subarray([0, 1, 2, 3]),
        change: fc.constantFrom("nothing", "homes", "admit", "expel", "retire"),
      }),
      { maxLength: 3 },
    ),
    founders: fc.constantFrom("all", "all", "all", "fewer", "operational"),
    seen: seenPicks,
    memberSeen: seenPicks,
  })
  .map((plan) =>
    unchecked(() => {
      const people = ["ada", "bea", "cy", "dee"].map((name) => new KeyMind(name, 0));
      const members = people.slice(0, plan.size);
      const outsider = people[3]!;
      const threshold = Math.min(plan.threshold, plan.size);
      const fields = plan.height === undefined ? {} : { height: plan.height };
      let club: Collective;
      try {
        club = new Collective("club", members, threshold, 200, fields);
      } catch {
        // A threshold that is not a majority, or a height that cannot be: signed raw.
        const sound = new Collective("club", members, plan.size, 200);
        club = sound;
        club.events[0] = rawSign(
          withMembers(sound.events[0] as unknown as JsonObject, {
            ...fields,
            controller: { members: members.map((member) => member.address), threshold },
          }),
          members.map((member) => member.asMember()),
        ) as never;
      }
      if (plan.founders === "fewer") {
        club.events[0] = rawSign(
          club.events[0] as unknown as JsonObject,
          members.slice(1).map((member) => member.asMember()),
        ) as never;
      } else if (plan.founders === "operational") {
        club.events[0] = rawSign(
          club.events[0] as unknown as JsonObject,
          members.map((member) => ({
            member: member.address,
            versionId: member.versionId(),
            invocation: member.operational(),
          })),
        ) as never;
      }
      // The first member's own log goes on while the collective lives.
      const first = members[0]!;
      let seconds = plan.memberStart;
      for (const { kind, gap, change } of plan.memberSteps) {
        seconds += gap + 1;
        const changed = fieldsFor(first, change, seconds);
        if (kind === "retire") first.retire(seconds, changed);
        else first.update(seconds, changed);
      }
      let when = 200;
      let current = [...members];
      for (const update of plan.updates) {
        when += update.gap;
        const signers = update.signers.flatMap((n) => (people[n] === undefined ? [] : [people[n]]));
        try {
          if (update.change === "retire") {
            club.retire(when, signers);
          } else if (update.change === "admit" || update.change === "expel") {
            current =
              update.change === "admit"
                ? [...new Set([...current, outsider])]
                : current.length > 1
                  ? current.slice(1)
                  : current;
            club.update(when, signers, {
              controller: {
                members: current.map((member) => member.address),
                threshold: Math.floor(current.length / 2) + 1,
              },
            });
          } else {
            club.update(
              when,
              signers,
              update.change === "homes" ? { homes: ["https://club.example"] } : {},
            );
          }
        } catch {
          // An event nobody signs is not written.
        }
      }
      const log = club.events as unknown as Events;
      const extraLogs = people.map((person) => person.events as unknown as Events);
      return {
        kind: "log",
        name: "generated",
        log,
        extraLogs,
        seen: {
          ...seenFor(first.events, plan.memberSeen),
          ...seenFor(log, plan.seen),
        },
      };
    }),
  );

/**
 * A `countsFor` case: a record signed by one of a mind's operational keys,
 * pinned to some version of its log, dated and seen at some times. No proof
 * names an authority, so the mind's own keys decide (Layer 1, 6.1).
 */
const ownKeyCase: fc.Arbitrary<VectorCase> = fc
  .record({
    name: names,
    steps: fc.array(step, { minLength: 1, maxLength: 4 }),
    position: fc.nat(8),
    key: fc.constantFrom(0, 0, 0, 1),
    type: fc.constantFrom("Intent", "Intent", "Location"),
    created: fc.constantFrom(50, 100, 101, 160, 161, 3700, 4000, 9000),
    seenAfter: fc.constantFrom(undefined, -301, -300, 0, 1, 61, 3601, 100_000),
    expires: fc.constantFrom(undefined, undefined, 10, 4000),
    logSeen: seenPicks,
  })
  .map((plan) => {
    const mind = unchecked(() => live(plan.name, plan.steps));
    const position = plan.position % mind.events.length;
    const base =
      plan.type === "Intent" ? intentBy(mind, plan.created) : locationBy(mind, plan.created);
    const unsigned =
      plan.expires === undefined ? base : { ...base, expires: T(plan.created + plan.expires) };
    const record = mind.sign(unsigned, { key: plan.key, position });
    const proof = record.proof[0];
    const seen: Record<string, string> = seenFor(mind.events, plan.logSeen);
    if (plan.seenAfter !== undefined && proof !== undefined) {
      seen[proofDigest(proof)] = formatTimestamp(at(plan.created + plan.seenAfter));
    }
    return {
      kind: "countsFor",
      name: "generated",
      record: record,
      mind: mind.address,
      extraLogs: [mind.events],
      seen,
    };
  });

describe.skipIf(unavailable !== undefined && !required)("differential: identity logs", () => {
  let judge: PythonJudge;

  beforeAll(() => {
    if (unavailable !== undefined) throw new Error(unavailable);
    judge = new PythonJudge();
  });

  afterAll(async () => {
    await judge.close();
  });

  async function compare(vectorCase: VectorCase): Promise<void> {
    const disagreement = await compareVerdicts(
      referenceAdapter,
      judge,
      vectors,
      vectorCase,
      "same",
    );
    // Shown small: a case holds whole logs.
    expect(
      disagreement === undefined
        ? undefined
        : {
            implementation: disagreement.implementation,
            judge: disagreement.judge,
            judgeError: disagreement.judgeError,
            case: JSON.stringify(vectorCase).slice(0, 6000),
          },
    ).toBeUndefined();
  }

  it("generates logs that verify and logs that do not, of every kind", () => {
    const sample = fc.sample(fc.oneof(keyLogCase, collectiveLogCase, ownKeyCase), {
      numRuns: 300,
      seed: 7,
    });
    const verdicts = sample.map((vectorCase) => {
      const answer =
        vectorCase.kind === "log"
          ? referenceAdapter.logVerifies?.(vectorCase.log, {
              logs: [],
              extraLogs: vectorCase.extraLogs ?? [],
              branches: [],
              records: [],
              extraRecords: [],
              seen: vectorCase.seen,
            })
          : vectorCase.kind === "countsFor"
            ? referenceAdapter.countsFor?.(vectorCase.record, vectorCase.mind, {
                logs: [],
                extraLogs: vectorCase.extraLogs ?? [],
                branches: [],
                records: [],
                extraRecords: [],
                seen: vectorCase.seen,
              })
            : undefined;
      return `${vectorCase.kind} ${String(answer)}`;
    });
    // Neither verdict is rare: a campaign of rejections alone would show nothing.
    for (const outcome of ["log true", "log false", "countsFor true", "countsFor false"]) {
      expect(verdicts.filter((verdict) => verdict === outcome).length, outcome).toBeGreaterThan(15);
    }
  });

  it(
    `agrees with the Python checker on ${RUNS} generated logs of key-controlled minds`,
    async () => {
      await fc.assert(fc.asyncProperty(keyLogCase, compare), { numRuns: RUNS });
    },
    TIMEOUT,
  );

  it(
    `agrees with it on ${Math.ceil(RUNS / 2)} generated logs of collectives`,
    async () => {
      await fc.assert(fc.asyncProperty(collectiveLogCase, compare), {
        numRuns: Math.ceil(RUNS / 2),
      });
    },
    TIMEOUT,
  );

  it(
    `agrees with it on ${Math.ceil(RUNS / 2)} generated records signed by a mind's own keys`,
    async () => {
      await fc.assert(fc.asyncProperty(ownKeyCase, compare), { numRuns: Math.ceil(RUNS / 2) });
    },
    TIMEOUT,
  );
});
