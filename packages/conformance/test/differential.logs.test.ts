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
 *
 * Verdicts are not all that is compared. For the mind each case is about,
 * the two implementations also resolve its DID document, now and at one
 * earlier version, and those must be equal: a state replayed wrongly shows
 * there even where both happen to accept the log.
 */

import { contentId, formatTimestamp, proofDigest } from "@oip/core";
import { draftUpdate } from "@oip/identity";
import {
  agreementKey,
  at,
  Collective,
  intentBy,
  KeyMind,
  lineageBy,
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
  claimHolds,
  type JsonObject,
  loadVectors,
  PythonJudge,
  pythonJudgeUnavailable,
  referenceAdapter,
  type LogCase,
  type VectorCase,
  viewFor,
} from "../src/index.ts";

const unavailable = pythonJudgeUnavailable();
const required = process.env["OIP_REQUIRE_PYTHON"] !== undefined;
// A short campaign with the ordinary tests. `pnpm run ci` sets 6,700, which
// is more than the 10,000 logs BUILD.md asks of every pull request, and the
// nightly job a million. Each test says in its name how many cases it ran.
const RUNS = Number(process.env["OIP_DIFFERENTIAL_LOGS"] ?? 300);
// About 40 ms a case with its DID documents; ten times that, so a slow runner does not fail the campaign.
const TIMEOUT = Math.max(120_000, RUNS * 400);

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
  // A member that is present with the value null is not absent.
  { controller: null },
  { homes: null },
  { keys: null },
  { invocation: null },
  { revoked: null },
  { expires: null },
  { ext: null },
  { critical: null },
  { critical: [] },
  // An event evaluated before, at and after it expires (core 9.6).
  { expires: T(50) },
  { expires: T(3000) },
  { expires: T(100_000) },
  { revoked: [{ key: signer("extra").publicKey, compromisedsince: T(0) }] },
  {
    parents: [
      {
        mind: "did:oip:bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna",
        at: "0-bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna",
      },
    ],
  },
  {
    parents: [
      {
        mind: "did:oip:bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna",
        at: "0-bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna",
        terms: "everything",
      },
    ],
  },
  { homes: ["https://:::"] },
  { homes: ["https://a.example\n"] },
];

type Twist =
  | { readonly kind: "none" | "swap" | "drop" | "repeat" | "truncate" | "wrong key" | "no proofs" }
  | { readonly kind: "unsigned"; readonly member: JsonObject }
  | { readonly kind: "raw"; readonly member: JsonObject }
  | { readonly kind: "purpose" | "intruder revealed" }
  | { readonly kind: "proof dated"; readonly after: number };

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
      // A key the event before did not commit to, revealed and signing correctly (Layer 1, 4.3).
      { kind: "intruder revealed" },
      { kind: "intruder revealed" },
      // The proof's own date against the evidence for its event (core 9.3).
      { kind: "proof dated", after: 300 },
      { kind: "proof dated", after: 301 },
      { kind: "proof dated", after: -5 },
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
    case "intruder revealed": {
      const intruder = signer(`${mind.name}/intruder`);
      const controller = { ...(event["controller"] as JsonObject), keys: [intruder.publicKey] };
      return replaced(rawSign(withMembers(event, { controller }), [{ control: intruder }]));
    }
    case "proof dated": {
      const created = Date.parse(String(event["created"])) / 1000 + change.after;
      return replaced(
        rawSign(event, [{ control: mind.control(i) }], {
          created: formatTimestamp(BigInt(Math.round(created)) * 1_000_000_000n),
        }),
      );
    }
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
    // The view may hold the whole log already: the log asked about takes its place.
    held: fc.constantFrom(false, false, false, false, true),
  })
  .map(({ name, steps, change, pick, seen, held }) => {
    const mind = unchecked(() => live(name, steps));
    const whole = [...mind.events] as unknown as Events;
    const log = unchecked(() => twisted(mind, change, pick));
    return {
      kind: "log",
      name: "generated",
      log,
      ...(held ? { extraLogs: [whole] } : {}),
      seen: seenFor(log, seen),
    };
  });

/**
 * A `log` case about a collective: up to three people found it, and it lives
 * through updates signed by some of them, while one of them changes or
 * retires its own keys. Evidence may place any event at another time.
 */
const collectiveLogCase: fc.Arbitrary<VectorCase> = fc
  .record({
    size: fc.constantFrom(1, 2, 3),
    // Mostly a majority: a threshold that is not one is a single rule, and needs few cases.
    threshold: fc.constantFrom(3, 3, 3, 3, 3, 2, 2, 1),
    height: fc.constantFrom(undefined, undefined, undefined, undefined, 1, 1, 2, 5),
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
    founders: fc.constantFrom("all", "all", "all", "all", "fewer", "operational", "for another"),
    seen: seenPicks,
    memberSeen: seenPicks,
    // One case in three is sound by construction, so that logs both accept are not all short ones.
    sound: fc.constantFrom(false, false, true),
  })
  .map((drawn) =>
    unchecked(() => {
      const plan = !drawn.sound
        ? drawn
        : {
            ...drawn,
            threshold: 3,
            height: undefined,
            memberSteps: [],
            updates: drawn.updates.map((update) => ({ ...update, signers: [0, 1, 2, 3] })),
            founders: "all",
            seen: [],
            memberSeen: [],
          };
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
      } else if (plan.founders === "for another") {
        // One founder's proof names an authority: it is made as a delegate, and is not the member's own (Layer 1, 6.4).
        const { proof: _, ...genesis } = club.events[0] as unknown as JsonObject;
        const [delegate, ...others] = members as [KeyMind, ...KeyMind[]];
        const authority = [`${delegate.address}/${contentId(delegate.events[0])}`];
        club.events[0] = {
          ...genesis,
          proof: [
            ...rawSign(genesis, [delegate.asMember()], { authority }).proof,
            ...rawSign(
              genesis,
              others.map((member) => member.asMember()),
            ).proof,
          ],
        } as never;
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

// Most cases have neither: each is one rule, and needs few cases.
const NO_COPY = Array.from({ length: 5 }, () => undefined);
const NO_EXTENSION = Array.from({ length: 6 }, () => undefined);
const NO_EARLIER = Array.from({ length: 7 }, () => undefined);

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
    // core 8.3: an extension nobody implements, which the record may list in `critical`.
    extension: fc.constantFrom(...NO_EXTENSION, "critical", "not critical"),
    // The view may be given an earlier state of the log after the log itself, which then replaces it.
    earlier: fc.constantFrom(...NO_EARLIER, 1, 2),
  })
  .map((plan) => {
    const mind = unchecked(() => live(plan.name, plan.steps));
    const position = plan.position % mind.events.length;
    const base =
      plan.type === "Intent" ? intentBy(mind, plan.created) : locationBy(mind, plan.created);
    const unsigned = {
      ...base,
      ...(plan.expires === undefined ? {} : { expires: T(plan.created + plan.expires) }),
      ...(plan.extension === undefined ? {} : { ext: { "com.example.escrow": { v: "1" } } }),
      ...(plan.extension === "critical" ? { critical: ["com.example.escrow"] } : {}),
    };
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
      extraLogs:
        plan.earlier === undefined
          ? [mind.events]
          : [mind.events, mind.events.slice(0, plan.earlier)],
      seen,
    };
  });

/** A collective, founded soundly if its members allow, and otherwise signed as it stands. */
function founded(
  name: string,
  members: readonly Mind[],
  threshold: number,
  seconds: number,
  fields: JsonObject = {},
): Collective {
  try {
    return new Collective(name, members, threshold, seconds, fields);
  } catch {
    const sound = new Collective(name, members, members.length, seconds);
    sound.events[0] = rawSign(
      withMembers(sound.events[0] as unknown as JsonObject, {
        ...fields,
        controller: { members: members.map((member) => member.address), threshold },
      }),
      members.map((member) => member.asMember()),
    ) as never;
    return sound;
  }
}

const majority = (count: number): number => Math.floor(count / 2) + 1;

/**
 * A `log` case about a collective that has collectives among its members:
 * the heights of Layer 1, 4.7, declared or not, at the founding and when a
 * member is admitted later.
 */
const nestedLogCase: fc.Arbitrary<VectorCase> = fc
  .record({
    innerHeight: fc.constantFrom(undefined, undefined, 1, 2, 3),
    innerSize: fc.constantFrom(1, 2),
    outerHeight: fc.constantFrom(undefined, undefined, 1, 2, 3, 4),
    founders: fc.constantFrom("inner", "inner and a person", "a person", "deep"),
    admit: fc.constantFrom(undefined, "inner", "second", "deep", "a person"),
    secondHeight: fc.constantFrom(undefined, 2, 3, 4),
    admitSigners: fc.constantFrom("all", "all", "not the newcomer"),
  })
  .map((plan) =>
    unchecked(() => {
      const [ada, bea, cy, dee] = ["ada", "bea", "cy", "dee"].map(
        (name) => new KeyMind(name, 0),
      ) as [KeyMind, KeyMind, KeyMind, KeyMind];
      const inner = founded(
        "inner",
        [ada, bea].slice(0, plan.innerSize),
        plan.innerSize,
        100,
        plan.innerHeight === undefined ? {} : { height: plan.innerHeight },
      );
      const second = founded(
        "second",
        [cy],
        1,
        100,
        plan.secondHeight === undefined ? {} : { height: plan.secondHeight },
      );
      const deep = founded("deep", [inner], 1, 150);
      const pick: Record<string, Mind> = { inner, second, deep, "a person": dee };
      const first: Mind[] =
        plan.founders === "inner and a person"
          ? [inner, dee]
          : plan.founders === "a person"
            ? [cy]
            : [plan.founders === "deep" ? deep : inner];
      const outer = founded(
        "outer",
        first,
        first.length,
        200,
        plan.outerHeight === undefined ? {} : { height: plan.outerHeight },
      );
      const newcomer = plan.admit === undefined ? undefined : pick[plan.admit];
      if (newcomer !== undefined && !first.includes(newcomer)) {
        const members = [...first, newcomer];
        try {
          outer.update(300, plan.admitSigners === "all" ? members : first, {
            controller: {
              members: members.map((member) => member.address),
              threshold: majority(members.length),
            },
          });
        } catch {
          // An event that cannot be drafted is not written.
        }
      }
      return {
        kind: "log",
        name: "generated",
        log: outer.events,
        extraLogs: [ada, bea, cy, dee, inner, second, deep].map(
          (mind) => mind.events as unknown as Events,
        ),
      };
    }),
  );

/**
 * A `countsFor` case about a mind whose log the verifier holds in two or
 * three branches (Layer 1, Section 7): they share some events and then part.
 * One branch may end in an event that does not verify. The evidence for the
 * events where they part ties them or separates them, and the record is
 * pinned to an event of one of them.
 */
/** Changes that leave a log valid whatever came before, and one that removes the first key. */
const CALM = [
  "nothing",
  "homes",
  "aliases",
  "another agreement key",
  "a second operational key",
  "no operational key",
] as const;

const calmStep: fc.Arbitrary<Step> = fc.record({
  kind: fc.constantFrom("update", "update", "update", "update", "fork"),
  gap: fc.constantFrom(1, 60, 3600),
  change: fc.constantFrom(...CALM),
});

const branchCase: fc.Arbitrary<VectorCase> = fc
  .record({
    name: names,
    shared: fc.array(calmStep, { maxLength: 2 }),
    // The branches part with events of one date, so that only evidence can tell them apart.
    partAfter: fc.constantFrom(1, 60, 3600),
    tails: fc.array(
      fc.record({
        kind: fc.constantFrom("update", "update", "update", "retire"),
        change: fc.constantFrom(...CALM),
        then: fc.array(calmStep, { maxLength: 1 }),
      }),
      { minLength: 2, maxLength: 3 },
    ),
    junk: fc.constantFrom(undefined, undefined, undefined, undefined, 0, 1),
    // A further copy of one branch: with an invalid event after it, cut short, with the
    // proofs of its last event lost, or with a `proof` that is not well formed on its last
    // event or on the one before. None is another branch, and none takes anything away
    // (Layer 1, 4.9, 7.1).
    again: fc.constantFrom(
      ...NO_COPY,
      "junk after",
      "cut short",
      "proofs lost",
      "proofs spoiled",
      "proofs spoiled",
      "spoiled before",
      "spoiled before",
    ),
    againOf: fc.nat(2),
    spoiling: fc.constantFrom(
      "an entry that is no object",
      "an entry that is no object",
      "an entry that is not plain data",
      "no entry",
      "no list",
    ),
    seenAfter: fc.array(fc.constantFrom(0, 0, 0, 0, 1, 7, 200), { minLength: 3, maxLength: 3 }),
    branch: fc.nat(2),
    position: fc.nat(6),
    key: fc.constantFrom(0, 0, 0, 1),
    type: fc.constantFrom("Intent", "Intent", "Location"),
    created: fc.constantFrom(150, 170, 3800, 9000, 20_000),
  })
  .map((plan) =>
    unchecked(() => {
      const branches = plan.tails.map(({ kind, change, then }) =>
        live(plan.name, [
          ...plan.shared,
          { kind, gap: plan.partAfter, change },
          // Nothing follows a Retire.
          ...(kind === "retire" ? [] : then),
        ]),
      );
      const fork = 1 + plan.shared.length;
      const seen: Record<string, string> = {};
      branches.forEach((branch, n) => {
        const event = branch.events[fork] as unknown as JsonObject | undefined;
        if (event === undefined) return;
        const created = BigInt(Date.parse(String(event["created"]))) * 1_000_000n;
        seen[contentId(event)] = formatTimestamp(
          created + BigInt(plan.seenAfter[n] ?? 0) * 1_000_000_000n,
        );
      });
      const signer = branches[plan.branch % branches.length]!;
      const base =
        plan.type === "Intent" ? intentBy(signer, plan.created) : locationBy(signer, plan.created);
      const record = signer.sign(base, {
        key: plan.key,
        position: plan.position % signer.events.length,
      });
      // Signed before the junk is added: an event that does not verify is no version to pin.
      if (plan.junk !== undefined) branches[plan.junk]?.raw(30_000, "Merge");
      const whole = branches.map((branch) => branch.events as unknown as Events);
      const which = plan.againOf % branches.length;
      const copied = whole[which] ?? [];
      const last = copied.at(-1) as (JsonObject & { proof: JsonObject[] }) | undefined;
      /** The event with a `proof` that core 5.1 does not allow: the copy adds no proof to it. */
      const spoiled = (event: JsonObject & { proof: JsonObject[] }) => ({
        ...event,
        proof:
          plan.spoiling === "an entry that is no object"
            ? [...event.proof, "no proof"]
            : plan.spoiling === "an entry that is not plain data"
              ? [...event.proof, { n: 1.5 }]
              : plan.spoiling === "no entry"
                ? []
                : (event.proof[0] ?? null),
      });
      const spoiledAt = (index: number) =>
        copied.map((event, i) =>
          i === index ? spoiled(event as unknown as JsonObject & { proof: JsonObject[] }) : event,
        ) as Events;
      const again: Events[] =
        plan.again === undefined || last === undefined
          ? []
          : plan.again === "junk after"
            ? [[...copied, { junk: true }] as Events]
            : plan.again === "cut short"
              ? [copied.slice(0, -1)]
              : plan.again === "proofs spoiled"
                ? [spoiledAt(copied.length - 1)]
                : plan.again === "spoiled before"
                  ? [spoiledAt(copied.length - 2)]
                  : [
                      [
                        ...copied.slice(0, -1),
                        {
                          ...last,
                          proof: last.proof.map((proof) => ({ ...proof, proofValue: "z1111" })),
                        },
                      ] as Events,
                    ];
      // The copy spoiled before its end is then the only one with the last event: the
      // branch itself is held without it. The event spoiled is the one that copy shows
      // whole, so the last event has its place (Layer 1, 7.1).
      if (plan.again === "spoiled before" && copied.length > 1) whole[which] = copied.slice(0, -1);
      const [first, ...others] = whole;
      return {
        kind: "countsFor",
        name: "generated",
        record,
        mind: signer.address,
        extraLogs: [first ?? []],
        branches: [...others, ...again.filter((copy) => copy.length > 0)],
        seen,
      };
    }),
  );

/**
 * Sets of copies of one mind's log, made by hand: what a verifier may come to
 * hold of a log from several sources (Layer 1, 4.9, 7.1, 7.3). Each asks
 * whether a record counts, and says what the answer is. Most came from the
 * independent reviews of the log book, as cases one implementation got wrong
 * or the two answered differently.
 */
function copiesByHand(): { readonly counts: boolean; readonly vectorCase: VectorCase }[] {
  type Any = JsonObject & { proof: JsonObject[] };
  type Copies = readonly (readonly unknown[])[];
  // A key-controlled mind that removes its operational key at 20.
  const ada = new KeyMind("h-ada").update(10).update(20, { keys: [] });
  const [g, u1, rm] = ada.events as unknown as [Any, Any, Any];
  const [good] = rm.proof as [JsonObject];
  /** Signed with the removed key after the removal: counts if, and only if, the removal is not in the log. */
  const late = ada.sign(intentBy(ada, 25), { position: 1 });
  /** Signed and seen before the removal: counts whenever version 1 is in a log that verifies. */
  const early = ada.sign(intentBy(ada, 15), { position: 1 });
  const withProof = (event: JsonObject, proof: unknown) => ({ ...event, proof });
  /** A proof that is an object, verifies nothing, and is as large as asked. */
  const big = (tag: string, size: number) => ({ ...good, "@context": tag + "x".repeat(size) });
  const numbered = (from: number, count: number) =>
    Array.from({ length: count }, (_, n) => ({ ...good, n: from + n }));
  const rivals = Array.from({ length: 9 }, (_, n) =>
    new KeyMind("h-ada").update(10).update(21 + n, { homes: [`https://r${n}.example`] }),
  );
  const tied = [0, 1].map((n) =>
    new KeyMind("h-ada").update(10).update(20, { homes: [`https://t${n}.example`] }),
  ) as [KeyMind, KeyMind];
  const tiedOn = [0, 1].map((n) =>
    new KeyMind("h-ada")
      .update(10)
      .update(20, { homes: ["https://t0.example"] })
      .update(30 + n, { homes: [`https://later${n}.example`] }),
  );
  const third = new KeyMind("h-ada").update(10).update(21, { homes: ["https://third.example"] });
  const MERGE = { oip: "1", type: "Merge" };
  const junkWithProofs = { oip: "1", type: "Update", junk: true, proof: [] };

  /** An object nested as deep as asked. As an entry of `proof`, it stands at depth 3 of its event. */
  const nested = (depth: number): unknown => (depth === 1 ? {} : { in: nested(depth - 1) });
  // `{"pad":"…"}` is ten bytes and the string.
  const sized = (bytes: number) => ({ pad: "x".repeat(bytes - 10) });

  const own: [string, boolean, Copies, (Copies | undefined)?, object?][] = [
    ["the log alone", false, [ada.events]],
    // 7.1: a copy of an event that is not well formed adds no proof and takes none away.
    [
      "the log, and a copy whose removal has a string beside its proof",
      false,
      [ada.events],
      [[g, u1, withProof(rm, [good, "junk"])]],
    ],
    [
      "a copy whose removal has only a string for proof, and the log",
      false,
      [[g, u1, withProof(rm, ["junk"])]],
      [ada.events],
    ],
    [
      "the log, and a copy whose removal has null for a proof",
      false,
      [ada.events],
      [[g, u1, withProof(rm, [null])]],
    ],
    [
      "the log, and a copy whose removal has a proof of 1.1 MB beside its own",
      false,
      [ada.events],
      [[g, u1, withProof(rm, [good, big("a", 1_100_000)])]],
    ],
    [
      "a copy whose removal has a string beside its proof, alone",
      true,
      [[g, u1, withProof(rm, [good, "junk"])]],
    ],
    [
      "the log cut short, and a later copy whose second event has a string beside its proof",
      false,
      [[g, u1]],
      [[g, withProof(u1, [...u1.proof, "junk"]), rm]],
    ],
    ...(
      [
        ["a number out of range", { n: 2 ** 60 }],
        ["a number that is no integer", { n: 1.5 }],
        ["a lone surrogate", { text: "\ud800" }],
        ["65 levels of nesting", nested(63)],
        ["64 levels of nesting", nested(62)],
      ] as const
    ).map(([what, entry]): [string, boolean, Copies, Copies] => [
      `the log cut short, and a later copy whose second event has a proof entry with ${what}`,
      false,
      [[g, u1]],
      [[g, withProof(u1, [...u1.proof, entry]), rm]],
    ]),
    [
      "a copy whose genesis has no proofs, alone",
      false,
      [[withProof(g, []), u1, rm]],
      undefined,
      early,
    ],
    [
      "a copy whose genesis has a proof entry that is not plain data, and the genesis",
      false,
      [[withProof(g, [...g.proof, { n: 1.5 }]), u1, rm]],
      [[g]],
    ],
    [
      "a copy whose genesis has no proofs, and the genesis",
      false,
      [[withProof(g, []), u1, rm]],
      [[g]],
    ],
    // 7.1: the proofs of well-formed copies, together more than one record carries.
    [
      "two copies, each within 1 MiB, whose proofs together are not",
      false,
      [[g, u1, withProof(rm, [good, big("a", 600_000)])]],
      [[g, u1, withProof(rm, [good, big("b", 600_000)])]],
      early,
    ],
    [
      "one copy with a proof of 600 kB beside its own",
      true,
      [[g, u1, withProof(rm, [good, big("a", 600_000)])]],
      undefined,
      early,
    ],
    [
      "two copies whose removal has 256 proofs between them",
      true,
      [[g, u1, withProof(rm, [good, ...numbered(0, 127)])]],
      [[g, u1, withProof(rm, numbered(127, 128))]],
      early,
    ],
    [
      "two copies whose removal has 257 proofs between them",
      false,
      [[g, u1, withProof(rm, [good, ...numbered(0, 127)])]],
      [[g, u1, withProof(rm, numbered(127, 129))]],
      early,
    ],
    [
      "the log, and a copy with the proof twice",
      false,
      [ada.events],
      [[g, u1, withProof(rm, [good, good])]],
    ],
    // What a copy shows after a value that is not the event of that place.
    [
      "the log, and a copy with an odd value and then the removal",
      false,
      [ada.events],
      [[g, u1, { odd: true }, rm]],
    ],
    [
      "a copy with an odd value and then the removal, and the log cut short",
      true,
      [[g, u1, { odd: true }, rm]],
      [[g, u1]],
    ],
    [
      "an invalid event with a proof list, then the log's events; and the log cut short",
      true,
      [[g, junkWithProofs, u1, rm]],
      [[g, u1]],
    ],
    // 7.3: any number of events for one position, and of copies that end in junk.
    [
      "the log and eight rivals for position 2, all seen later",
      true,
      [ada.events],
      rivals.slice(0, 8).map((rival) => rival.events),
      early,
    ],
    [
      "the log and nine rivals for position 2, all seen later",
      false,
      [ada.events],
      rivals.map((rival) => rival.events),
    ],
    [
      "the log, and nine copies of it each with other junk after",
      true,
      [ada.events],
      Array.from({ length: 9 }, (_, n) => [...ada.events, { junk: n }]),
      early,
    ],
    // 7.3: events the evidence cannot separate.
    ["two events tied at position 2", true, [tied[0].events], [tied[1].events], early],
    ["two tied at position 2, one of them the removal", false, [ada.events], [tied[0].events]],
    [
      "tied at 2, and one of the tied goes on in two ways",
      true,
      [tied[1].events],
      tiedOn.map((branch) => branch.events),
      early,
    ],
    [
      "tied at 2, and one tied branch ends in an event nobody can read",
      false,
      [tied[1].events],
      [[...tied[0].events, MERGE]],
      early,
    ],
    [
      "tied at 2, and one tied branch ends in junk",
      true,
      [tied[1].events],
      [[...tied[0].events, { junk: true }]],
      early,
    ],
    [
      "two tied at 2, and a third seen later whose copy goes on to an event nobody can read",
      false,
      [tied[0].events],
      [tied[1].events, [...third.events, MERGE]],
      early,
    ],
    [
      "two tied at 2, and a third seen later",
      true,
      [tied[0].events],
      [tied[1].events, third.events],
      early,
    ],
    [
      "the removal has position 2; a rival seen later goes on to an event nobody can read",
      false,
      [ada.events],
      [[...(rivals[0]?.events ?? []), MERGE]],
    ],
    [
      "the removal, and beside it at position 2 an event nobody can read",
      false,
      [ada.events],
      [[g, u1, MERGE]],
      early,
    ],
  ];

  // A collective of three, threshold two, that removes its operational key at 20.
  const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(`h-${name}`)) as [
    KeyMind,
    KeyMind,
    KeyMind,
  ];
  const founded = () => new Collective("h-club", [a, b, c], 2, 5);
  const club = founded().update(10, [a, b], { homes: ["https://club.example"] });
  const rivalAtOne = founded().update(11, [a, b], { homes: ["https://rival.example"] });
  const [c0, c1] = club.events as unknown as [Any, Any];
  const c1x = rivalAtOne.events[1];
  const removal = draftUpdate(club.head, T(20), { keys: [] });
  const c2 = (...members: KeyMind[]) =>
    rawSign(
      removal,
      members.map((member) => member.asMember()),
    ) as unknown as Any;
  const strangers = rawSign(removal, [
    { member: a.address, versionId: a.versionId(), invocation: signer("h-fake/0") },
    { member: b.address, versionId: b.versionId(), invocation: signer("h-fake/1") },
  ]);
  const clubLate = club.sign(intentBy(club, 25), { position: 1 });
  const members = [a.events, b.events, c.events];

  const clubs: [string, boolean, Copies][] = [
    ["a collective's log", false, [[c0, c1, c2(a, b)]]],
    [
      "a collective's removal in two halves",
      false,
      [
        [c0, c1, c2(a)],
        [c0, c1, c2(b)],
      ],
    ],
    ["one half of a collective's removal, alone", true, [[c0, c1, c2(a)]]],
    [
      "a collective's removal in three copies with overlapping proofs",
      false,
      [
        [c0, c1, c2(a)],
        [c0, c1, c2(a, b)],
        [c0, c1, c2(b, c)],
      ],
    ],
    // 7.1: the proofs of an event count for it wherever in a copy it stands.
    [
      "one half after the event that has position 1, the other half after its rival",
      false,
      [
        [c0, c1, c2(a)],
        [c0, c1x, c2(b)],
      ],
    ],
    [
      "one half in its place, the other half after an invalid event with a proof list",
      false,
      [
        [c0, c1, c2(a)],
        [c0, junkWithProofs, c2(b)],
      ],
    ],
    [
      "one half in its place, the other half after an odd value",
      false,
      [
        [c0, c1, c2(a)],
        [c0, { odd: true }, c2(b)],
      ],
    ],
    [
      "a collective's removal under keys that are not the members', and with the members' own",
      false,
      [
        [c0, c1, strangers],
        [c0, c1, c2(a, b)],
      ],
    ],
    // 7.1: which values in a copy have a place. One half of the removal is in its place,
    // and the other half comes after another value: is that copy held past the value?
    ...(
      [
        ["an empty object", false, {}],
        ["an object nested 64 deep", false, nested(64)],
        ["an object of exactly 1 MiB", false, sized(1_048_576)],
        ["the number 5", true, 5],
        ["null", true, null],
        ["a string", true, "an event"],
        ["a list", true, [c1]],
        ["an object nested 65 deep", true, nested(65)],
        ["an object of one byte more than 1 MiB", true, sized(1_048_577)],
        ["an object of 600,000 values", true, { pad: Array.from({ length: 600_000 }, () => 0) }],
        ["an object with a number that is no integer", true, { n: 1.5 }],
      ] as const
    ).map(([what, counts, value]): [string, boolean, Copies] => [
      `one half in its place, the other half after ${what}`,
      counts,
      [
        [c0, c1, c2(a)],
        [c0, value, c2(b)],
      ],
    ]),
    [
      "one half in its place, the other half after 10,001 objects that are no events",
      false,
      [
        [c0, c1, c2(a)],
        [c0, ...Array.from({ length: 10_001 }, (_, n) => ({ n })), c2(b)],
      ],
    ],
    [
      "one half in its place, the other half after an object and then an event nobody can read that is larger than a record",
      true,
      [
        [c0, c1, c2(a)],
        [c0, { junk: true }, { oip: "1", type: "Merge", pad: "x".repeat(1_100_000) }, c2(b)],
      ],
    ],
    [
      "a collective's event with a proof entry holding a number out of range, the removal after it, and the event whole in another copy",
      false,
      [
        [c0, c1],
        [c0, withProof(c1, [...c1.proof, { n: 2 ** 60 }]), c2(a, b)],
      ],
    ],
    [
      "a collective's log, and a copy with an event nobody can read that is larger than a record",
      false,
      [
        [c0, c1, c2(a, b)],
        [c0, c1, { oip: "1", type: "Merge", pad: "x".repeat(1_100_000) }],
      ],
    ],
    [
      "a collective's log, and a copy that shows one object three times with more proofs than a record carries",
      false,
      [
        [c0, c1, c2(a, b)],
        [
          c0,
          c1,
          ...Array.from({ length: 3 }, (_, n) => ({
            junk: true,
            proof: [{ n, pad: "x".repeat(600_000) }],
          })),
        ],
      ],
    ],
    [
      "a collective's log, and a copy whose removal has a number among its proofs",
      false,
      [
        [c0, c1, c2(a, b)],
        [c0, c1, withProof(c2(a, b), [...c2(a, b).proof, 7])],
      ],
    ],
  ];

  return [
    ...own.map(([name, counts, extraLogs, branches, record]) => ({
      counts,
      vectorCase: {
        kind: "countsFor",
        name,
        record: record ?? late,
        mind: ada.address,
        extraLogs,
        branches: branches ?? [],
      } as unknown as VectorCase,
    })),
    ...clubs.map(([name, counts, copies]) => ({
      counts,
      vectorCase: {
        kind: "countsFor",
        name,
        record: clubLate,
        mind: club.address,
        extraLogs: [copies[0], ...members],
        branches: copies.slice(1),
      } as unknown as VectorCase,
    })),
  ];
}

const CLUB_CHANGES = ["nothing", "expel", "admit", "tighten", "retire"] as const;

/** A collective of ada, bea and cy that lives through some changes, each signed by everyone it needs. */
function club(
  people: readonly KeyMind[],
  threshold: number,
  changes: readonly { readonly gap: number; readonly change: (typeof CLUB_CHANGES)[number] }[],
): Collective {
  const group = new Collective("club", people.slice(0, 3), threshold, 200);
  let current = people.slice(0, 3);
  let when = 200;
  for (const { gap, change } of changes) {
    when += gap;
    try {
      if (change === "retire") {
        group.retire(when, current);
      } else if (change === "nothing") {
        group.update(when, current, { homes: ["https://club.example"] });
      } else {
        const next =
          change === "expel" && current.length > 1
            ? current.slice(0, -1)
            : change === "admit"
              ? [...new Set([...current, people[3]!])]
              : current;
        group.update(when, [...new Set([...current, ...next])], {
          controller: {
            members: next.map((member) => member.address),
            threshold: change === "tighten" ? next.length : majority(next.length),
          },
        });
        current = next;
      }
    } catch {
      // An event that cannot be drafted is not written.
    }
  }
  return group;
}

/**
 * A `countsFor` case about a record signed under a collective's threshold
 * (Layer 1, 9.5): some of four people sign it, at one time or at two, while
 * the collective's members and threshold change, or it retires. The verifier
 * may hold a second event for the collective's last position (Layer 1, 7.3).
 */
const collectiveSignedCase: fc.Arbitrary<VectorCase> = fc
  .record({
    threshold: fc.constantFrom(2, 2, 2, 3),
    changes: fc.array(
      fc.record({
        gap: fc.constantFrom(10, 100, 1000),
        change: fc.constantFrom(...CLUB_CHANGES),
      }),
      { maxLength: 2 },
    ),
    other: fc.constantFrom(undefined, undefined, ...CLUB_CHANGES),
    otherSeenAfter: fc.constantFrom(0, 0, 60),
    signers: fc.subarray([0, 1, 2, 3], { minLength: 1 }),
    created: fc.constantFrom(150, 205, 210, 250, 300, 310, 1200, 1300, 5000),
    stagger: fc.constantFrom(0, 0, 0, 10, 100, 1100),
    // A Hello is signed by its author's own key, never under a threshold (Layer 1, 9.5).
    type: fc.constantFrom("Intent", "Intent", "Intent", "Location", "Hello"),
    expires: fc.constantFrom(undefined, undefined, undefined, 50),
    // The collective's own operational key signs as well.
    own: fc.constantFrom(false, false, false, true),
    // The collective's log is held in two copies, each with some of the proofs of its last
    // event: together they are the event (Layer 1, 7.1).
    split: fc.constantFrom(false, false, false, true),
  })
  .map((plan) =>
    unchecked(() => {
      const people = ["ada", "bea", "cy", "dee"].map((name) => new KeyMind(name, 0));
      const group = club(people, plan.threshold, plan.changes);
      const seen: Record<string, string> = {};
      const branches: Events[] = [];
      const last = plan.changes.at(-1);
      if (plan.other !== undefined && last !== undefined) {
        // The same history, with another event in the place of the last one.
        const alternative = club(people, plan.threshold, [
          ...plan.changes.slice(0, -1),
          { gap: last.gap, change: plan.other },
        ]);
        const event = alternative.events.at(-1) as unknown as JsonObject;
        const created = BigInt(Date.parse(String(event["created"]))) * 1_000_000n;
        seen[contentId(event)] = formatTimestamp(
          created + BigInt(plan.otherSeenAfter) * 1_000_000_000n,
        );
        branches.push(alternative.events);
      }
      const base =
        plan.type === "Intent"
          ? intentBy(group, plan.created)
          : plan.type === "Location"
            ? locationBy(group, plan.created)
            : { oip: "1", type: "Hello", author: group.address, created: T(plan.created) };
      // A Hello's proof answers a challenge for a host (core 11).
      const more =
        plan.type === "Hello"
          ? { challenge: "q8xG3kZ2pV7mT0wR5nY1aB", domain: "https://host.example" }
          : {};
      let record: object =
        plan.expires === undefined ? base : { ...base, expires: T(plan.created + plan.expires) };
      plan.signers.forEach((n, order) => {
        record = people[n]!.sign(record, {
          created: T(plan.created + (order === 0 ? 0 : plan.stagger)),
          more,
        });
      });
      if (plan.own) record = group.sign(record, { more });
      const whole = group.events as unknown as Events;
      const tail = whole.at(-1) as (JsonObject & { proof: JsonObject[] }) | undefined;
      const halves =
        plan.split && tail !== undefined && whole.length > 1 && tail.proof.length > 1
          ? [tail.proof.slice(0, 1), tail.proof.slice(1)].map(
              (proof) => [...whole.slice(0, -1), { ...tail, proof }] as Events,
            )
          : undefined;
      return {
        kind: "countsFor",
        name: "generated",
        record: record as JsonObject,
        mind: group.address,
        extraLogs: [
          halves?.[0] ?? whole,
          ...people.map((mind) => mind.events as unknown as Events),
        ],
        branches: [...branches, ...(halves === undefined ? [] : [halves[1] ?? []])],
        seen,
      };
    }),
  );

/**
 * A lineage (Layer 1, Section 8): a child that names a version of its parent,
 * and a parent that acknowledges it with a `Fork` event, with a `Lineage`
 * record, with a record somebody else signed, or not at all.
 */
const lineageQuestion = fc
  .record({
    name: names,
    steps: fc.array(step, { maxLength: 2 }),
    at: fc.nat(4),
    acknowledged: fc.constantFrom("not", "by a fork", "by a record", "by a stranger's record"),
    again: fc.array(step, { maxLength: 1 }),
  })
  .map((plan) =>
    unchecked(() => {
      const parent = live(plan.name, plan.steps);
      const child = new KeyMind("kid", 50, {
        parents: [{ mind: parent.address, at: parent.versionId(plan.at % parent.events.length) }],
      });
      const stranger = new KeyMind("stranger", 0);
      const records: object[] = [];
      if (plan.acknowledged === "by a fork") parent.fork(20_000, { child: child.address });
      if (plan.acknowledged === "by a record") {
        records.push(parent.sign(lineageBy(parent, child.address, 20_000)));
      }
      if (plan.acknowledged === "by a stranger's record") {
        records.push(stranger.sign(lineageBy(parent, child.address, 20_000)));
      }
      // The parent's log may go on afterwards, and remove the key that signed.
      let seconds = 30_000;
      for (const { kind, gap, change } of plan.again) {
        seconds += gap;
        if (kind === "retire") parent.retire(seconds, fieldsFor(parent, change, seconds));
        else parent.update(seconds, fieldsFor(parent, change, seconds));
      }
      return {
        kind: "lineage",
        name: "generated",
        mind: child.address,
        extraLogs: [parent, child, stranger].map((mind) => mind.events as unknown as Events),
        extraRecords: records as JsonObject[],
      };
    }),
  );

/** The mind a case is about, and the logs a verifier must hold to resolve it. */
function subjectOf(
  vectorCase: VectorCase,
): { mind: string; logs: Events[]; own: Events } | undefined {
  try {
    if (vectorCase.kind === "log") {
      const own = vectorCase.log as Events;
      return {
        mind: `did:oip:${contentId(own[0] ?? {})}`,
        logs: [...((vectorCase.extraLogs ?? []) as Events[]), own],
        own,
      };
    }
    if (vectorCase.kind === "countsFor") {
      const logs = (vectorCase.extraLogs ?? []) as Events[];
      const own = logs.find((log) => `did:oip:${contentId(log[0] ?? {})}` === vectorCase.mind);
      return own === undefined ? undefined : { mind: vectorCase.mind, logs, own };
    }
  } catch {
    // A first event with no content ID names no mind.
  }
  return undefined;
}

// A mutation run leaves the campaign out. Nearly every mutant of
// `@oip/identity` is covered by it, so each would wait for the Python checker
// on every case, and the unit tests are what a mutant has to get past.
const measured = process.env["OIP_MUTATION"] !== undefined;

describe.skipIf((unavailable !== undefined && !required) || measured)(
  "differential: identity logs",
  () => {
    let judge: PythonJudge;
    /** What was compared, by generator: how many cases, and how many both implementations accepted. */
    const tally = new Map<
      string,
      { cases: number; accepted: number; documents: number; intakes: number }
    >();

    beforeAll(() => {
      if (unavailable !== undefined) throw new Error(unavailable);
      judge = new PythonJudge();
    });

    afterAll(async () => {
      await judge.close();
      for (const [generator, { cases, accepted, documents, intakes }] of tally) {
        // For the log of the run: the numbers that ran, whatever was asked for.
        process.stdout.write(
          `differential, ${generator}: ${cases} cases compared, ${accepted} accepted by both; ${documents} DID documents resolved by both and equal; ${intakes} copies classed alike where an event failed\n`,
        );
      }
    });

    // Shown small: a case holds whole logs.
    const shown = (value: unknown): string => JSON.stringify(value).slice(0, 6000);

    /** The DID document of a case's mind, now or at one version, must be the same for both. */
    async function sameDocument(
      vectorCase: VectorCase,
      pick: number | undefined,
    ): Promise<boolean> {
      const subject = subjectOf(vectorCase);
      if (subject === undefined) return false;
      let versionId: string | undefined;
      if (pick !== undefined) {
        const position = pick % subject.own.length;
        try {
          versionId = `${position}-${contentId(subject.own[position] ?? {})}`;
        } catch {
          return false;
        }
      }
      const question = {
        kind: "didDocument",
        name: "generated",
        mind: subject.mind,
        ...(versionId === undefined ? {} : { versionId }),
        extraLogs: subject.logs,
        branches: vectorCase.branches ?? [],
        seen: vectorCase.seen,
      };
      const ours = referenceAdapter.didDocument?.(subject.mind, versionId, {
        ...viewFor(vectors, vectorCase),
        extraLogs: subject.logs,
      });
      const theirs = await judge.judge(question);
      expect(
        // A document compares as JSON: the checker's answer has been through it.
        JSON.parse(JSON.stringify(ours ?? null)),
        `the DID document${versionId === undefined ? "" : ` at ${versionId}`} of ${shown(question)}`,
      ).toStrictEqual(theirs.error === undefined ? theirs.value : null);
      return ours !== undefined;
    }

    /**
     * Layer 1, 4.9: how far the log of a case verifies, and whether the
     * event after that is invalid or undecided, must be the same for both.
     * The checker answers from the text of 4.9, apart from its own
     * verification of the log.
     *
     * @returns Whether an event failed, so that there was a class to compare.
     */
    async function sameIntake(vectorCase: LogCase): Promise<boolean> {
      const ours = referenceAdapter.logIntake?.(vectorCase.log, viewFor(vectors, vectorCase));
      const theirs = await judge.judge({ ...vectorCase, kind: "intake" });
      expect(
        ours,
        `how far it verifies, and the class of the next event: ${shown(vectorCase)}`,
      ).toStrictEqual(theirs.error === undefined ? theirs.value : null);
      return ours?.undecided !== null;
    }

    /**
     * @param document - Which DID document to compare as well: 0 the current
     *   one, 1 the one at a version chosen by `pick`, anything else none. A
     *   document costs as much as the verdict, so one case in four has one.
     */
    async function compare(
      generator: string,
      vectorCase: VectorCase,
      pick: number,
      document: number,
    ): Promise<void> {
      const ours = claimHolds(referenceAdapter, vectors, vectorCase);
      // Every case generated here is one the reference implementation judges.
      expect(ours, `not judged: ${shown(vectorCase)}`).toBeDefined();
      const theirs = await judge.judge(vectorCase);
      expect(
        { implementation: ours, judge: theirs.holds, judgeError: theirs.error },
        shown(vectorCase),
      ).toMatchObject({ implementation: theirs.holds });
      const counted = tally.get(generator) ?? { cases: 0, accepted: 0, documents: 0, intakes: 0 };
      tally.set(generator, counted);
      counted.cases++;
      if (ours === true) counted.accepted++;
      if (vectorCase.kind === "log" && (await sameIntake(vectorCase))) counted.intakes++;
      if (document > 1) return;
      if (await sameDocument(vectorCase, document === 0 ? undefined : pick)) counted.documents++;
    }

    const cases = (generator: fc.Arbitrary<VectorCase>) =>
      fc.tuple(generator, fc.nat(8), fc.nat(7));

    it("generates cases that hold and cases that do not, of every kind", () => {
      const generators = {
        keyLogCase,
        collectiveLogCase,
        nestedLogCase,
        ownKeyCase,
        branchCase,
        collectiveSignedCase,
      };
      for (const [name, generator] of Object.entries(generators)) {
        const sample = fc.sample(generator, { numRuns: 60, seed: 7 });
        const held = sample.filter((vectorCase) =>
          claimHolds(referenceAdapter, vectors, vectorCase),
        );
        // Neither verdict is rare: a campaign of rejections alone would show nothing.
        expect(held.length, `${name}: accepted`).toBeGreaterThan(3);
        expect(sample.length - held.length, `${name}: rejected`).toBeGreaterThan(3);
      }
    });

    it("reaches the rules it is there for", () => {
      // Duplicity that evidence cannot separate, for a mind and for a collective.
      const duplicitous = (generator: fc.Arbitrary<VectorCase>) =>
        fc.sample(generator, { numRuns: 60, seed: 11 }).filter((vectorCase) => {
          const subject = subjectOf(vectorCase);
          const resolved = referenceAdapter.didDocument?.(subject?.mind ?? "", undefined, {
            ...viewFor(vectors, vectorCase),
            extraLogs: subject?.logs ?? [],
          }) as { didDocumentMetadata?: { duplicitous?: boolean } } | undefined;
          return resolved?.didDocumentMetadata?.duplicitous === true;
        }).length;
      expect(duplicitous(branchCase)).toBeGreaterThan(3);
      expect(duplicitous(collectiveSignedCase)).toBeGreaterThan(2);
      // Lineage of each status.
      const statuses = fc.sample(lineageQuestion, { numRuns: 60, seed: 11 }).map((question) =>
        Object.values(
          referenceAdapter.lineage?.(question.mind, {
            ...viewFor(vectors, { kind: "log", name: "generated", log: [] }),
            extraLogs: question.extraLogs,
            extraRecords: question.extraRecords,
          }) ?? {},
        ).join(),
      );
      expect(statuses.filter((status) => status === "acknowledged").length).toBeGreaterThan(5);
      expect(statuses.filter((status) => status === "claimed").length).toBeGreaterThan(5);
    });

    const campaigns: [name: string, generator: fc.Arbitrary<VectorCase>, runs: number][] = [
      ["logs of key-controlled minds", keyLogCase, RUNS],
      ["logs of collectives", collectiveLogCase, Math.ceil(RUNS / 2)],
      ["logs of collectives that have collectives as members", nestedLogCase, Math.ceil(RUNS / 8)],
      ["records signed by a mind's own keys", ownKeyCase, Math.ceil(RUNS / 4)],
      ["records pinned to a branch of a log", branchCase, Math.ceil(RUNS / 4)],
      ["records signed under a collective's threshold", collectiveSignedCase, Math.ceil(RUNS / 4)],
    ];

    for (const [name, generator, runs] of campaigns) {
      it(
        `agrees with the Python checker on ${runs} generated ${name}`,
        async () => {
          await fc.assert(
            fc.asyncProperty(cases(generator), ([vectorCase, pick, document]) =>
              compare(name, vectorCase, pick, document),
            ),
            { numRuns: runs },
          );
          // The number in this test's name is the number that ran, and a
          // campaign of any size has cases both implementations accept.
          const counted = tally.get(name);
          expect(counted?.cases).toBe(runs);
          if (runs >= 100) expect(counted?.accepted).toBeGreaterThan(0);
        },
        TIMEOUT,
      );
    }

    it(
      `agrees with it on ${Math.ceil(RUNS / 8)} generated lineages`,
      async () => {
        await fc.assert(
          fc.asyncProperty(lineageQuestion, async (question) => {
            const ours = referenceAdapter.lineage?.(question.mind, {
              ...viewFor(vectors, { kind: "log", name: "generated", log: [] }),
              extraLogs: question.extraLogs,
              extraRecords: question.extraRecords,
            });
            const theirs = await judge.judge(question);
            expect(ours ?? {}, shown(question)).toStrictEqual(
              theirs.error === undefined ? theirs.value : {},
            );
          }),
          { numRuns: Math.ceil(RUNS / 8) },
        );
      },
      TIMEOUT,
    );

    it(
      "agrees with the Python checker, and with what each says, on sets of copies made by hand",
      async () => {
        const made = copiesByHand();
        for (const { counts, vectorCase } of made) {
          expect(
            claimHolds(referenceAdapter, vectors, vectorCase),
            `whether the record counts: ${vectorCase.name}`,
          ).toBe(counts);
          await compare("sets of copies made by hand", vectorCase, 0, 0);
        }
        expect(made.length).toBeGreaterThan(55);
      },
      TIMEOUT,
    );
  },
);
