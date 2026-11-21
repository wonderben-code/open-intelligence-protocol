// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Properties of log verification, over generated logs (BUILD.md, M2): a log
 * that is reordered, cut in the middle, signed again by other keys or
 * changed in any member does not verify, and a log replayed to any version
 * gives the state it had then.
 */

import { contentId } from "@oip/core";
import type { Validation } from "@oip/schema";
import { clause, copy, type JsonObject } from "@oip/testkit";
import {
  agreementKey,
  bookOf,
  Collective,
  KeyMind,
  LATER,
  rawSign,
  signer,
  T,
  witness,
} from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { didDocument, entryAt, latestState, type VerifiedLog, verifyLog } from "../src/index.ts";

type Events = JsonObject[];

/** What an event of a generated log does. Every combination gives a log that verifies. */
const step = fc.record({
  kind: fc.constantFrom("update", "update", "update", "fork"),
  gap: fc.constantFrom(0, 1, 60, 86_400),
  homes: fc.option(fc.subarray(["https://a.example", "https://b.example:8443"]), {
    nil: undefined,
  }),
  aliases: fc.option(fc.subarray(["dns:mind.example", "at://mind.example"]), { nil: undefined }),
  operational: fc.option(fc.subarray([0, 1, 2], { minLength: 1 }), { nil: undefined }),
  agreement: fc.boolean(),
});

/** What the state of a mind should be after an event, worked out from the plan and not from the log. */
interface Expected {
  readonly homes: readonly string[];
  readonly alsoKnownAs: readonly string[];
  readonly keys: readonly string[];
  readonly agreement: readonly string[];
  readonly children: number;
  readonly retired: boolean;
}

/** A key-controlled mind with a log of two to six events, all of them valid, and the state after each. */
const lived = fc
  .record({
    name: fc.constantFrom("ada", "bea", "cy"),
    steps: fc.array(step, { minLength: 1, maxLength: 4 }),
    retires: fc.boolean(),
  })
  .map(({ name, steps, retires }) => {
    const mind = new KeyMind(name, 100);
    let now: Expected = {
      homes: [],
      alsoKnownAs: [],
      keys: [mind.operational(0).publicKey],
      agreement: [agreementKey(`${name}/agreement/0`)],
      children: 0,
      retired: false,
    };
    const expected = [now];
    let seconds = 100;
    for (const { kind, gap, homes, aliases, operational, agreement } of steps) {
      seconds += gap;
      const keys = operational?.map((n) => mind.operational(n).publicKey);
      const agreed = agreement ? [agreementKey(`${name}/agreement/${seconds}`)] : undefined;
      const fields = {
        ...(homes === undefined ? {} : { homes }),
        ...(aliases === undefined ? {} : { alsoKnownAs: aliases }),
        ...(keys === undefined ? {} : { keys: keys.map((key) => ({ key })) }),
        ...(agreed === undefined ? {} : { agreement: agreed.map((key) => ({ key })) }),
      };
      if (kind === "fork") mind.fork(seconds, { ...fields, child: new KeyMind("child").address });
      else mind.update(seconds, fields);
      // Layer 1, 4.5: a set that an event states replaces the one before; one it does not state stays.
      now = {
        homes: homes ?? now.homes,
        alsoKnownAs: aliases ?? now.alsoKnownAs,
        keys: keys ?? now.keys,
        agreement: agreed ?? now.agreement,
        children: now.children + (kind === "fork" ? 1 : 0),
        retired: false,
      };
      expected.push(now);
    }
    if (retires) {
      mind.retire(seconds + 1);
      expected.push({ ...now, retired: true });
    }
    return { mind, expected };
  });

const livedMind = lived.map(({ mind }) => mind);

/**
 * Verifies events for a verifier whose witness saw each of them when it was
 * made: the mind's own, and whatever was put in their place. A forged event
 * is seen like any other, so it is refused for what is wrong with it, and
 * not for want of evidence.
 */
function verify(mind: KeyMind, events: readonly unknown[] = mind.events) {
  return verifyLog(events, {
    evidence: witness([mind.events, events as JsonObject[]]),
    asOf: LATER,
  });
}

/** The clause and the place of a refusal. */
function refused(result: Validation<unknown>): { clause: string; at: string } {
  if (result.ok) throw new Error("the log verified");
  const { clause: found, path } = result.issues[0];
  return { clause: found, at: `/${path.split("/")[1] ?? ""}` };
}

function verified(mind: KeyMind): VerifiedLog {
  const log = verify(mind);
  if (!log.ok) throw new Error(JSON.stringify(log.issues));
  return log.value;
}

// A mutation run tries each property on fewer logs: nearly every mutant of the
// package is covered by all of them, and a fault a property finds, it finds early.
const RUNS = { numRuns: process.env["OIP_MUTATION"] === undefined ? 40 : 10 };

describe(`${clause("L1 4", "L1 4.2")} what is done to a log shows`, () => {
  it("verifies as written", () => {
    fc.assert(
      fc.property(livedMind, (mind) => {
        expect(verified(mind).entries).toHaveLength(mind.events.length);
      }),
      RUNS,
    );
  });

  it("does not verify in any other order", () => {
    fc.assert(
      fc.property(
        livedMind.chain((mind) =>
          fc.tuple(
            fc.constant(mind),
            fc.shuffledSubarray(
              mind.events.map((_, i) => i),
              { minLength: mind.events.length },
            ),
          ),
        ),
        ([mind, order]) => {
          fc.pre(order.some((position, i) => position !== i));
          expect(
            verify(
              mind,
              order.map((position) => mind.events[position]),
            ).ok,
          ).toBe(false);
        },
      ),
      RUNS,
    );
  });

  it("does not verify with an event taken out of the middle, or one put in twice", () => {
    fc.assert(
      fc.property(livedMind, fc.nat(), (mind, pick) => {
        const events = mind.events;
        // Every event but the last: without the last, what is left is a shorter log.
        const i = pick % (events.length - 1);
        expect(verify(mind, [...events.slice(0, i), ...events.slice(i + 1)]).ok).toBe(false);
        expect(verify(mind, [...events.slice(0, i + 1), ...events.slice(i)]).ok).toBe(false);
      }),
      RUNS,
    );
  });

  it("does not verify when an event is signed again by keys that were not committed to", () => {
    fc.assert(
      fc.property(livedMind, fc.nat(), (mind, pick) => {
        const i = pick % mind.events.length;
        const intruder = signer(`${mind.name}/intruder`);
        const event = mind.events[i] as unknown as JsonObject;
        // The intruder signs the event as it is, and then with itself as the key revealed.
        const resigned = rawSign(event, [{ control: intruder }]);
        const revealed = rawSign(
          { ...event, controller: { keys: [intruder.publicKey], next: [] } },
          [{ control: intruder }],
        );
        // A genesis that reveals another key is another mind's genesis, so only later events are tried that way.
        for (const forged of i === 0 ? [resigned] : [resigned, revealed]) {
          const events = mind.events.map((e, n) => (n === i ? forged : e));
          // Refused at that event, for its authority: the forgery has evidence like any other event.
          expect(refused(verify(mind, events.slice(0, i + 1)))).toStrictEqual({
            clause: i === 0 ? "L1 4.1" : "L1 4.3",
            at: `/${i}`,
          });
        }
      }),
      RUNS,
    );
  });

  it("does not verify when any member of any event is changed, or its signature", () => {
    const changes: ((event: JsonObject) => JsonObject)[] = [
      // Later than every event of any log here, so that the date itself breaks no rule.
      (event) => ({ ...event, created: T(9_999_999) }),
      (event) => ({ ...event, homes: ["https://elsewhere.example"] }),
      (event) => ({ ...event, keys: [{ key: signer("thief").publicKey }] }),
      (event) => ({ ...event, note: "added afterwards" }),
      (event) => {
        const changed = copy(event) as { proof: { proofValue: string }[] };
        const [proof] = changed.proof;
        if (proof !== undefined) {
          const last = proof.proofValue.at(-1) === "2" ? "3" : "2";
          proof.proofValue = proof.proofValue.slice(0, -1) + last;
        }
        return changed;
      },
    ];
    fc.assert(
      fc.property(livedMind, fc.nat(), fc.constantFrom(...changes), (mind, pick, change) => {
        const i = pick % mind.events.length;
        const events = (mind.events as unknown as Events).map((e, n) => (n === i ? change(e) : e));
        // The proofs on the event are of what it was, so no key has signed what it is now.
        expect(refused(verify(mind, events))).toStrictEqual({
          clause: i === 0 ? "L1 4.1" : "L1 4.3",
          at: `/${i}`,
        });
      }),
      RUNS,
    );
  });
});

describe(`${clause("L1 4.1", "L1 4.4")} what is done to a collective's log shows`, () => {
  const people = () => ["a", "b", "c", "d"].map((name) => new KeyMind(name));

  /** A collective of three, threshold two, whose events are each signed by two or three of its members. */
  const livedCollective = fc
    .array(
      fc.record({
        gap: fc.constantFrom(1, 60, 3600),
        signers: fc.subarray([0, 1, 2], { minLength: 2 }),
        homes: fc.boolean(),
      }),
      { minLength: 1, maxLength: 3 },
    )
    .map((steps) => {
      const members = people();
      const club = new Collective("club", members.slice(0, 3), 2, 100);
      let seconds = 100;
      for (const { gap, signers, homes } of steps) {
        seconds += gap;
        club.update(
          seconds,
          signers.map((n) => members[n]!),
          homes ? { homes: ["https://club.example"] } : {},
        );
      }
      return { club, members, steps };
    });

  const verifyClub = (members: readonly KeyMind[], events: readonly unknown[]) => {
    const book = bookOf(members);
    return verifyLog(events, {
      evidence: witness([events as JsonObject[]]),
      asOf: LATER,
      memberLog: (mind) => book.log(mind),
    });
  };

  it("verifies as written, and not when an event keeps fewer proofs than the threshold", () => {
    fc.assert(
      fc.property(livedCollective, fc.nat(), ({ club, members }, pick) => {
        expect(verifyClub(members, club.events).ok).toBe(true);
        const i = 1 + (pick % (club.events.length - 1));
        const event = club.events[i] as unknown as JsonObject & { proof: unknown[] };
        const one = { ...event, proof: event.proof.slice(0, 1) };
        const events = club.events.map((e, n) => (n === i ? one : e));
        expect(refused(verifyClub(members, events))).toStrictEqual({
          clause: "L1 4.4",
          at: `/${i}`,
        });
      }),
      RUNS,
    );
  });

  it("does not verify when an event is signed by a mind that is no member, or changed after it was signed", () => {
    fc.assert(
      fc.property(livedCollective, fc.nat(), fc.boolean(), ({ club, members }, pick, late) => {
        const i = pick % club.events.length;
        const event = club.events[i] as unknown as JsonObject;
        const [a, , , stranger] = members as [KeyMind, KeyMind, KeyMind, KeyMind];
        const forged = late
          ? // A member no reader knows, added after the members signed.
            { ...event, note: "added afterwards" }
          : // One member, and a mind the collective never admitted.
            rawSign(event, [a.asMember(), stranger.asMember()]);
        const events = club.events.map((e, n) => (n === i ? forged : e));
        expect(refused(verifyClub(members, events))).toStrictEqual({
          clause: i === 0 ? "L1 4.1" : "L1 4.4",
          at: `/${i}`,
        });
      }),
      RUNS,
    );
  });
});

describe(`${clause("L1 2.4", "L1 5.1")} a log replayed to any version`, () => {
  it("gives the state the log had at that version, whatever came after", () => {
    fc.assert(
      fc.property(lived, ({ mind, expected }) => {
        const whole = verified(mind);
        expect(expected).toHaveLength(mind.events.length);
        mind.events.forEach((event, i) => {
          const versionId = mind.versionId(i);
          expect(versionId).toBe(`${i}-${contentId(event)}`);
          // What the plan says the state is, which no replay produced.
          const state = entryAt(whole, versionId)?.entry.state;
          const planned = expected[i];
          expect({
            homes: state?.homes,
            alsoKnownAs: state?.alsoKnownAs,
            keys: state?.keys,
            agreement: state?.agreement,
            retired: state?.retired,
            seq: state?.seq,
          }).toStrictEqual({
            homes: planned?.homes,
            alsoKnownAs: planned?.alsoKnownAs,
            keys: planned?.keys,
            agreement: planned?.agreement,
            retired: planned?.retired,
            seq: i,
          });
          const resolved = didDocument(whole, { versionId });
          expect(resolved.ok && resolved.value.didDocumentMetadata.children).toHaveLength(
            planned?.children ?? -1,
          );
          // The first events of a log are a log: its last state is the state at that version.
          const prefix = verify(mind, mind.events.slice(0, i + 1));
          if (!prefix.ok) throw new Error("a prefix does not verify");
          const then = latestState(prefix.value);
          expect(entryAt(whole, versionId)).toEqual({
            position: i,
            entry: {
              event: whole.entries[i]?.event,
              state: then,
              time: prefix.value.entries[i]?.time,
            },
          });
          // And the document resolved at that version is the document of the shorter log, but
          // for `deactivated`, which is of the mind as its whole log stands (Layer 1, 5.2): a
          // mind that has retired since is deactivated at every one of its versions.
          const versioned = didDocument(whole, { versionId });
          const current = didDocument(prefix.value, { versionId });
          if (!versioned.ok || !current.ok) throw new Error("a version does not resolve");
          const { retired } = latestState(whole);
          expect(versioned.value).toEqual({
            ...current.value,
            didDocumentMetadata: { ...current.value.didDocumentMetadata, deactivated: retired },
          });
          expect(versioned.value.didDocumentMetadata.deactivated).toBe(retired);
          expect(versioned.value.didDocumentMetadata.versionId).toBe(versionId);
        });
      }),
      RUNS,
    );
  });
});
