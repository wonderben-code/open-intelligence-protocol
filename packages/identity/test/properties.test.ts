// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Properties of log verification, over generated logs (BUILD.md, M2): a log
 * that is reordered, cut in the middle, signed again by other keys or
 * changed in any member does not verify, and a log replayed to any version
 * gives the state it had then.
 */

import { contentId } from "@oip/core";
import { clause, copy, type JsonObject } from "@oip/testkit";
import { agreementKey, KeyMind, LATER, rawSign, signer, T, witness } from "@oip/testkit/minds";
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

/** A key-controlled mind with a log of two to six events, all of them valid. */
const livedMind = fc
  .record({
    name: fc.constantFrom("ada", "bea", "cy"),
    steps: fc.array(step, { minLength: 1, maxLength: 4 }),
    retires: fc.boolean(),
  })
  .map(({ name, steps, retires }) => {
    const mind = new KeyMind(name, 100);
    let seconds = 100;
    for (const { kind, gap, homes, aliases, operational, agreement } of steps) {
      seconds += gap;
      const fields = {
        ...(homes === undefined ? {} : { homes }),
        ...(aliases === undefined ? {} : { alsoKnownAs: aliases }),
        ...(operational === undefined
          ? {}
          : { keys: operational.map((n) => ({ key: mind.operational(n).publicKey })) }),
        ...(agreement
          ? { agreement: [{ key: agreementKey(`${name}/agreement/${seconds}`) }] }
          : {}),
      };
      if (kind === "fork") mind.fork(seconds, { ...fields, child: new KeyMind("child").address });
      else mind.update(seconds, fields);
    }
    if (retires) mind.retire(seconds + 1);
    return mind;
  });

/** Verifies events for a verifier whose witness saw each when it was made, whatever is done to them after. */
function verify(mind: KeyMind, events: readonly unknown[] = mind.events) {
  return verifyLog(events, { evidence: witness([mind.events]), asOf: LATER });
}

function verified(mind: KeyMind): VerifiedLog {
  const log = verify(mind);
  if (!log.ok) throw new Error(JSON.stringify(log.issues));
  return log.value;
}

const RUNS = { numRuns: 40 };

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
          expect(verify(mind, events.slice(0, i + 1)).ok).toBe(false);
        }
      }),
      RUNS,
    );
  });

  it("does not verify when any member of any event is changed, or its signature", () => {
    const changes: ((event: JsonObject) => JsonObject)[] = [
      (event) => ({ ...event, created: T(99_999) }),
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
        expect(verify(mind, events).ok).toBe(false);
      }),
      RUNS,
    );
  });
});

describe(`${clause("L1 2.4", "L1 5.1")} a log replayed to any version`, () => {
  it("gives the state the log had at that version, whatever came after", () => {
    fc.assert(
      fc.property(livedMind, (mind) => {
        const whole = verified(mind);
        mind.events.forEach((event, i) => {
          const versionId = mind.versionId(i);
          expect(versionId).toBe(`${i}-${contentId(event)}`);
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
          // And the document resolved at that version is the document of the shorter log.
          const versioned = didDocument(whole, { versionId });
          const current = didDocument(prefix.value, { versionId });
          expect(versioned.ok && versioned.value).toEqual(current.ok && current.value);
          expect(versioned.ok && versioned.value.didDocumentMetadata.versionId).toBe(versionId);
        });
      }),
      RUNS,
    );
  });
});
