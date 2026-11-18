// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, and what a verifier keeps.
 *
 * With the call stack all but spent, a function that judges still answers:
 * whatever fails inside it becomes a refusal. That refusal is true of the
 * moment and not of what was judged, so nothing may keep it. These tests
 * make the fault for certain, by noting a failure for want of room from
 * inside the work, as the places that turn one into an answer do.
 * `spent-stack.test.ts` makes it by spending the stack.
 */

import { contentId } from "@oip/core";
import { noteCutShort } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, LATER, witness } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { type EvidenceView, FirstSeen, judgeRecord, LogBook, ownSignedTime } from "../src/index.ts";

const SPENT = { ok: false, issues: [{ clause: "implementation limit", path: "" }] };

/** A value that fails with `error` as soon as anything is asked of it. */
function failing(error: Error): object {
  const refuse = (): never => {
    throw error;
  };
  return new Proxy(
    {},
    { ownKeys: refuse, get: refuse, has: refuse, getOwnPropertyDescriptor: refuse },
  );
}

const overflow = (): RangeError => new RangeError("Maximum call stack size exceeded");

/** Evidence that notes a check cut short, while `cut.now` is set, each time it is asked about an event. */
function cutting(seen: EvidenceView): { view: EvidenceView; cut: { now: boolean } } {
  const cut = { now: false };
  return {
    cut,
    view: {
      proofSeen: (digest) => seen.proofSeen(digest),
      eventSeen: (id) => {
        if (cut.now) noteCutShort(overflow());
        return seen.eventSeen(id);
      },
    },
  };
}

describe(`${clause("core 4.4")} a check that was cut short`, () => {
  it("is no verdict on a log: the book refuses, keeps nothing, and is right when asked again", () => {
    const ada = new KeyMind("ada").update(10);
    const intent = judgeRecord(ada.sign(intentBy(ada, 20)));
    if (!intent.ok) throw new Error(JSON.stringify(intent.issues));
    const seen = witness([ada.events], [ada.sign(intentBy(ada, 20))]);
    const { view, cut } = cutting(seen);
    const book = new LogBook(view);
    book.hold(ada.events, LATER);
    cut.now = true;
    expect(book.log(ada.address)).toMatchObject(SPENT);
    expect(ownSignedTime(intent.value, ada.address, book)).toBeUndefined();
    // Nothing of it was kept: with room again, the log verifies and the record counts.
    cut.now = false;
    expect(book.log(ada.address)).toMatchObject({ ok: true, value: { mind: ada.address } });
    expect(ownSignedTime(intent.value, ada.address, book)).toBe(at(20));
    // A verdict reached with room is kept, and a check cut short afterwards does not touch it.
    cut.now = true;
    expect(book.log(ada.address).ok).toBe(true);
  });

  it("is no verdict on a member's log either, or on the collective that rests on it", () => {
    const [a, b] = [new KeyMind("a"), new KeyMind("b")];
    const club = new Collective("club", [a, b], 2, 5);
    const { view, cut } = cutting(witness([a.events, b.events, club.events]));
    const book = new LogBook(view);
    for (const mind of [a, b, club]) book.hold(mind.events, LATER);
    cut.now = true;
    expect(book.log(club.address)).toMatchObject(SPENT);
    expect(book.log(a.address)).toMatchObject(SPENT);
    cut.now = false;
    for (const mind of [club, a, b]) expect(book.log(mind.address).ok, mind.name).toBe(true);
  });

  it("records no first sight: a look that was cut short is no look", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    const { view, cut } = cutting(seen);
    const book = new LogBook(view);
    cut.now = true;
    // The copy is held, and what would have been recorded of it is not.
    expect(book.witness(ada.events, at(50), seen).ok).toBe(true);
    book.witnessHeld(at(60), seen);
    expect(ada.events.map((event) => seen.eventSeen(contentId(event)))).toStrictEqual([
      undefined,
      undefined,
    ]);
    cut.now = false;
    book.witnessHeld(at(70), seen);
    expect(ada.events.map((event) => seen.eventSeen(contentId(event)))).toStrictEqual([
      at(70),
      at(70),
    ]);
  });

  it("is no judgement of a record: `judgeRecord` says so, and keeps no proof out", () => {
    expect(judgeRecord(failing(overflow()))).toMatchObject(SPENT);
    // Any other failure of a value to be read is the value's own, as before.
    expect(judgeRecord(failing(new Error("no")))).toMatchObject({
      ok: false,
      issues: [{ clause: "core 1.2" }],
    });
    const ada = new KeyMind("ada");
    expect(judgeRecord(ada.sign(intentBy(ada, 20)))).toMatchObject({ ok: true });
  });

  it("is what a process in no state to serialise gives, and a book keeps nothing of it", () => {
    // Other code has put a `toJSON` on every object. Nothing is hashed or signed in a
    // process in that state (core 2), so no proof can be judged: that is no verdict on the
    // record, and none on a log.
    const ada = new KeyMind("ada");
    const record = ada.sign(intentBy(ada, 20));
    const book = new LogBook(witness([ada.events], [record]));
    let judged: ReturnType<typeof judgeRecord> | undefined;
    let held: ReturnType<LogBook["hold"]> | undefined;
    Object.defineProperty(Object.prototype, "toJSON", {
      value: () => "rewritten",
      configurable: true,
      writable: true,
    });
    try {
      judged = judgeRecord(record);
      held = book.hold(ada.events, LATER);
    } finally {
      delete (Object.prototype as { toJSON?: unknown }).toJSON;
    }
    expect(judged).toMatchObject(SPENT);
    expect(held).toMatchObject(SPENT);
    // Back in a process that can: the record counts, and the book takes the log in.
    expect(judgeRecord(record).ok).toBe(true);
    expect(book.hold(ada.events, LATER).ok).toBe(true);
    expect(book.log(ada.address).ok).toBe(true);
  });

  it("is no copy of a log: `hold` takes nothing in, where it would have held a value it could not read", () => {
    const ada = new KeyMind("ada").update(10);
    const book = new LogBook(witness([ada.events]));
    expect(book.hold([ada.events[0], failing(overflow())], LATER)).toMatchObject(SPENT);
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 6.3" }] });
    expect(book.hold(ada.events, LATER).ok).toBe(true);
    expect(book.log(ada.address)).toMatchObject({ ok: true });
    // A value that fails for a reason of its own is held as one the verifier cannot
    // judge, and stops the log at it, as before (Layer 1, 4.9).
    const other = new LogBook(witness([ada.events]));
    expect(other.hold([ada.events[0], failing(new Error("no"))], LATER).ok).toBe(true);
    expect(other.log(ada.address).ok).toBe(false);
  });
});
