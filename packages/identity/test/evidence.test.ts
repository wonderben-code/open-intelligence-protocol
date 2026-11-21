// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { CLOCK_SKEW, contentId } from "@oip/core";
import { clause, withAmbientTrapped } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  earliestEvidence,
  eventTime,
  type EvidenceView,
  FirstSeen,
  LogBook,
  proofTime,
  verifyLog,
} from "../src/index.ts";
import { at, KeyMind, LATER, witness } from "@oip/testkit/minds";

const instants = fc.bigInt({ min: 0n, max: 4_000_000_000_000_000_000n });

/** What a refusal says. */
const said = (result: { ok: boolean; issues?: readonly { message: string }[] }): string =>
  result.issues?.[0]?.message ?? "";

describe(`${clause("core 9.3")} the evaluation time of a proof`, () => {
  it("is the later of the proof's date and the evidence that it existed", () => {
    const evaluation = (seen: number, time: number, evidenced = seen) => ({
      ok: true,
      value: { seen: at(seen), time: at(time), evidenced: at(evidenced) },
    });
    expect(proofTime(at(10), at(20))).toStrictEqual(evaluation(20, 20));
    expect(proofTime(at(20), at(10))).toStrictEqual(evaluation(10, 20));
    expect(proofTime(at(10), at(10))).toStrictEqual(evaluation(10, 10));
    fc.assert(
      fc.property(instants, instants, (created, seen) => {
        const time = proofTime(created, seen);
        if (created > seen + CLOCK_SKEW) return !time.ok;
        return (
          time.ok &&
          time.value.time >= created &&
          time.value.time >= seen &&
          time.value.seen === seen &&
          // The signer's own date is no part of what the evidence shows.
          time.value.evidenced === seen
        );
      }),
    );
  });

  it(`${clause("core 9.1")} counts for nothing when dated more than 300 seconds after its evidence`, () => {
    expect(CLOCK_SKEW).toBe(300n * 1_000_000_000n);
    expect(proofTime(at(300), at(0))).toStrictEqual({
      ok: true,
      value: { seen: at(0), time: at(300), evidenced: at(0) },
    });
    expect(proofTime(at(300.000000001), at(0))).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.3" }],
    });
    expect(said(proofTime(at(300.000000001), at(0)))).toContain("after the evidence");
  });

  it(`${clause("core 9.2")} has no evaluation time without evidence, whatever date it carries`, () => {
    expect(proofTime(at(10), undefined)).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.4" }],
    });
  });
});

describe(`${clause("core 9.5")} the evaluation time of an identity event`, () => {
  it("is the latest of its date, its evidence and the time of the event before it", () => {
    const evaluation = (seen: number, time: number, evidenced = seen) => ({
      ok: true,
      value: { seen: at(seen), time: at(time), evidenced: at(evidenced) },
    });
    expect(eventTime(at(10), at(20))).toStrictEqual(evaluation(20, 20));
    // Dated after its evidence: it takes effect when it says, and the evidence shows no more than it did.
    expect(eventTime(at(20), at(10))).toStrictEqual(evaluation(10, 20));
    // Never before the event it follows. What the evidence shows goes on from
    // what it showed for that event, and leaves out the date its signer wrote.
    const before = (time: number, evidenced: number) => ({
      time: at(time),
      evidenced: at(evidenced),
    });
    expect(eventTime(at(10), at(20), before(30, 30))).toStrictEqual(evaluation(20, 30, 30));
    expect(eventTime(at(10), at(20), before(30, 25))).toStrictEqual(evaluation(20, 30, 25));
    expect(eventTime(at(40), at(20), before(30, 30))).toStrictEqual(evaluation(20, 40, 30));
    expect(eventTime(at(10), at(20), before(15, 15))).toStrictEqual(evaluation(20, 20));
    expect(eventTime(at(10), at(20), before(25, 15))).toStrictEqual(evaluation(20, 25, 20));
    fc.assert(
      fc.property(
        instants,
        instants,
        fc.option(fc.tuple(instants, instants), { nil: undefined }),
        (created, seen, before) => {
          // What the evidence showed for the event before is never after its evaluation time.
          const previous =
            before === undefined
              ? undefined
              : {
                  time: before[0] > before[1] ? before[0] : before[1],
                  evidenced: before[0] > before[1] ? before[1] : before[0],
                };
          const time = eventTime(created, seen, previous);
          if (created > seen + CLOCK_SKEW) return !time.ok;
          const latest = (...times: bigint[]) => times.reduce((a, b) => (b > a ? b : a));
          return (
            time.ok &&
            time.value.seen === seen &&
            time.value.time === latest(created, seen, ...(previous ? [previous.time] : [])) &&
            time.value.evidenced === latest(seen, ...(previous ? [previous.evidenced] : [])) &&
            time.value.evidenced <= time.value.time
          );
        },
      ),
    );
  });

  it("does not verify when dated more than 300 seconds after its evidence, or without evidence", () => {
    expect(eventTime(at(300), at(0)).ok).toBe(true);
    expect(eventTime(at(300.000000001), at(0))).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.5" }],
    });
    expect(said(eventTime(at(300.000000001), at(0)))).toContain("after the evidence");
    expect(said(eventTime(at(10), undefined))).toContain("no evidence");
    expect(said(proofTime(at(10), undefined))).toContain("no evidence");
    expect(eventTime(at(10), undefined, { time: at(5), evidenced: at(5) })).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.5" }],
    });
  });

  it("is what a log is verified with: no event is taken at its own word", () => {
    const ada = new KeyMind("ada", 10).update(20).update(30);
    const ids = ada.events.map((event) => contentId(event));
    const verify = (seen: readonly (number | undefined)[]) => {
      const evidence = new FirstSeen();
      seen.forEach((seconds, position) => {
        if (seconds !== undefined) evidence.sawEvent(ids[position] ?? "", at(seconds));
      });
      const log = verifyLog(ada.events, { evidence, asOf: LATER });
      return log.ok ? log.value.entries.map((entry) => entry.time) : log.issues[0];
    };
    expect(verify([10, 20, 30])).toEqual([at(10), at(20), at(30)]);
    // Seen late: each event takes effect when it is known to have existed.
    expect(verify([10, 50, 30])).toEqual([at(10), at(50), at(50)]);
    expect(verify([100, 20, 30])).toEqual([at(100), at(100), at(100)]);
    // Seen early, within the skew: its own date stands.
    expect(verify([-290, 20, 30])).toEqual([at(10), at(20), at(30)]);
    expect(verify([-291, 20, 30])).toMatchObject({ clause: "core 9.5", path: "/0" });
    expect(verify([10, undefined, 30])).toMatchObject({ clause: "core 9.5", path: "/1" });
    expect(verify([])).toMatchObject({ clause: "core 9.5", path: "/0" });
  });
});

describe(`${clause("core 9.4")} evidence that something existed`, () => {
  it("keeps the earliest time it is told, for each proof and each event", () => {
    const seen = new FirstSeen();
    expect(seen.proofSeen("sha256:aa")).toBeUndefined();
    expect(seen.sawProof("sha256:aa", at(20))).toBe(at(20));
    expect(seen.sawProof("sha256:aa", at(30))).toBe(at(20));
    expect(seen.sawProof("sha256:aa", at(10))).toBe(at(10));
    expect(seen.proofSeen("sha256:aa")).toBe(at(10));
    expect(seen.eventSeen("sha256:aa")).toBeUndefined();
    expect(seen.sawEvent("bciq", at(5))).toBe(at(5));
    expect(seen.sawEvent("bciq", at(6))).toBe(at(5));
    expect(seen.sawEvent("bciq", at(4))).toBe(at(4));
    expect(seen.eventSeen("bciq")).toBe(at(4));
    expect(seen.proofSeen("bciq")).toBeUndefined();
  });

  it("takes the earliest of several sources: the verifier's own, a witness's, an anchor's", () => {
    const own = new FirstSeen();
    const witnessed = new FirstSeen();
    own.sawProof("p", at(50));
    witnessed.sawProof("p", at(20));
    own.sawEvent("e", at(5));
    witnessed.sawEvent("e", at(9));
    witnessed.sawEvent("only", at(1));
    const all = earliestEvidence(own, witnessed);
    expect(all.proofSeen("p")).toBe(at(20));
    expect(all.eventSeen("e")).toBe(at(5));
    expect(all.eventSeen("only")).toBe(at(1));
    expect(all.proofSeen("none")).toBeUndefined();
    expect(earliestEvidence().eventSeen("e")).toBeUndefined();
  });
});

describe("purity", () => {
  it("reads no clock and no randomness, and does no I/O, to verify a log", () => {
    const ada = new KeyMind("ada").update(10).retire(20);
    const evidence: EvidenceView = witness([ada.events]);
    const verified = withAmbientTrapped(() => {
      const book = new LogBook(evidence);
      book.hold(ada.events, LATER);
      return book.log(ada.address);
    });
    expect(verified.ok).toBe(true);
  });
});
