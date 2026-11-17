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

describe(`${clause("core 9.3")} the evaluation time of a proof`, () => {
  it("is the later of the proof's date and the evidence that it existed", () => {
    expect(proofTime(at(10), at(20))).toEqual({ ok: true, value: { seen: at(20), time: at(20) } });
    expect(proofTime(at(20), at(10))).toEqual({ ok: true, value: { seen: at(10), time: at(20) } });
    expect(proofTime(at(10), at(10))).toEqual({ ok: true, value: { seen: at(10), time: at(10) } });
    fc.assert(
      fc.property(instants, instants, (created, seen) => {
        const time = proofTime(created, seen);
        if (created > seen + CLOCK_SKEW) return !time.ok;
        return (
          time.ok &&
          time.value.time >= created &&
          time.value.time >= seen &&
          time.value.seen === seen
        );
      }),
    );
  });

  it(`${clause("core 9.1")} counts for nothing when dated more than 300 seconds after its evidence`, () => {
    expect(CLOCK_SKEW).toBe(300n * 1_000_000_000n);
    expect(proofTime(at(300), at(0))).toEqual({ ok: true, value: { seen: at(0), time: at(300) } });
    expect(proofTime(at(300.000000001), at(0))).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.3" }],
    });
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
    expect(eventTime(at(10), at(20))).toEqual({ ok: true, value: { seen: at(20), time: at(20) } });
    expect(eventTime(at(20), at(10))).toEqual({ ok: true, value: { seen: at(10), time: at(20) } });
    expect(eventTime(at(10), at(20), at(30))).toEqual({
      ok: true,
      value: { seen: at(20), time: at(30) },
    });
    expect(eventTime(at(10), at(20), at(15))).toEqual({
      ok: true,
      value: { seen: at(20), time: at(20) },
    });
    fc.assert(
      fc.property(
        instants,
        instants,
        fc.option(instants, { nil: undefined }),
        (created, seen, previous) => {
          const time = eventTime(created, seen, previous);
          if (created > seen + CLOCK_SKEW) return !time.ok;
          return (
            time.ok &&
            time.value.seen === seen &&
            time.value.time >= created &&
            time.value.time >= seen &&
            (previous === undefined || time.value.time >= previous) &&
            [created, seen, previous].includes(time.value.time)
          );
        },
      ),
    );
  });

  it("is invalid when dated more than 300 seconds after its evidence, or without evidence", () => {
    expect(eventTime(at(300), at(0)).ok).toBe(true);
    expect(eventTime(at(300.000000001), at(0))).toMatchObject({
      ok: false,
      issues: [{ clause: "core 9.5" }],
    });
    expect(eventTime(at(10), undefined, at(5))).toMatchObject({
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
