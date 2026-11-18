// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The second performance budget of BUILD.md 3.8, measured in full
 * (ADR-0006): verifying an identity log of 1,000 events, each event read,
 * validated, hashed, checked against the one before it and its signature
 * verified.
 *
 * As in `@oip/core`, a ceiling in milliseconds is set with room, because it
 * depends on the machine, and a ratio is set close, because it does not: the
 * whole log against a thousand times the signature check of one event.
 */

import { parseRecord, verifyProofs } from "@oip/core";
import { KeyMind, LATER, witness } from "@oip/testkit/minds";
import { describe, expect, test } from "vitest";

import { type EvidenceView, LogBook, verifyLog } from "../src/index.ts";

export const BUDGETS = {
  /** Verify an identity log of 1,000 events, in milliseconds. */
  logOfAThousandEvents: 3500,
  /**
   * The same against a thousand times `parseRecord` and `verifyProofs` of
   * one event, as a ratio: what replaying adds to reading and checking each
   * event's signature. It measures at about 1.1.
   */
  overTheSignatures: 1.4,
} as const;

const EVENTS = 1000;

/** A log of 1,000 events: a genesis and 999 rotations, each changing the mind's homes. */
function longLog(): { events: readonly unknown[]; evidence: EvidenceView; mind: string } {
  const mind = new KeyMind("long-lived");
  for (let n = 1; n < EVENTS; n++) mind.update(n, { homes: [`https://home${n}.example`] });
  return { events: mind.events, evidence: witness([mind.events]), mind: mind.address };
}

describe("the budgets of BUILD.md 3.8", () => {
  const { events, evidence, mind } = longLog();
  const oneEvent = JSON.stringify(events[500]);

  test("verify an identity log of 1,000 events", async ({ bench }) => {
    const check = verifyLog(events, { evidence, asOf: LATER });
    expect(check.ok && check.value.entries).toHaveLength(EVENTS);
    const whole = await bench("verifyLog: 1,000 events", () =>
      verifyLog(events, { evidence, asOf: LATER }),
    )
      // A few runs of some seconds each say enough; the default would take minutes.
      .run({ iterations: 3, time: 0, warmupIterations: 1, warmupTime: 0 });
    expect(whole.latency.min).toBeLessThan(BUDGETS.logOfAThousandEvents);
    const one = await bench("parseRecord + verifyProofs: one event of the log", () => {
      const parsed = parseRecord(oneEvent);
      return parsed.ok && verifyProofs(parsed.value).verified.length;
    }).run();
    // A ratio of medians: the best case of one event is one sample of thousands, and a
    // lucky one moved this ratio between 1.2 and 1.45 where the medians give about 1.1.
    expect(whole.latency.p50 / (EVENTS * one.latency.p50)).toBeLessThan(BUDGETS.overTheSignatures);
  });

  test("answer at once for a log a book has verified", async ({ bench }) => {
    const book = new LogBook(evidence);
    book.hold(events, LATER);
    expect(book.log(mind).ok).toBe(true);
    const again = await bench("LogBook.log: a log verified before", () => book.log(mind)).run();
    expect(again.latency.p50).toBeLessThan(0.05);
  });
});
