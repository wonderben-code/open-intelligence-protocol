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

import { forgetVerifiedSignatures, parseRecord, verifyProofs } from "@oip/core";
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
  /**
   * How many times faster a log is verified again, once its signatures have
   * verified: a verifier that is sent a copy of a log it has read pays for
   * the reading and the hashing, and not again for the signatures.
   */
  againOverFirst: 5,
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
    /** The median time to read and check one event of the log. */
    const one = async (when: string): Promise<number> =>
      (
        await bench(`parseRecord + verifyProofs: one event of the log (${when})`, () => {
          // What is timed is the checking of a signature: none is remembered from the call before.
          forgetVerifiedSignatures();
          const parsed = parseRecord(oneEvent);
          return parsed.ok && verifyProofs(parsed.value).verified.length;
        }).run()
      ).latency.p50;
    const before = await one("before");
    const whole = await bench("verifyLog: 1,000 events", () => {
      forgetVerifiedSignatures();
      return verifyLog(events, { evidence, asOf: LATER });
    })
      // A few runs of some seconds each say enough; the default would take minutes.
      .run({ iterations: 3, time: 0, warmupIterations: 1, warmupTime: 0 });
    expect(whole.latency.min).toBeLessThan(BUDGETS.logOfAThousandEvents);
    const after = await one("after");
    // A ratio of medians: the best case of one event is one sample of thousands, and a
    // lucky one moved this ratio between 1.2 and 1.45 where the medians give about 1.1.
    // One event is measured before the log and after it, and the faster of the two is
    // what the log is compared with: other work on the machine while one of them is
    // measured does not make the log look cheaper than it is. Work that slows both of
    // them and not the log would, which their lengths make unlikely.
    expect(whole.latency.p50 / (EVENTS * Math.min(before, after))).toBeLessThan(
      BUDGETS.overTheSignatures,
    );
  });

  test("verify again a log whose signatures verified before, for a fraction of the first time", async ({
    bench,
  }) => {
    const options = { iterations: 3, time: 0, warmupIterations: 1, warmupTime: 0 };
    const first = await bench("verifyLog: 1,000 events, none verified before", () => {
      forgetVerifiedSignatures();
      return verifyLog(events, { evidence, asOf: LATER });
    }).run(options);
    // The same log, read again: by a verifier that was sent a longer copy of it, or the same one.
    const again = await bench("verifyLog: 1,000 events, all verified before", () =>
      verifyLog(events, { evidence, asOf: LATER }),
    ).run(options);
    expect(again.latency.p50 * BUDGETS.againOverFirst).toBeLessThan(first.latency.p50);
  });

  test("answer at once for a log a book has verified", async ({ bench }) => {
    const book = new LogBook(evidence);
    book.hold(events, LATER);
    expect(book.log(mind).ok).toBe(true);
    const again = await bench("LogBook.log: a log verified before", () => book.log(mind)).run();
    expect(again.latency.p50).toBeLessThan(0.05);
  });
});
