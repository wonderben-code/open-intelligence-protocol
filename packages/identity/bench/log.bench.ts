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
 * whole log against a thousand times the signature check of one event,
 * measured turn about (ADR-0020).
 */

import { forgetVerifiedSignatures, parseRecord, verifyProofs } from "@oip/core";
import { KeyMind, LATER, witness } from "@oip/testkit/minds";
import { ratiosOver, reportMeasured } from "@oip/testkit/ratio";
import { describe, expect, test } from "vitest";

import { type EvidenceView, LogBook, verifyLog } from "../src/index.ts";

export const BUDGETS = {
  /** Verify an identity log of 1,000 events, in milliseconds. */
  logOfAThousandEvents: 3500,
  /**
   * The same against a thousand times `parseRecord` and `verifyProofs` of
   * one event, as a ratio: what replaying adds to reading and checking each
   * event's signature. It measures at 0.93 to 1.2: a run of the log takes
   * seconds, so a turn is long enough for the machine's speed to change
   * within it (ADR-0020). A signature checked twice would pass 2.
   */
  overTheSignatures: 1.5,
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

  test("verify an identity log of 1,000 events", async () => {
    const check = verifyLog(events, { evidence, asOf: LATER });
    expect(check.ok && check.value.entries).toHaveLength(EVENTS);
    const log = "verifyLog: 1,000 events";
    const measured = await ratiosOver(
      () => {
        // What is timed is the checking of a signature: none is remembered from the call before.
        forgetVerifiedSignatures();
        const parsed = parseRecord(oneEvent);
        return parsed.ok && verifyProofs(parsed.value).verified.length;
      },
      {
        [log]: () => {
          forgetVerifiedSignatures();
          return verifyLog(events, { evidence, asOf: LATER });
        },
      },
      // A run of the log takes seconds. A few turns say enough, and the one event is sampled
      // for a tenth as long as the log beside it, not for a quarter of a millisecond.
      { minTurns: 7, budgetMs: 0, sampleMs: 200, warmupMs: 0 },
    );
    reportMeasured("@oip/identity", "parseRecord + verifyProofs: one event of the log", measured);
    expect(measured.fastest[log]).toBeLessThan(BUDGETS.logOfAThousandEvents);
    expect((measured.ratios[log] ?? Number.NaN) / EVENTS).toBeLessThan(BUDGETS.overTheSignatures);
  });

  test("verify again a log whose signatures verified before, for a fraction of the first time", async () => {
    const again = "verifyLog: 1,000 events, all verified before";
    // Turn about, the log is verified with no signature remembered, and then again with all of
    // them: by a verifier that was sent a longer copy of it, or the same one.
    const measured = await ratiosOver(
      () => {
        forgetVerifiedSignatures();
        return verifyLog(events, { evidence, asOf: LATER });
      },
      { [again]: () => verifyLog(events, { evidence, asOf: LATER }) },
      { minTurns: 3, budgetMs: 0, warmupMs: 0 },
    );
    reportMeasured("@oip/identity", "verifyLog: 1,000 events, none verified before", measured);
    expect((measured.ratios[again] ?? Number.NaN) * BUDGETS.againOverFirst).toBeLessThan(1);
  });

  test("answer at once for a log a book has verified", async ({ bench }) => {
    const book = new LogBook(evidence);
    book.hold(events, LATER);
    expect(book.log(mind).ok).toBe(true);
    const again = await bench("LogBook.log: a log verified before", () => book.log(mind)).run();
    expect(again.latency.p50).toBeLessThan(0.05);
  });
});
