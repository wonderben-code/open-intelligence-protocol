// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The functions that never throw, called with the call stack all but spent:
 * each answers from the moment it can be entered, and is right again
 * afterwards. A program that judges what strangers send it is called from
 * wherever its caller happens to be.
 *
 * The calls are made by `spent-stack.node.ts`, in a Node.js process of its
 * own and not under the test runner: `inNode` says why. There the code is
 * also as cold as in a process that has just started, which is when the
 * fault of the first test was found.
 */

import { clause, inNode } from "@oip/testkit";
import { describe, expect, it } from "vitest";

type Tally = Readonly<Record<string, number>>;

const report = inNode(new URL("./spent-stack.node.ts", import.meta.url)) as {
  readonly keys: readonly {
    readonly answers: Tally;
    readonly cutShort: boolean;
    readonly verifiesAfter: boolean;
    readonly isKeyAfter: boolean;
  }[];
  readonly proofs: {
    readonly one: Tally;
    readonly all: Tally;
    readonly matches: Tally;
    readonly after: unknown;
  };
  readonly records: {
    readonly text: Tally;
    readonly bytes: Tally;
    readonly extension: Tally;
    readonly critical: Tally;
    readonly after: boolean;
  };
};

/** The answers a function gave, 200 in all, each of a kind that is allowed. */
function expectAnswers(tally: Tally, allowed: readonly string[]): void {
  expect(Object.values(tally).reduce((sum, count) => sum + count, 0)).toBe(200);
  expect(Object.keys(tally).filter((kind) => !allowed.includes(kind))).toStrictEqual([]);
}

describe(`${clause("core 4.4")} a check that could not be finished`, () => {
  it("leaves no trace: a spent stack never marks an honest key as bad", () => {
    // A key that passes the order check is remembered. A check cut short must not
    // be remembered as a no: when every answer was remembered, one call from a deep
    // stack turned an honest key away until the memory forgot it.
    expect(report.keys).toHaveLength(4);
    for (const key of report.keys) {
      // It answers from the moment it can be entered, and never throws.
      expectAnswers(key.answers, ["boolean"]);
      // Whatever it could answer then, it answers rightly now.
      expect(key.verifiesAfter).toBe(true);
      expect(key.isKeyAfter).toBe(true);
    }
    // Whether a check really was cut short depends on the engine, so it is not asserted
    // here. `ed25519.stack.test.ts` makes the same fault without the engine's help.
    expect(report.keys.filter((key) => key.cutShort).length).toBeGreaterThanOrEqual(0);
  });
});

describe("judging with the stack all but spent", () => {
  it("answers for a proof and does not throw, and is right again afterwards", () => {
    // A rejection says why; an acceptance is the whole of one.
    expectAnswers(report.proofs.one, ["accepted", "refused with a reason"]);
    expectAnswers(report.proofs.all, [
      "1 verified, 0 rejected, 0 issues",
      "0 verified, 1 rejected, 0 issues",
      "0 verified, 0 rejected, 1 issues",
    ]);
    expectAnswers(report.proofs.matches, ["boolean"]);
    expect(report.proofs.after).toStrictEqual([true, 1, true]);
  });

  it("answers for a record read from text and does not throw", () => {
    for (const read of [report.records.text, report.records.bytes, report.records.extension]) {
      expectAnswers(read, ["read", "refused with a reason"]);
    }
    expectAnswers(report.records.critical, ["array"]);
    expect(report.records.after).toBe(true);
  });
});
