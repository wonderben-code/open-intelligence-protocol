// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The functions that never throw, called with the call stack all but spent:
 * each answers from the moment it can be entered, and is right again
 * afterwards.
 *
 * The calls are made by `spent-stack.node.ts`, in a Node.js process of its
 * own and not under the test runner: `inNode` says why.
 */

import { clause, inNode } from "@oip/testkit";
import { describe, expect, it } from "vitest";

type Tally = Readonly<Record<string, number>>;

const report = inNode(new URL("./spent-stack.node.ts", import.meta.url)) as {
  readonly cold: { readonly signed: Tally; readonly after: string; readonly log: boolean };
  readonly logs: { readonly verified: Tally; readonly after: boolean };
  readonly records: { readonly signed: Tally; readonly last: string; readonly after: string };
};

const total = (tally: Tally) => Object.values(tally).reduce((sum, count) => sum + count, 0);

describe(`${clause("core 4.4")} a book asked for the first time with the stack all but spent`, () => {
  it("keeps no verdict from a check that was cut short, and is right afterwards", () => {
    expect(total(report.cold.signed)).toBe(200);
    // It answers that the record is signed, or that it cannot tell: never anything else.
    expect(
      Object.keys(report.cold.signed).filter(
        (kind) => kind !== "signed at 10" && kind !== "signed at undefined",
      ),
    ).toStrictEqual([]);
    // With room again, it tells: the refusals it gave then were of the moment.
    expect(report.cold.after).toBe("signed at 10");
    expect(report.cold.log).toBe(true);
  });
});

describe("judging with the stack all but spent", () => {
  it("answers for a log and does not throw, and is right again afterwards", () => {
    expect(total(report.logs.verified)).toBe(200);
    // A log that is not verified is refused with a reason, never in part.
    expect(
      Object.keys(report.logs.verified).filter(
        (kind) => kind !== "2 events" && kind !== "refused with a reason",
      ),
    ).toStrictEqual([]);
    expect(report.logs.after).toBe(true);
  });

  it("answers for a record and its signer and does not throw", () => {
    expect(total(report.records.signed)).toBe(200);
    // Signed at the time the evidence gives, or not at all: never at another time.
    expect(
      Object.keys(report.records.signed).filter(
        (kind) =>
          kind !== "signed at 10" &&
          kind !== "signed at undefined" &&
          !kind.startsWith("not judged: "),
      ),
    ).toStrictEqual([]);
    expect(report.records.last).toBe("signed at 10");
    expect(report.records.after).toBe("signed at 10");
  });
});
