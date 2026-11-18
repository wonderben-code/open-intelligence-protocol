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

import { inNode } from "@oip/testkit";
import { describe, expect, it } from "vitest";

type Tally = Readonly<Record<string, number>>;

const report = inNode(new URL("./spent-stack.node.ts", import.meta.url)) as {
  readonly logs: { readonly verified: Tally; readonly after: boolean };
  readonly records: { readonly signed: Tally; readonly last: string; readonly after: string };
};

const total = (tally: Tally) => Object.values(tally).reduce((sum, count) => sum + count, 0);

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
