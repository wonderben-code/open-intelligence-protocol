// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * With the call stack all but spent, no function that judges throws, and
 * none gives the answer that a record it could not judge was there to
 * change (ADR-0010). The stack is spent in a Node.js process of its own and
 * not under the test runner: `inNode` says why.
 */

import { clause, inNode } from "@oip/testkit";
import { describe, expect, it } from "vitest";

type Tally = Readonly<Record<string, number>>;

const report = inNode(new URL("./spent-stack.node.ts", import.meta.url)) as {
  readonly withdrawn: { readonly status: Tally; readonly after: string };
  readonly broken: { readonly status: Tally; readonly after: string };
  readonly revoked: {
    readonly counts: Tally;
    readonly revoked: Tally;
    readonly after: readonly [string, string];
  };
  readonly superseded: {
    readonly inForce: Tally;
    readonly counts: Tally;
    readonly after: readonly [string, string];
  };
};

const total = (tally: Tally): number => Object.values(tally).reduce((sum, count) => sum + count, 0);

/** The kinds of answer given, apart from those allowed. */
const others = (tally: Tally, ...allowed: string[]): string[] =>
  Object.keys(tally).filter((kind) => !allowed.includes(kind));

describe(`${clause("L2 8")} a status asked for with the stack all but spent`, () => {
  it("is the status, or a refusal for want of room: never the status a record changed", () => {
    expect(total(report.withdrawn.status)).toBe(200);
    // Not `open`, which is what the Intent would be without its withdrawal.
    expect(others(report.withdrawn.status, "withdrawn", "implementation limit")).toStrictEqual([]);
    expect(report.withdrawn.after).toBe("withdrawn");
    expect(total(report.broken.status)).toBe(200);
    // Not `accepted`, without the Receipt; not `proposed`, without a party's signature.
    expect(others(report.broken.status, "broken", "implementation limit")).toStrictEqual([]);
    expect(report.broken.after).toBe("broken");
  });
});

describe(`${clause("L1 11.5", "L2 6.2")} what was taken away, asked about with the stack all but spent`, () => {
  it("is never given back: not by a revocation that could not be judged", () => {
    expect(total(report.revoked.counts)).toBe(200);
    // The agent signed after the revocation: the record never counts for the principal.
    expect(others(report.revoked.counts, "undefined, false")).toStrictEqual([]);
    expect(total(report.revoked.revoked)).toBe(200);
    // Revoked at 30, or no answer: never "not revoked".
    expect(Object.keys(report.revoked.revoked)).not.toContain("undefined");
    expect(
      others(report.revoked.revoked, "implementation limit").every((kind) => /^\d+$/u.test(kind)),
    ).toBe(true);
    expect(report.revoked.after[0]).toBe("undefined, false");
    expect(report.revoked.after[1]).toMatch(/^\d+$/u);
  });

  it("is never given back: not by a charter that could not be judged", () => {
    expect(total(report.superseded.inForce)).toBe(200);
    // The second charter, or no answer: never the first, which the second replaced.
    expect(others(report.superseded.inForce, "the second", "implementation limit")).toStrictEqual(
      [],
    );
    expect(total(report.superseded.counts)).toBe(200);
    expect(others(report.superseded.counts, "false")).toStrictEqual([]);
    expect(report.superseded.after).toStrictEqual(["the second", "false"]);
  });
});
