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

/** The same script, told to ask a book's own operations first, in a process of their own. */
const { books } = inNode(new URL("./spent-stack.node.ts", import.meta.url), ["books"]) as {
  readonly books: {
    readonly witness: Tally;
    readonly witnessHeld: Tally;
    readonly hold: Tally;
    readonly log: Tally;
    readonly after: readonly string[];
  };
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

describe(`${clause("core 4.4", "core 9.5")} a book's own operations with the stack all but spent`, () => {
  const others = (tally: Tally, ...expected: string[]) =>
    Object.keys(tally).filter((kind) => !expected.includes(kind));

  it("never answers `ok` for a look that passed over an event that verifies", () => {
    // Ada's update removes a key. A look that reports nothing wrong and has not recorded it
    // would let that key sign until the next look.
    for (const looks of [books.witness, books.witnessHeld]) {
      expect(total(looks)).toBe(200);
      expect(
        others(looks, "ok, removal recorded", "implementation limit, removal not recorded"),
      ).toStrictEqual([]);
    }
  });

  it("takes a copy in whole or not at all, and answers for a log or refuses for want of room", () => {
    expect(total(books.hold)).toBe(200);
    expect(
      others(
        books.hold,
        "held, 2 events",
        // Taken in, and the log then asked for with no room to verify it.
        "held, implementation limit",
        "implementation limit, no log is held",
      ),
    ).toStrictEqual([]);
    expect(total(books.log)).toBe(200);
    expect(others(books.log, "2 events", "implementation limit")).toStrictEqual([]);
    // With room again, each is right.
    expect(books.after).toStrictEqual([
      "ok, removal recorded",
      "ok, removal recorded",
      "held, 2 events",
      "2 events",
    ]);
  });
});

describe("judging with the stack all but spent", () => {
  it("answers for a log and does not throw, and is right again afterwards", () => {
    expect(total(report.logs.verified)).toBe(200);
    // A log is verified whole, or refused for want of room: never in part, and never for a
    // reason that would be a verdict on it.
    expect(
      Object.keys(report.logs.verified).filter(
        (kind) => kind !== "2 events" && kind !== "implementation limit",
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
