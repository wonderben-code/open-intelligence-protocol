// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { inNode } from "../src/index.ts";

describe("withStackSpent", () => {
  // The checks that a function never throws at a spent stack rest on this helper telling a
  // throw of the function's own from one made before it could be entered.
  const report = inNode(new URL("./stack.node.ts", import.meta.url));

  it("gives the answers of a function that answers whenever it can be entered", () => {
    expect(report).toMatchObject({ steady: { answers: 200 }, fewer: { answers: 7 } });
  });

  it("throws for a function that throws after it has answered, with more room than it had", () => {
    expect(report).toMatchObject({
      leaky: {
        threw: "it threw with more room than it had when it first answered: the function's own",
      },
    });
  });

  it("reports nothing of a function that never answers: it gives back no answer at all", () => {
    // A caller that expects answers sees there are none.
    expect(report).toMatchObject({ never: { answers: 0 } });
  });
});

describe("keepFramesOneSize", () => {
  // The checks made at a chosen distance from the end of the stack rest on a descent whose
  // frames are one size: it is found to end at one depth, and reaches that depth again.
  const frames = (...args: string[]) =>
    inNode(new URL("./frames.node.ts", import.meta.url), args) as {
      readonly depths: number;
      readonly short: number;
      readonly syntax: string;
      readonly first: number;
    };

  it("makes a descent end at one depth however often it runs, and reach that depth again", () => {
    const kept = frames("kept");
    expect(kept.first).toBeGreaterThan(1000);
    expect({ depths: kept.depths, short: kept.short }).toStrictEqual({ depths: 1, short: 0 });
  });

  it("leaves the engine's own syntax unread once it has asked", () => {
    expect(frames("kept").syntax).toBe("refused");
    expect(frames().syntax).toBe("refused");
  });
});
