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
