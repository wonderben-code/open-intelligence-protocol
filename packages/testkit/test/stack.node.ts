// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `withStackSpent` asked about functions whose behaviour is known: one that
 * always answers once it can be entered, and one that throws after it has
 * answered, with more room than it had. `stack.test.ts` runs this in a
 * process of its own.
 *
 * Usage: node --conditions=@oip/source stack.node.ts
 */

import { withStackSpent } from "../src/index.ts";

/** What the helper did with a function: how many answers it gave back, or what it threw. */
function asked(run: () => number, answers?: number): { answers: number } | { threw: string } {
  try {
    return { answers: withStackSpent(run, answers).length };
  } catch (error) {
    const cause = (error as { cause?: unknown }).cause;
    return {
      threw: `${(error as Error).message}: ${cause instanceof Error ? cause.message : String(cause)}`,
    };
  }
}

let calls = 0;
const report = {
  // It answers from the moment it can be entered.
  steady: asked(() => 1),
  fewer: asked(() => 1, 7),
  // It answers four times, and throws the fifth time, from a frame with more room.
  leaky: asked(() => {
    calls++;
    if (calls === 5) throw new Error("the function's own");
    return calls;
  }),
  // It never answers: every throw is one from before its first answer, and none is reported.
  never: asked(() => {
    throw new Error("always");
  }),
};
process.stdout.write(JSON.stringify(report));
