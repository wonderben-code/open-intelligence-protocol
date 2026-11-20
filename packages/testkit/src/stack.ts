// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { setFlagsFromString } from "node:v8";
import { runInThisContext } from "node:vm";

/**
 * Tells the engine never to compile these functions again for speed, so
 * that a frame of each stays the size it is.
 *
 * A script that finds where the call stack ends by descending, and then
 * descends again to a chosen distance from the end, counts on the frames of
 * both descents being one size. The engine compiles a function that runs
 * often again, more than once and on a thread of its own, and each
 * compilation has frames of another size. Whether the second descent ran
 * the code the first did then depended on how fast the machine was: on some
 * it ended before it reached the depth asked for.
 *
 * This is V8's own request for it, in the syntax V8 keeps for its tests.
 * The syntax is allowed while the request is read, and not after. What the
 * functions call is compiled as it would be anyway.
 */
export function keepFramesOneSize(...functions: readonly ((...args: never[]) => unknown)[]): void {
  setFlagsFromString("--allow-natives-syntax");
  try {
    const keep = runInThisContext("(function (f) { %NeverOptimizeFunction(f); })") as (
      f: unknown,
    ) => void;
    for (const one of functions) keep(one);
  } finally {
    setFlagsFromString("--no-allow-natives-syntax");
  }
}

/**
 * Calls a function with the call stack all but spent, at one depth after
 * another near the end of it. Any function throws when there is no stack
 * left even to enter it; a function that promises never to throw must answer
 * from the moment it can be entered, however little room it then has.
 *
 * The stack is filled until a call fails. On the way back up the function is
 * tried from each frame, so that it runs out of stack at one place after
 * another inside itself, until it has answered `answers` times. The answers
 * are returned, least room first. Once the function has answered, a throw
 * from a shallower frame is the function's own, and is thrown on from here.
 *
 * Call it from a script run with `inNode`, not from a test: under the test
 * runner an import can read as `undefined` when the stack is spent, which
 * is the runner's doing and no fault of the function.
 */
export function withStackSpent<T>(run: () => T, answers = 200): T[] {
  const given: T[] = [];
  let leaked: unknown;
  const descend = (): void => {
    try {
      descend();
    } catch {
      // No deeper: the stack is spent.
    }
    if (given.length >= answers) return;
    try {
      // An index, not push: a call of its own could be the one that finds no room.
      given[given.length] = run();
    } catch (error) {
      if (given.length > 0) leaked ??= error;
    }
  };
  descend();
  if (leaked !== undefined) {
    throw new Error("it threw with more room than it had when it first answered", {
      cause: leaked,
    });
  }
  return given;
}
