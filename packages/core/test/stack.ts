// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

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
