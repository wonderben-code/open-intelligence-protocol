// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Checks that were cut short (ADR-0010).
 *
 * A function that judges answers and does not throw, with the call stack
 * all but spent as at any other time: whatever fails inside it becomes a
 * refusal. A refusal reached that way is true of the moment, and not of
 * what was judged. Nothing may keep it: not a verdict a book would
 * remember, not a record held with the proofs that verified, not a place in
 * a log.
 *
 * The same holds of a process in no state to judge anything, which
 * `UnfitProcess` reports: its refusals are true while that lasts.
 *
 * So each place that turns a failure into an answer notes it here
 * (`noteCutShort`), and each function that judges for a caller asks whether
 * anything was noted while it worked (`judging`, `finding`). If so it
 * refuses with the clause `implementation limit`, or finds nothing, and the
 * caller asks again. The count says nothing of any input, and is read only
 * as a difference.
 */

import type { Validation } from "./issue.ts";

/**
 * Thrown where nothing can be judged in the state the process is in: other
 * code has put a `toJSON` on every object, for one, so that nothing can be
 * serialised. It says nothing of the value that was being judged.
 */
export class UnfitProcess extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnfitProcess";
  }
}

let noted = 0;

/**
 * What each engine says, word for word, of a call stack that is spent: V8
 * and JavaScriptCore in a `RangeError`, SpiderMonkey in an `InternalError`.
 */
const SPENT = new Set([
  "Maximum call stack size exceeded",
  "Maximum call stack size exceeded.",
  "too much recursion",
]);

/**
 * Whether a failure is the engine's for want of room, or the process's for
 * the state it is in, and no fault of what was being judged.
 *
 * A spent call stack is told by the engine's own message, whole. The class
 * of the error does not tell: a library throws a `RangeError` for a value
 * out of range, and such a value may come from outside. Nor does a part of
 * a message: a parser's message may quote the text it was given. A spent
 * stack also stops a regular expression from being compiled the first time
 * it is used, which V8 reports as a `SyntaxError` that names the expression
 * and ends in "Stack overflow"; every expression here is the code's own.
 *
 * What was thrown may be anything a caller's value chose to throw. No
 * getter of it is run: the message read is an own data property, as an
 * engine's error has it.
 */
function noFaultOfTheValue(error: unknown): boolean {
  if (error instanceof UnfitProcess) return true;
  if (!(error instanceof Error)) return false;
  const message = Object.getOwnPropertyDescriptor(error, "message")?.value as unknown;
  if (typeof message !== "string") return false;
  return (
    SPENT.has(message) ||
    (error instanceof SyntaxError &&
      message.startsWith("Invalid regular expression: ") &&
      message.endsWith(": Stack overflow"))
  );
}

/**
 * Notes a failure that is about to be turned into an answer, if it is the
 * engine's for want of room or the process's for its state. Call it first
 * in a `catch` that answers for whatever was thrown.
 *
 * It never throws, whatever it is given: a failure it cannot so much as
 * look at (a proxy that has been revoked, for one) is counted, since
 * nothing shows it is not one.
 */
export function noteCutShort(error: unknown): void {
  let cut = true;
  try {
    cut = noFaultOfTheValue(error);
  } catch {
    // The look itself failed: counted.
  }
  if (cut) noted++;
}

/**
 * How many failures for want of room have been noted. Two readings that
 * differ mean that a check between them was cut short, and that what was
 * worked out in between is not to be kept.
 */
export function cutShortCount(): number {
  return noted;
}

/** The message of a refusal given in place of an answer that a cut-short check went into. */
export const CUT_SHORT =
  "this could not be judged: the call stack was too nearly spent, or the process is in no state to serialise anything. Ask again";

/** A refusal: the reasons there is no answer. */
type Refusal = Extract<Validation<never>, { readonly ok: false }>;

const REFUSAL: Refusal = Object.freeze({
  ok: false,
  issues: Object.freeze([
    Object.freeze({ path: "", message: CUT_SHORT, clause: "implementation limit" }),
  ]) as unknown as Refusal["issues"],
});

/**
 * The refusal given in place of an answer that a cut-short check went into:
 * the clause is `implementation limit`, and it says nothing of what was
 * judged. It is frozen.
 */
export function cutShort(): Refusal {
  return REFUSAL;
}

/**
 * Works out an answer for a caller, and refuses if any check was cut short
 * on the way: an answer built on a refusal that is true only of the moment
 * would be kept as if it were a verdict.
 *
 * It also answers where the work itself fails for want of room, at
 * whatever depth: a `catch` far below may find no room to answer in.
 * A failure that is no such thing is a mistake in the calling program or
 * in this one, and is not hidden.
 */
export function judging<T>(work: () => Validation<T>): Validation<T> {
  const before = noted;
  let answer: Validation<T>;
  try {
    answer = work();
  } catch (error) {
    noteCutShort(error);
    if (noted === before) throw error;
    return REFUSAL;
  }
  return noted === before ? answer : REFUSAL;
}

/**
 * As `judging`, for a function that answers with what it found or with
 * `undefined`: it finds nothing where a check was cut short. Such an answer
 * cannot say why, so a caller that keeps a "nothing" compares
 * `cutShortCount()` itself.
 */
export function finding<T>(work: () => T | undefined): T | undefined {
  const before = noted;
  let found: T | undefined;
  try {
    found = work();
  } catch (error) {
    noteCutShort(error);
    if (noted === before) throw error;
    return undefined;
  }
  return noted === before ? found : undefined;
}

// An engine compiles a function when it is first called, and that takes room on the call stack
// too. These are called where there is least of it, from a `catch`: they are called once here,
// with nothing, so that they are ready before they are needed. The count ends as it began.
noteCutShort(undefined);
judging(cutShort);
finding(cutShortCount);
