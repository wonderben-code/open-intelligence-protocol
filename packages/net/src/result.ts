// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Results of judging input: a value, or the reasons there is none (ADR-0004). */

import {
  CUT_SHORT,
  cutShortCount,
  IMPLEMENTATION_LIMIT,
  noteCutShort,
  type Validation,
} from "@oip/schema";

/** A rejection: the reasons there is no value. */
export type Rejection = Extract<Validation<never>, { readonly ok: false }>;

/** A success. */
export function ok<T>(value: T): Validation<T> {
  return { ok: true, value };
}

/** A rejection for one reason. */
export function no(message: string, clause: string, path = ""): Rejection {
  return { ok: false, issues: [{ path, message, clause }] };
}

/** A rejection for the reasons of another, with its paths under `path`. */
export function under(path: string, rejection: Rejection): Rejection {
  const [first, ...rest] = rejection.issues;
  return {
    ok: false,
    issues: [
      { ...first, path: path + first.path },
      ...rest.map((issue) => ({ ...issue, path: path + issue.path })),
    ],
  };
}

/** The refusal for a check that could not be made. It says nothing of what was judged (ADR-0004). */
function cutShort(): Rejection {
  return { ok: false, issues: [{ path: "", message: CUT_SHORT, clause: IMPLEMENTATION_LIMIT }] };
}

/**
 * Works out an answer that is built from other answers, and refuses if any
 * check was cut short on the way (ADR-0004): with the call stack all but
 * spent, or in a process that can serialise nothing, a refusal from below
 * is true of the moment and not of what was judged, and an answer built on
 * it would be kept as if it were.
 *
 * A failure that is no such thing is a mistake in the calling program or in
 * this one, and is not hidden.
 */
export function judging<T>(work: () => Validation<T>): Validation<T> {
  const before = cutShortCount();
  let answer: Validation<T>;
  try {
    answer = work();
  } catch (error) {
    noteCutShort(error);
    if (cutShortCount() === before) throw error;
    return cutShort();
  }
  return cutShortCount() === before ? answer : cutShort();
}

/**
 * As `judging`, for a function that answers with what it found or with
 * `undefined`: it finds nothing where a check was cut short.
 */
export function finding<T>(work: () => T | undefined): T | undefined {
  const before = cutShortCount();
  let found: T | undefined;
  try {
    found = work();
  } catch (error) {
    noteCutShort(error);
    if (cutShortCount() === before) throw error;
    return undefined;
  }
  return cutShortCount() === before ? found : undefined;
}
