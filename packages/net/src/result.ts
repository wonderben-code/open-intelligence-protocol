// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Results of judging input: a value, or the reasons there is none (ADR-0004, ADR-0010). */

import { cutShort, cutShortCount, noteCutShort, type Validation } from "@oip/schema";

// How a check that was cut short is refused, by whatever answers with a result or with what
// it found (ADR-0010). One rule, kept in one place, for every package.
export { finding, judging } from "@oip/schema";

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

/**
 * As `judging` of `@oip/schema`, for work that waits (ADR-0010). The count is read before
 * the work starts and after it ends: other work of the process that is cut short in
 * between refuses this answer too, once, and never makes it wrong.
 */
export async function judgingLater<T>(work: () => Promise<Validation<T>>): Promise<Validation<T>> {
  const before = cutShortCount();
  let settled: Validation<T>;
  try {
    settled = await work();
  } catch (error) {
    noteCutShort(error);
    if (cutShortCount() === before) throw error;
    return cutShort();
  }
  return cutShortCount() === before ? settled : cutShort();
}
