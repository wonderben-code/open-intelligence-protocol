// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Results of judging input: a value, or the reasons there is none (ADR-0004). */

import type { Validation } from "@oip/schema";

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
