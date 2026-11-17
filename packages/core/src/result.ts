// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Results of judging input: a value, or the reasons there is none (ADR-0004). */

import type { Issue, Validation } from "@oip/schema";

export type { Issue, Validation };

/** A success. */
export function ok<T>(value: T): Validation<T> {
  return { ok: true, value };
}

/** A rejection for one reason. */
export function no<T>(message: string, clause: string, path = ""): Validation<T> {
  return { ok: false, issues: [{ path, message, clause }] };
}

/** A rejection for the reasons of another, with its paths under `path`. */
export function under<T>(
  path: string,
  rejection: { readonly issues: readonly [Issue, ...Issue[]] },
): Validation<T> {
  const [first, ...rest] = rejection.issues.map((issue) => ({
    ...issue,
    path: path + issue.path,
  })) as [Issue, ...Issue[]];
  return { ok: false, issues: [first, ...rest] };
}
