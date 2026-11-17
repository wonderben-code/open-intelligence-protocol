// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Results of judging input: a value, or the reasons there is none (ADR-0004). */

import type { Issue, JsonValue, Validation } from "@oip/schema";

/** Whether a JSON value is an object, and not an array or null. */
export function isJsonObject(value: JsonValue): value is Readonly<Record<string, JsonValue>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

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
  const [first, ...rest] = rejection.issues;
  return {
    ok: false,
    issues: [
      { ...first, path: path + first.path },
      ...rest.map((issue) => ({ ...issue, path: path + issue.path })),
    ],
  };
}
