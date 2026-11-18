// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Results of judging input: a value, or the reasons there is none (ADR-0004). */

import type { Issue, JsonValue, Validation } from "@oip/schema";
import { CUT_SHORT, IMPLEMENTATION_LIMIT, noteCutShort } from "@oip/schema";

/** Whether a JSON value is an object, and not an array or null. */
export function isJsonObject(value: JsonValue): value is Readonly<Record<string, JsonValue>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A rejection: the reasons there is no value. */
export type Rejection = Extract<Validation<never>, { readonly ok: false }>;

/**
 * Freezes a value and everything it holds, and returns it. What this package
 * hands out it also keeps, so none of it may be changed by whoever reads it.
 * A part that is already frozen was frozen here, with everything in it.
 */
export function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const inner of Object.values(value)) deepFreeze(inner);
  return value;
}

/**
 * A member of an options object, if it is the object's own. Options arrive
 * from callers that TypeScript does not check, and a member found on a
 * prototype was not given by anyone.
 */
export function own(options: unknown, name: string): unknown {
  try {
    return typeof options === "object" && options !== null && Object.hasOwn(options, name)
      ? (options as Readonly<Record<string, unknown>>)[name]
      : undefined;
  } catch (error) {
    noteCutShort(error);
    // An object that cannot be read gives nothing.
    return undefined;
  }
}

/**
 * The refusal given in place of an answer that a cut-short check went into:
 * a failure for want of room on the call stack, turned into a refusal
 * somewhere on the way. Such an answer is true of the moment and not of
 * what was judged, so it is neither given as a verdict nor kept.
 */
export function cutShort(): Validation<never> {
  return { ok: false, issues: [{ path: "", message: CUT_SHORT, clause: IMPLEMENTATION_LIMIT }] };
}

/** A success. */
export function ok<T>(value: T): Validation<T> {
  return { ok: true, value };
}

/** A rejection for one reason. */
export function no(message: string, clause: string, path = ""): Rejection {
  return { ok: false, issues: [{ path, message, clause }] };
}

/** A rejection for the reasons of another, with its paths under `path`. */
export function under(
  path: string,
  rejection: { readonly issues: readonly [Issue, ...Issue[]] },
): Rejection {
  const [first, ...rest] = rejection.issues;
  return {
    ok: false,
    issues: [
      { ...first, path: path + first.path },
      ...rest.map((issue) => ({ ...issue, path: path + issue.path })),
    ],
  };
}
