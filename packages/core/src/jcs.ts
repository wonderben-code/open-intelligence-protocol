// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical form (core Section 2): the JSON Canonicalization Scheme,
 * RFC 8785. Content IDs and signatures are computed over it, so two
 * implementations must produce the same bytes for the same value.
 */

import { type JsonValue, type Limits, validateJson } from "@oip/schema";
import serialise from "canonicalize";

import { utf8 } from "./bytes.ts";
import { errorFrom } from "./errors.ts";

/**
 * The library's serialiser, typed for the values it is given here. It gives
 * no text only for a value with no JSON form, such as `undefined`, and a
 * `JsonValue` is never one.
 */
const serialiseJson = serialise as (value: JsonValue) => string;

/**
 * The canonical form of a value that is known to be within the profile of
 * core Section 1. Everything in this package calls it only after
 * `validateJson`: the serialiser also writes floats, and calls `toJSON`
 * where it finds one, and neither may ever be hashed or signed.
 */
export function canonicalText(value: JsonValue): string {
  // The serialiser calls a `toJSON` wherever it finds one, and it would find one
  // on every value if other code had put it on the prototype of all objects or
  // of all arrays: every record would then have the same canonical form, and
  // the same content ID. Nothing is hashed or signed in a process in that state.
  if ("toJSON" in Array.prototype || "toJSON" in Object.prototype) {
    throw new Error(
      "Object.prototype or Array.prototype has a toJSON: nothing can be serialised safely",
    );
  }
  return serialiseJson(value);
}

/** The size in UTF-8 bytes of a string as canonical form writes it, quotation marks included. */
function stringSize(text: string): number {
  let size = 2;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit === 0x22 || unit === 0x5c) size += 2;
    // \b, \t, \n, \f and \r have short escapes; the other controls are written \u00XX.
    else if (unit < 0x20) {
      size += unit === 8 || unit === 9 || unit === 10 || unit === 12 || unit === 13 ? 2 : 6;
    } else if (unit < 0x80) size += 1;
    // Each half of a surrogate pair counts two of the pair's four bytes.
    else if (unit < 0x800 || (unit >= 0xd800 && unit <= 0xdfff)) size += 2;
    else size += 3;
  }
  return size;
}

/**
 * The size in bytes of the canonical form of a value that is known to be
 * within the profile, counted without writing it, and counted no further
 * than `limit`: the answer is the size if it is within the limit, and
 * `limit + 1` if it is not.
 *
 * A size limit is checked this way. Writing out a value of many megabytes
 * to learn that it is over one would cost several times its size in memory.
 */
export function canonicalSizeUpTo(value: JsonValue, limit: number): number {
  let size = 0;
  const pending: JsonValue[] = [value];
  for (let next = pending.pop(); next !== undefined; next = pending.pop()) {
    if (next === null || next === true) size += 4;
    else if (next === false) size += 5;
    // An integer in its shortest form. -0 is written 0.
    else if (typeof next === "number") size += String(next).length;
    else if (typeof next === "string") size += stringSize(next);
    else if (Array.isArray(next)) {
      // The brackets, and a comma between each two elements.
      size += next.length === 0 ? 2 : next.length + 1;
      for (const element of next as readonly JsonValue[]) pending.push(element);
    } else {
      const names = Object.keys(next);
      size += names.length === 0 ? 2 : names.length + 1;
      for (const name of names) {
        // The name, the colon and, later, the value.
        size += stringSize(name) + 1;
        pending.push((next as Readonly<Record<string, JsonValue>>)[name] as JsonValue);
      }
    }
    if (size > limit) return limit + 1;
  }
  return size;
}

/** As `canonicalText`, in UTF-8. */
export function canonicalBytesOf(value: JsonValue): Uint8Array {
  return utf8(canonicalText(value));
}

/**
 * The canonical form of a JSON value (core 2.1): members sorted by the
 * UTF-16 code units of their names, no white space, minimal escaping, and
 * integers in their shortest decimal form.
 *
 * The value may nest as deep as a container does (core 1.9), so that a page
 * of records can be written. Whether each record in it keeps the limit is
 * `validateRecord`'s question.
 *
 * A value that did not come from text is read up to `MAX_VALUES` values. A
 * caller that has accepted a longer container says so with `limits`.
 *
 * @throws OipError `invalid-record` if the value is not within the JSON
 * profile of core Section 1 (a float, a Date, an unpaired surrogate, ...).
 * Nothing outside the profile has a canonical form.
 * @throws Error if other code in the process has put a `toJSON` on the
 * prototype of every object or every array: nothing is serialised then.
 */
export function canonicalize(value: unknown, limits?: Limits): string {
  const checked = validateJson(value, "container", limits);
  if (!checked.ok) throw errorFrom(checked);
  return canonicalText(checked.value);
}

/** The canonical form of a JSON value, in UTF-8: the bytes that are hashed. */
export function canonicalBytes(value: unknown, limits?: Limits): Uint8Array {
  return utf8(canonicalize(value, limits));
}
