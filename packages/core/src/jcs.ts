// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical form (core Section 2): the JSON Canonicalization Scheme,
 * RFC 8785. Content IDs and signatures are computed over it, so two
 * implementations must produce the same bytes for the same value.
 */

import { type JsonValue, validateJson } from "@oip/schema";
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
  return serialiseJson(value);
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
 * @throws OipError `invalid-record` if the value is not within the JSON
 * profile of core Section 1 (a float, a Date, an unpaired surrogate, ...).
 * Nothing outside the profile has a canonical form.
 */
export function canonicalize(value: unknown): string {
  const checked = validateJson(value, "container");
  if (!checked.ok) throw errorFrom(checked);
  return canonicalText(checked.value);
}

/** The canonical form of a JSON value, in UTF-8: the bytes that are hashed. */
export function canonicalBytes(value: unknown): Uint8Array {
  return utf8(canonicalize(value));
}
