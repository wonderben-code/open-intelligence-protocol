// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The two helpers the compiled validators call. They replace Ajv's runtime
 * modules, so that the published package has no dependency on Ajv.
 */

/** The length of a string in Unicode code points (core 1.8). */
export function codePointLength(value: string): number {
  let length = 0;
  for (let i = 0; i < value.length; i++) {
    length++;
    const unit = value.charCodeAt(i);
    // A high surrogate followed by a low surrogate is one code point.
    if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < value.length) {
      const next = value.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i++;
    }
  }
  return length;
}

/** Whether two JSON values are equal, member for member. Member order does not matter. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const left = a as Readonly<Record<string, unknown>>;
  const right = b as Readonly<Record<string, unknown>>;
  const keys = Object.keys(left);
  if (keys.length !== Object.keys(right).length) return false;
  for (const key of keys) {
    if (!Object.hasOwn(right, key) || !deepEqual(left[key], right[key])) return false;
  }
  return true;
}
