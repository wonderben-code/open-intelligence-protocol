// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The selector grammar of the policy language (Layer 1, 11.3). */

import { noteCutShort } from "./cut-short.ts";

/** One step of a selector's path: a member name or an array index. */
export type SelectorStep = string | number;

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const NEWLINE = 0x0a;

function isNameCharacter(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) || // 0-9
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    code === 0x5f // _
  );
}

const isDigit = (code: number) => code >= 0x30 && code <= 0x39;

/**
 * Parses a selector into its path. `.` alone is the empty path, the value
 * itself. Otherwise a selector is one or more steps: `.name`, `[index]` or
 * `["name"]`, where the quoted form is a JSON string. Returns `undefined`
 * when the string is not a selector.
 *
 * It scans by hand, in one pass and without recursion, so that a selector of
 * any length costs time in proportion to its length and nothing else.
 */
export function parseSelector(selector: unknown): SelectorStep[] | undefined {
  if (typeof selector !== "string" || selector === "") return undefined;
  if (selector === ".") return [];
  const path: SelectorStep[] = [];
  const end = selector.length;
  let at = 0;
  while (at < end) {
    if (selector[at] === ".") {
      let stop = at + 1;
      while (stop < end && isNameCharacter(selector.charCodeAt(stop))) stop++;
      if (stop === at + 1) return undefined;
      path.push(selector.slice(at + 1, stop));
      at = stop;
    } else if (selector[at] === "[" && selector.charCodeAt(at + 1) === QUOTE) {
      // Find the closing quote, stepping over escaped characters.
      let stop = at + 2;
      while (stop < end && selector.charCodeAt(stop) !== QUOTE) {
        if (selector.charCodeAt(stop) === BACKSLASH) {
          stop++;
          if (stop >= end || selector.charCodeAt(stop) === NEWLINE) return undefined;
        }
        stop++;
      }
      if (stop >= end || selector[stop + 1] !== "]") return undefined;
      let name: unknown;
      try {
        name = JSON.parse(selector.slice(at + 1, stop + 1));
      } catch (error) {
        noteCutShort(error);
        return undefined;
      }
      if (typeof name !== "string") return undefined;
      path.push(name);
      at = stop + 2;
    } else if (selector[at] === "[") {
      let stop = at + 1;
      while (stop < end && isDigit(selector.charCodeAt(stop))) stop++;
      const digits = selector.slice(at + 1, stop);
      // A non-negative integer without leading zeros.
      if (digits === "" || (digits.length > 1 && digits.startsWith("0"))) return undefined;
      if (selector[stop] !== "]") return undefined;
      // No array is this long, so any larger index selects nothing either.
      path.push(digits.length > 15 ? Number.MAX_SAFE_INTEGER : Number(digits));
      at = stop + 1;
    } else {
      return undefined;
    }
  }
  return path;
}
