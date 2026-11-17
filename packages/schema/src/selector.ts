// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The selector grammar of the policy language (Layer 1, 11.3). */

// One step: `.name`, `[index]` or `["name"]`. The quoted form is a JSON string.
const STEP = /\.([A-Za-z0-9_]+)|\[(0|[1-9][0-9]*)\]|\[("(?:[^"\\]|\\[^\n])*")\]/y;

/** One step of a selector's path: a member name or an array index. */
export type SelectorStep = string | number;

/**
 * Parses a selector into its path. `.` alone is the empty path, the value
 * itself. Returns `undefined` when the string is not a selector.
 */
export function parseSelector(selector: unknown): SelectorStep[] | undefined {
  if (typeof selector !== "string" || selector === "") return undefined;
  if (selector === ".") return [];
  const path: SelectorStep[] = [];
  let position = 0;
  while (position < selector.length) {
    STEP.lastIndex = position;
    const match = STEP.exec(selector);
    if (match === null) return undefined;
    const [, name, index, quoted] = match;
    if (name !== undefined) {
      path.push(name);
    } else if (index !== undefined) {
      path.push(Number(index));
    } else {
      let parsed: unknown;
      try {
        parsed = JSON.parse(quoted ?? "");
      } catch {
        return undefined;
      }
      if (typeof parsed !== "string") return undefined;
      path.push(parsed);
    }
    position = STEP.lastIndex;
  }
  return path;
}
