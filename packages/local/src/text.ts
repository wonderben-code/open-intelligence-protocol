// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What is printed, made safe to print. Much of what a program shows is a
 * stranger's words: a name in a profile, the text of a packet, an indexer's
 * reason. A terminal obeys control characters in what it is given, so they
 * are never passed on: a packet must not be able to clear the screen, move
 * the cursor, or write over the line that says who it is from.
 */

/**
 * Characters a terminal acts on, or that reorder what is shown, besides the
 * C0 controls: DEL, the C1 controls, the line and paragraph separators, and
 * the controls of bidirectional text. `JSON.stringify` leaves these as they
 * are.
 */
const BEYOND_C0 = "\\u007f-\\u009f\\u2028\\u2029\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069";
const UNSAFE = new RegExp(`[\\u0000-\\u001f${BEYOND_C0}]`, "gu");
const UNSAFE_IN_JSON = new RegExp(`[${BEYOND_C0}]`, "gu");

const escaped = (character: string): string =>
  `\\u${(character.codePointAt(0) ?? 0).toString(16).padStart(4, "0")}`;

/** One line to print: every character a terminal would act on is shown as its escape, as `\u001b`. */
export function printable(line: string): string {
  return line.replace(UNSAFE, escaped);
}

/**
 * A value as JSON to print. It is the same JSON: the characters that
 * `JSON.stringify` leaves as they are and a terminal would act on are
 * written as escapes, which a JSON parser reads back as the same string.
 */
export function printableJson(value: unknown): string {
  // A number too large for JSON is written as its digits: what is printed is never cut short by one.
  const whole = (_: string, member: unknown): unknown =>
    typeof member === "bigint" ? String(member) : member;
  // Inside JSON these characters occur in strings alone, where an escape is theirs to have.
  return JSON.stringify(value, whole, 2).replace(UNSAFE_IN_JSON, escaped);
}

/** A stranger's text as lines to print, each indented, and no more of them than `most`. */
export function quoted(text: string, most = 40): string[] {
  const lines = text.split(/\r\n|\r|\n/u);
  const shown = lines.slice(0, most).map((line) => `    ${line}`);
  return lines.length > most
    ? [...shown, `    … and ${String(lines.length - most)} more lines: --json has all of it`]
    : shown;
}

/** A count with its noun, in the singular for one: `1 event`, `2 events`. */
export function counted(count: number, noun: string, plural = `${noun}s`): string {
  return `${String(count)} ${count === 1 ? noun : plural}`;
}
