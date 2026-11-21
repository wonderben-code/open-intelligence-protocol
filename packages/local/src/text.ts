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
 * Characters a terminal acts on, or that change what is shown around them,
 * besides the C0 controls: DEL, the C1 controls, the line and paragraph
 * separators, and every format character. Those are the controls of
 * bidirectional text, the characters of no width, the soft hyphen and the
 * tags. `JSON.stringify` leaves all of these as they are.
 */
const BEYOND_C0 = "\\x7f-\\x9f\\p{Zl}\\p{Zp}\\p{Cf}";
const UNSAFE = new RegExp(`[\\x00-\\x1f${BEYOND_C0}]`, "gu");
const UNSAFE_IN_JSON = new RegExp(`[${BEYOND_C0}]`, "gu");

/** A character as escapes, one for each of its halves: what a JSON parser reads back as the character. */
const escaped = (character: string): string =>
  Array.from(
    { length: character.length },
    (_, at) => `\\u${character.charCodeAt(at).toString(16).padStart(4, "0")}`,
  ).join("");

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

/**
 * A stranger's words as a string of JSON in ASCII, to set inside a sentence
 * of one's own: quoted, with every character beyond printable ASCII written
 * as its escape.
 *
 * Nothing in it ends the quotation early, turns the line round, looks like
 * a quotation mark, or is invisible. And it is text that any record can
 * hold, whatever the stranger wrote: half a pair of surrogates and a
 * noncharacter are escapes too.
 */
export function asciiJson(words: string): string {
  // Unit by unit, with no `u` flag: half a pair is written as what it is.
  return JSON.stringify(words).replace(/[^\x20-\x7e]/g, escaped);
}

/**
 * The JSON text of a value, as a string that a record can hold.
 *
 * `JSON.stringify` escapes half a pair of surrogates. A noncharacter it
 * writes as it is, and a record's strings have none (core 1.1): here each
 * is written as its escape, which says the same to whoever parses the text.
 *
 * @throws TypeError for what has no JSON text: `undefined`, or a value
 *   that cannot be walked, a cycle or a nesting too deep.
 */
export function jsonText(value: unknown): string {
  let text: unknown;
  try {
    text = JSON.stringify(value);
  } catch (error) {
    throw new TypeError("the value has no JSON text", { cause: error });
  }
  if (typeof text !== "string") throw new TypeError("the value has no JSON text");
  return text.replace(/\p{Noncharacter_Code_Point}/gu, escaped);
}

/** What stands in for a character that is none. */
const REPLACEMENT = String.fromCodePoint(0xfffd);
const ELLIPSIS = String.fromCodePoint(0x2026);

/**
 * A stranger's text as text a record can hold (core 1.1), and no longer
 * than it may be.
 *
 * Half a pair of surrogates and a noncharacter each become U+FFFD. A text
 * that is longer than `most` is cut between two characters, never through
 * one, and ends in an ellipsis.
 *
 * @param most - The most UTF-16 units of the result, which bounds its
 *   characters too. At least 1.
 */
export function recordText(text: string, most = Number.POSITIVE_INFINITY): string {
  // With the `u` flag a surrogate is one only where it is half a pair on its own.
  const sound = text.replace(/[\p{Cs}\p{Noncharacter_Code_Point}]/gu, REPLACEMENT);
  if (sound.length <= most) return sound;
  const kept = sound.slice(0, Math.max(0, most - 1));
  const last = kept.charCodeAt(kept.length - 1);
  // The cut fell between the halves of a pair: the first half goes too.
  const whole = last >= 0xd800 && last <= 0xdbff ? kept.slice(0, -1) : kept;
  return whole + ELLIPSIS;
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
