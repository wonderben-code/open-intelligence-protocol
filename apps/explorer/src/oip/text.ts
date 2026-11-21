// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A stranger's words, made safe to show.
 *
 * A name, a summary and every string of a record are text that some mind
 * chose. A page shows them as text and never as markup. That leaves the
 * characters that act on what is around them: a control character, or one
 * that turns the direction of the line, so that what follows reads as
 * something else. Each is shown as its escape.
 */

/** A symbol that has nothing to see: the blank of the Braille patterns. */
const BLANK = String.fromCodePoint(0x2800);

/**
 * What acts on the text around it, or is not seen at all: a control or a
 * format character, one a display may leave out, one for private use or
 * that no script has, and a line end. The set is that of `@oip/schema`, for
 * what an issue quotes, and the blank besides.
 */
const ACTS = new RegExp(`[\\p{C}\\p{Zl}\\p{Zp}\\p{Default_Ignorable_Code_Point}${BLANK}]`, "gu");
/** More marks on one letter than a script puts there: the rest draw over the lines around. */
const PILED = /(\p{M}{4})(\p{M}+)/gu;
/** A mark with no letter of its own to stand on: it would stand on the page's. */
const LOOSE = /^\p{M}/u;

/** A character as its escape: `\u{202e}`. */
const escapeOf = (character: string): string =>
  `\\u{${(character.codePointAt(0) ?? 0).toString(16)}}`;

const escaped = (text: string): string => Array.from(text, escapeOf).join("");

/** Text with every character that acts shown as its escape, but for the line ends `kept`. */
function safe(text: string, kept = ""): string {
  return text
    .replace(ACTS, (character) => (character === kept ? character : escapeOf(character)))
    .replace(PILED, (_, stands: string, rest: string) => stands + escaped(rest))
    .replace(LOOSE, escapeOf);
}

/** One line of a stranger's words. */
export function shown(text: string): string {
  return safe(text);
}

/** What stands for a name that has nothing to see. */
export const NO_NAME = "(no name)";

/**
 * A name a mind gave itself, as a page shows it where the name is all there
 * is to see or to press: a name that is empty, or blank, is said to be none.
 */
export function shownName(name: string): string {
  const seen = shown(name);
  return /^\p{White_Space}*$/u.test(seen) ? NO_NAME : seen;
}

/** A record, or any value, as text of many lines: JSON, with every string made safe. */
export function shownJson(value: unknown): string {
  // Within JSON a line end is written as its escape already. Those between its lines stay.
  return safe(JSON.stringify(value, undefined, 2), "\n");
}
