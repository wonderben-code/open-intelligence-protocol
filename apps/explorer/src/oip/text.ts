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

const ACTS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** A character as its escape: `\u{202e}`. */
const escapeOf = (character: string): string =>
  `\\u{${(character.codePointAt(0) ?? 0).toString(16)}}`;

/** One line of a stranger's words. */
export function shown(text: string): string {
  return text.replace(ACTS, escapeOf);
}

/** A record, or any value, as text of many lines: JSON, with every string made safe. */
export function shownJson(value: unknown): string {
  // Within JSON a line end is written as its escape already. Those between its lines stay.
  return JSON.stringify(value, undefined, 2).replace(ACTS, (character) =>
    character === "\n" ? character : escapeOf(character),
  );
}
