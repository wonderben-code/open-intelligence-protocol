// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** One reason a value is not a well-formed record. */
export interface Issue {
  /** A JSON Pointer (RFC 6901) to the value at fault. The empty string is the record itself. */
  readonly path: string;
  /** What is wrong, in words. */
  readonly message: string;
  /**
   * The specification clause the value breaks, for example `"L1 11.1"`, or
   * `"implementation limit"` when the value exceeds a limit of this
   * implementation that the specification does not set.
   */
  readonly clause: string;
}

/** The result of validating a value: the value with its type, or the reasons it is malformed. */
export type Validation<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly issues: readonly [Issue, ...Issue[]] };

const UNSAFE_TO_SHOW = /[\p{C}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;

/**
 * A character as it is safe to show: itself, or an escape. Everything that
 * is not a visible character or a space is escaped: controls, format
 * characters, unassigned and private-use code points, lone surrogates, and
 * the characters a renderer is told to ignore, such as zero-width spaces,
 * variation selectors and tags, which can carry text nobody sees.
 */
export function shown(character: string): string {
  if (!UNSAFE_TO_SHOW.test(character)) return character;
  const code = character.codePointAt(0) ?? 0;
  const hex = code.toString(16);
  return code > 0xffff ? `\\u{${hex}}` : `\\u${hex.padStart(4, "0")}`;
}

/**
 * Quotes a value from the input for a message. Input is hostile and messages
 * are logged and shown, so the quotation is cut at `max` characters, and
 * every character that could forge a line or reorder the text is escaped.
 */
export function quote(value: string, max = 64): string {
  const cut = Array.from(value.slice(0, 2 * max))
    .slice(0, max)
    .join("");
  // JSON.stringify escapes quotation marks, backslashes, C0 controls and lone surrogates.
  const quoted = JSON.stringify(cut.length < value.length ? `${cut}…` : cut);
  return Array.from(quoted, shown).join("");
}

/** Escapes one reference token of a JSON Pointer (RFC 6901, Section 3). */
export function pointerToken(token: string | number): string {
  return String(token).replaceAll("~", "~0").replaceAll("/", "~1");
}

/** How many reference tokens a JSON Pointer has: 0 for the whole value, 1 for a member of it. */
export function pointerDepth(pointer: string): number {
  return pointer.split("/").length - 1;
}
