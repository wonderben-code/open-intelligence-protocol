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

/**
 * Whether a character from the input must not reach a log or a screen as
 * itself: the control characters, the line and paragraph separators, which
 * can forge a line, and the controls of the bidirectional algorithm, which
 * can show text in another order than it has.
 */
function unsafeToShow(code: number): boolean {
  return (
    code < 0x20 ||
    (code >= 0x7f && code <= 0x9f) ||
    code === 0x061c ||
    code === 0x200e ||
    code === 0x200f ||
    (code >= 0x2028 && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

/** A character as it is safe to show: itself, or a `\u` escape. */
export function shown(character: string): string {
  const code = character.codePointAt(0) ?? 0;
  return unsafeToShow(code) ? `\\u${code.toString(16).padStart(4, "0")}` : character;
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
