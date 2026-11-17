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
 * Quotes a value from the input for a message. Input is hostile and messages
 * are logged and shown, so the quotation is cut at `max` characters.
 */
export function quote(value: string, max = 64): string {
  const shown = Array.from(value.slice(0, 2 * max))
    .slice(0, max)
    .join("");
  return JSON.stringify(shown.length < value.length ? `${shown}…` : shown);
}

/** Escapes one reference token of a JSON Pointer (RFC 6901, Section 3). */
export function pointerToken(token: string | number): string {
  return String(token).replaceAll("~", "~0").replaceAll("/", "~1");
}
