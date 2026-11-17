// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Bytes and text. */

import {
  bytesToHex as toHex,
  concatBytes,
  hexToBytes as fromHex,
  utf8ToBytes,
} from "@noble/hashes/utils.js";

export { concatBytes };

/** Bytes as lower-case hexadecimal text, two digits a byte. */
export function bytesToHex(bytes: Uint8Array): string {
  return toHex(bytes);
}

/**
 * The bytes that hexadecimal text writes, in either case.
 *
 * @throws TypeError if the text is not hexadecimal digits in pairs. The
 * message does not repeat the text, which may be a private key.
 */
export function hexToBytes(hex: string): Uint8Array {
  try {
    return fromHex(hex);
  } catch {
    throw new TypeError("hexadecimal digits in pairs are needed");
  }
}

/** Whether a string is valid Unicode: every surrogate is half of a pair (core 1.1). */
export function isWellFormed(text: string): boolean {
  if (typeof text !== "string") return false;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit < 0xd800 || unit > 0xdfff) continue;
    const next = text.charCodeAt(i + 1);
    // A high surrogate must be followed by a low one; a low one on its own is unpaired.
    if (unit > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) return false;
    i++;
  }
  return true;
}

/**
 * The UTF-8 encoding of a string. The string must be valid Unicode: an
 * unpaired surrogate has no UTF-8 encoding, and an encoder would silently
 * write U+FFFD in its place.
 *
 * @throws TypeError if the string has an unpaired surrogate.
 */
export function utf8(text: string): Uint8Array {
  if (!isWellFormed(text)) {
    throw new TypeError("the string has an unpaired surrogate, so it has no UTF-8 encoding");
  }
  return utf8ToBytes(text);
}

const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * The text that some bytes encode in UTF-8, or `undefined` if they are not
 * valid UTF-8. A byte order mark is not removed: it stays in the text, where
 * the JSON parser rejects it.
 */
export function decodeUtf8(bytes: Uint8Array): string | undefined {
  let text: string | undefined;
  try {
    text = strictDecoder.decode(bytes);
  } catch {
    // Not UTF-8: there is no text.
  }
  return text;
}

/** Whether two byte strings are equal. Not constant-time: use it on public values only. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
