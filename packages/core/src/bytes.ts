// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Bytes and text. */

import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export { bytesToHex, concatBytes, hexToBytes };

/** Whether a string is valid Unicode: every surrogate is half of a pair (core 1.1). */
export function isWellFormed(text: string): boolean {
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

/** The length of a string in Unicode code points, which is how core 1.8 counts "characters". */
export function codePointLength(text: string): number {
  let length = 0;
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    // A surrogate pair is one code point: skip its second half.
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i++;
    }
    length++;
  }
  return length;
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
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return undefined;
  }
}

/** Whether two byte strings are equal. Not constant-time: use it on public values only. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
