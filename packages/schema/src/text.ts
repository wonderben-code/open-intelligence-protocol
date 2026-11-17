// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What core 1.1 requires of every string in a record. */

/** What is wrong with a string as the text of a record. */
export type TextFault = "unpaired surrogate" | "noncharacter";

/**
 * What is wrong with a string as the text of a record, or `undefined` if
 * nothing is. A record is an I-JSON message (core 1.1; RFC 7493, 2.1), so
 * its strings and member names hold no unpaired surrogate and none of the 66
 * noncharacters of Unicode: U+FDD0 to U+FDEF, and the last two code points
 * of each of the seventeen planes.
 */
export function textFault(text: string): TextFault | undefined {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    // Everything below the surrogates is an ordinary character.
    if (unit < 0xd800) continue;
    if (unit > 0xdfff) {
      if ((unit >= 0xfdd0 && unit <= 0xfdef) || unit >= 0xfffe) return "noncharacter";
      continue;
    }
    const next = text.charCodeAt(i + 1);
    // A high surrogate must be followed by a low one; a low one on its own is unpaired.
    if (unit > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) return "unpaired surrogate";
    // The low sixteen bits of the code point the pair writes.
    if ((((unit & 0x3f) << 10) | (next & 0x3ff)) >= 0xfffe) return "noncharacter";
    i++;
  }
  return undefined;
}
