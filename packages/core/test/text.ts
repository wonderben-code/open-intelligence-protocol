// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What text a record may hold (core 1.1), written for the tests from the
 * definitions and not from the implementation: the platform's own check for
 * unpaired surrogates, and a character class for the noncharacters.
 */

const PLANES = Array.from({ length: 17 }, (_, plane) => plane * 0x10000);

/** U+FDD0 to U+FDEF, and the last two code points of each of the 17 planes: 66 in all. */
export const NONCHARACTERS: readonly number[] = [
  ...Array.from({ length: 32 }, (_, i) => 0xfdd0 + i),
  ...PLANES.flatMap((plane) => [plane + 0xfffe, plane + 0xffff]),
];

const NONCHARACTER = new RegExp(
  `[\\u{FDD0}-\\u{FDEF}${PLANES.map(
    (plane) => `\\u{${(plane + 0xfffe).toString(16)}}\\u{${(plane + 0xffff).toString(16)}}`,
  ).join("")}]`,
  "u",
);

/** Whether a string is valid Unicode with no noncharacter in it. */
export function textInProfile(text: string): boolean {
  return text.isWellFormed() && !NONCHARACTER.test(text);
}
