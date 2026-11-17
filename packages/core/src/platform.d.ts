// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The one platform API the pure packages use that is not part of ECMAScript:
 * decoding UTF-8. It is the same in Node.js, browsers, Deno and Bun, reads
 * nothing from the environment and is deterministic. It is declared here
 * because pure packages are built without ambient types (ADR-0001).
 */
declare class TextDecoder {
  constructor(label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean });
  decode(input?: Uint8Array): string;
}
