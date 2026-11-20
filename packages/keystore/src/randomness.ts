// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { KeystoreError } from "./errors.ts";

/** Where keys, salts and nonces come from. A test gives its own. */
export interface Randomness {
  /** `length` bytes that nobody can predict. */
  bytes(length: number): Uint8Array;
}

/** The platform's generator (`crypto.getRandomValues`), in Node.js and in browsers. */
export const systemRandomness: Randomness = {
  bytes: (length) => globalThis.crypto.getRandomValues(new Uint8Array(length)),
};

/**
 * Bytes from a source, checked: a source that returns too few, or the same
 * array it was given, would otherwise make a key of zeros.
 *
 * @throws KeystoreError `argument` if the source does not give `length` bytes.
 */
export function draw(randomness: Randomness, length: number): Uint8Array {
  const bytes: unknown = randomness.bytes(length);
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
    throw new KeystoreError("argument", "the source of randomness did not give what was asked");
  }
  return bytes.slice();
}
