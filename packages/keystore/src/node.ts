// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/keystore/node`: what a keystore has in Node.js and nowhere else.
 *
 * @packageDocumentation
 */

export { fileStorage, type FileStorageOptions } from "./file.ts";
// The types its interface names, so that this entry stands by itself.
export type { Randomness } from "./randomness.ts";
export type { KeyStorage, Stored } from "./storage.ts";
