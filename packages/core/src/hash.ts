// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** SHA-256, the one hash function of this revision (core 3.1). */

import { sha256 as sha256Of } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/** The SHA-256 digest of some bytes: 32 bytes. */
export function sha256(bytes: Uint8Array): Uint8Array {
  return sha256Of(bytes);
}

/** The digest of exact bytes as records write it: `"sha256:"` and 64 lower-case hex digits. */
export function sha256Digest(bytes: Uint8Array): string {
  return `sha256:${bytesToHex(sha256Of(bytes))}`;
}
