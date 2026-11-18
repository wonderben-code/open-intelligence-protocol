// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Evidence items (Layer 2, Section 9). Nothing here fetches anything. */

import { sha256Digest } from "@oip/core";
import type { Evidence } from "@oip/schema";

/**
 * Layer 2, Section 9: whether some bytes are the bytes an evidence item
 * names by its `digest`. A verifier that fetches a `uri` item checks this
 * before it relies on what it fetched.
 *
 * An item with no digest names no bytes, so nothing matches it: what was
 * fetched for it is whatever the server chose to send.
 *
 * @param bytes - The exact bytes fetched, before any decoding.
 */
export function evidenceMatches(item: Evidence, bytes: Uint8Array): boolean {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("the bytes fetched are not bytes");
  return item.digest !== undefined && item.digest === sha256Digest(bytes);
}

/**
 * Layer 2, Section 9: whether an evidence item can be checked against
 * bytes: it carries a digest. `uri` and `hash` items always do.
 */
export function evidenceIsChecked(item: Evidence): boolean {
  return item.digest !== undefined;
}
