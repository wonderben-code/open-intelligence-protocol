// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Revocation (Layer 1, 11.5). */

import type { Instant } from "@oip/core";
import { type IdentityView, ownSignedTime } from "@oip/identity";

import type { RecordView } from "./records.ts";

/**
 * Layer 1, 11.5: the time from which a delegation is revoked, or `undefined`
 * if the verifier holds no revocation of it that counts.
 *
 * A revocation is by the author of the delegation it revokes, signed by
 * that author's own authority, and takes effect from its own evaluation
 * time: the earliest evidence of its signature, never the date written in
 * it. So a backdated revocation does not void what evidence shows came
 * before it, and the earliest of several is the one that matters.
 *
 * @param id - The delegation's content ID.
 * @param author - The delegation's author. Nobody else's revocation counts,
 *   the root principal's of a delegation further down a chain included.
 */
export function revokedTime(
  id: string,
  author: string,
  records: RecordView,
  identity: IdentityView,
): Instant | undefined {
  let earliest: Instant | undefined;
  for (const revocation of records.revocationsOf(id)) {
    if ((revocation.record as { readonly author?: unknown }).author !== author) continue;
    const time = ownSignedTime(revocation, author, identity);
    if (time !== undefined && (earliest === undefined || time < earliest)) earliest = time;
  }
  return earliest;
}
