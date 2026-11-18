// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Revocation (Layer 1, 11.5). */

import type { Instant } from "@oip/core";
import { disregardingCompromise, type IdentityView, ownSignedTime } from "@oip/identity";

import type { RecordView } from "./records.ts";

/** The view a revocation is judged with, for each view asked: made once. */
const withoutCompromise = new WeakMap<IdentityView, IdentityView>();

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
 * A revocation takes authority away and grants none. So it stands whatever
 * is later declared of the key that signed it: its signature is judged with
 * compromise declarations disregarded. A mind that declares a key
 * compromised from before one of its own revocations does not, by that,
 * give back what it took away.
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
  let lenient = withoutCompromise.get(identity);
  if (lenient === undefined) {
    lenient = disregardingCompromise(identity);
    withoutCompromise.set(identity, lenient);
  }
  let earliest: Instant | undefined;
  for (const revocation of records.revocationsOf(id)) {
    if ((revocation.record as { readonly author?: unknown }).author !== author) continue;
    const time = ownSignedTime(revocation, author, lenient);
    if (time !== undefined && (earliest === undefined || time < earliest)) earliest = time;
  }
  return earliest;
}
