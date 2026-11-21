// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The same logs with their compromise declarations disregarded (Layer 2, 8.3). */

import type { IdentityView } from "./book.ts";
import { ok } from "./result.ts";
import type { VerifiedLog } from "./state.ts";

/**
 * A view of the same logs and the same evidence, with every compromise
 * declaration (Layer 1, 6.2) disregarded. A key that an event revoked is
 * revoked still, from that event's own time on. It is declared compromised
 * from no earlier time.
 *
 * It answers one question, that of Layer 2, 8.3: whether a Commitment would
 * be accepted had no party declared a key compromised. A Commitment that
 * would be is `disputed`, and not merely `proposed`. Ask nothing else of
 * this view: by it, a signature made with a stolen key counts.
 */
export function disregardingCompromise(view: IdentityView): IdentityView {
  // A book answers with the same log each time, so each is copied once.
  const without = new WeakMap<VerifiedLog, VerifiedLog>();
  return Object.freeze({
    evidence: view.evidence,
    log: (mind: string) => {
      const held = view.log(mind);
      if (!held.ok) return held;
      let log = without.get(held.value);
      if (log === undefined) {
        log = Object.freeze({
          ...held.value,
          revocations: Object.freeze(
            held.value.revocations.map((revocation) =>
              Object.freeze({ ...revocation, compromisedSince: undefined }),
            ),
          ),
        });
        without.set(held.value, log);
      }
      return ok(log);
    },
  });
}
