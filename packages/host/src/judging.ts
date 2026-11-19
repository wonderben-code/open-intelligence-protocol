// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Two things every judgement the host makes needs. */

import type { Instant } from "@oip/core";
import type { IdentityView } from "@oip/identity";
import { cutShortCount } from "@oip/schema";
import { Unavailable } from "@oip/server";

/**
 * Makes a judgement, and refuses to act on it if any check in it was cut
 * short (ADR-0010). A check that could not be made says nothing of what
 * was judged: not that a packet is forged, and not that an entry no longer
 * verifies. The client asks again.
 *
 * @throws Unavailable if a check was cut short while `work` ran.
 */
export function standing<T>(work: () => T): T {
  const before = cutShortCount();
  const judged = work();
  if (cutShortCount() !== before) throw new Unavailable("this could not be judged just now");
  return judged;
}

/**
 * The logs and the evidence held, with more evidence of when proofs were
 * first seen laid over it. What is held already stands: the evidence laid
 * over it answers only for proofs the view knows nothing of.
 */
export function overlaid(
  view: IdentityView,
  proofSeen: (digest: string) => Instant | undefined,
): IdentityView {
  return {
    log: (mind) => view.log(mind),
    evidence: {
      eventSeen: (id) => view.evidence.eventSeen(id),
      proofSeen: (digest) => view.evidence.proofSeen(digest) ?? proofSeen(digest),
    },
  };
}
