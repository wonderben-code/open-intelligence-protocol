// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A packet whose sender the host cannot judge yet.
 *
 * An inbox takes a packet only if its sender signed it, and that is judged
 * by the sender's identity log (Layer 1, 12.4). A host holds the logs of
 * the minds it serves. For a sender it has not met, or one whose log has
 * grown since, it asks the resolvers its operator configured with the
 * `Lookup` of `@oip/server`, and judges the packet again.
 */

import { OipError, type OipRecord } from "@oip/core";
import type { Lookup } from "@oip/server";

import { type Answer, type Host, partiesOf } from "./host.ts";

/**
 * Whether learning more of a log might change a refusal: it was for a
 * sender or a broker the host has not met, or for a proof by a key or a
 * version of a log it does not know.
 */
function mayBeLearned(error: unknown): boolean {
  return error instanceof OipError && ["stale-version", "invalid-proof"].includes(error.code);
}

/**
 * Layer 1, 13.2: delivers a record to a mind's inbox, and if it is refused
 * for want of its sender's log, asks after the log and judges it again.
 *
 * @returns The answer at once where nothing was asked, and a promise of it
 *   where a resolver was: so one caller serves both without waiting where
 *   there is nothing to wait for.
 * @throws What `Host.deliver` throws, at once or as the promise's rejection.
 */
export function deliverLearning(
  host: Host,
  lookup: Lookup | undefined,
  mind: string,
  record: OipRecord,
): Answer | Promise<Answer> {
  try {
    return host.deliver(mind, record);
  } catch (error) {
    if (lookup === undefined || !mayBeLearned(error)) throw error;
    // The sender, and the broker if one forwarded the packet: whichever log is wanting.
    return Promise.all(partiesOf(record).map((party) => lookup.learn(party))).then((learned) => {
      if (!learned.includes(true)) throw error;
      return host.deliver(mind, record);
    });
  }
}
