// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Signing for a party (Layer 2, Section 7): whether a record counts for a
 * mind, by any of the four routes, and from when.
 */

import { CLOCK_SKEW, type Instant } from "@oip/core";
import { delegatedTime, type DelegationContext, isDelegableType } from "@oip/delegation";
import { type JudgedRecord, latestState, ownSignedTime } from "@oip/identity";

import { roleTime } from "./charter.ts";

/** The earliest of some times, some of which are none. */
function earliest(times: readonly (Instant | undefined)[]): Instant | undefined {
  let found: Instant | undefined;
  for (const time of times) {
    if (time !== undefined && (found === undefined || time < found)) found = time;
  }
  return found;
}

/**
 * Layer 2, 7.1: the earliest evaluation time at which a record counts for a
 * mind, or `undefined` if it never does. A verdict is a time.
 *
 * It counts by the mind's own key or its threshold, whatever its type; and,
 * if its type is delegable (7.2), through a delegation chain, or for a
 * collective through a charter role. By every route, a proof evaluated more
 * than 300 seconds after the record's `expires` does not count (core 9.6).
 */
export function signedTime(
  judged: JudgedRecord,
  mind: string,
  context: DelegationContext,
): Instant | undefined {
  const times = [ownSignedTime(judged, mind, context.identity)];
  if (isDelegableType(judged.record.type)) {
    times.push(delegatedTime(judged, mind, context));
    const log = context.identity.log(mind);
    if (log.ok && latestState(log.value).controller.kind === "member") {
      times.push(roleTime(judged, mind, log.value, context));
    }
  }
  const limit = judged.expires === undefined ? undefined : judged.expires + CLOCK_SKEW;
  return earliest(
    times.filter((time) => time === undefined || limit === undefined || time <= limit),
  );
}

/** Layer 2, 7.1: whether a record counts for a mind. */
export function countsFor(judged: JudgedRecord, mind: string, context: DelegationContext): boolean {
  return signedTime(judged, mind, context) !== undefined;
}

/**
 * Layer 2, 5.2: whether a proof by `signer` on a record counts for
 * `principal` through a delegation or a charter role (7.1, items 2 and 4).
 */
export function actsFor(
  judged: JudgedRecord,
  signer: string,
  principal: string,
  context: DelegationContext,
): boolean {
  if (delegatedTime(judged, principal, context, { signer }) !== undefined) return true;
  const log = context.identity.log(principal);
  return (
    log.ok &&
    latestState(log.value).controller.kind === "member" &&
    roleTime(judged, principal, log.value, context, signer) !== undefined
  );
}
