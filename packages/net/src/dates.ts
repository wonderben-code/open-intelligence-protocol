// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The rules of Layer 1 that are about the dates a record states of itself.
 *
 * A date a signer wrote is a claim, never evidence of when anything was
 * signed (core 9.2), and no rule here decides whether a key may sign. They
 * say how long a record asks to be used for: a mind states when its own
 * location record goes stale, and a sender when its own packet stops being
 * worth delivering. A signer that misdates such a record misleads only
 * about itself. This is the one file of the package that may compare a
 * `created` (ADR-0008).
 */

import { type Instant, parseTimestamp } from "@oip/core";
import type { Location } from "@oip/schema";

const NANOSECONDS_PER_SECOND = 1_000_000_000n;

/**
 * Layer 1, 15.2: whether a location record is stale at `now`: later than
 * its `created` plus its `ttl`. A stale record may still be used as a hint.
 *
 * @param now - The present, read by the caller.
 */
export function isStale(record: Location, now: Instant): boolean {
  const created = parseTimestamp(record.created);
  // A validated record's `created` is a timestamp. One that is not states no time to be fresh until.
  if (created === undefined) return true;
  return now > created + BigInt(record.ttl) * NANOSECONDS_PER_SECOND;
}
