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

import { CLOCK_SKEW, type Instant, parseTimestamp } from "@oip/core";
import type { Location, Packet, Validation } from "@oip/schema";

import { no, ok } from "./result.ts";

const NANOSECONDS_PER_SECOND = 1_000_000_000n;

/** Layer 1, 12.1: a packet asks to be delivered for at most seven days. */
const LONGEST_PACKET = 7n * 24n * 3600n * NANOSECONDS_PER_SECOND;

/** Layer 1, 12.1: a packet addressed to a query, for at most one hour. */
const LONGEST_QUERY = 3600n * NANOSECONDS_PER_SECOND;

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

/** What a receiver judges a packet's dates with. */
export interface PacketClock {
  /** The present, read by the caller. */
  readonly now: Instant;
  /**
   * How far back the receiver remembers the packets it accepted that state
   * no `expires`, in nanoseconds: its duplicate-detection window.
   */
  readonly window: bigint;
  /**
   * Whether the receiver still holds the state of the packet's sending chain
   * (Layer 1, 14.3). It is asked only about a packet that states no
   * `expires` and is older than the window.
   */
  readonly holdsChain: () => boolean;
}

/**
 * Layer 1, 12.4: the dates of a packet, as a receiver judges them at `now`.
 *
 * A packet is rejected if its `created` is more than 300 seconds ahead, if
 * its `expires` is more than 300 seconds past, or if it asks to be delivered
 * for longer than 12.1 allows: seven days, and one hour when it is addressed
 * to a query. A packet that states no `expires` (a session packet) is
 * rejected once its `created` is older than the receiver's window, unless the
 * receiver still holds the state of its sending chain, which tells a
 * duplicate by its place in the chain.
 *
 * @returns The time after which the packet can no longer be accepted, so
 *   that the receiver may forget it has accepted it: 300 seconds after its
 *   `expires`, or its `created` plus the window.
 */
export function packetDates(packet: Packet, clock: PacketClock): Validation<Instant> {
  const created = parseTimestamp(packet.created);
  if (created === undefined) return no("`created` is not a timestamp", "core 1.4", "/created");
  if (created > clock.now + CLOCK_SKEW) {
    return no("`created` is more than 300 seconds in the future", "L1 12.4", "/created");
  }
  if (packet.expires === undefined) {
    if (created + clock.window < clock.now && !clock.holdsChain()) {
      return no(
        "the packet states no `expires` and is older than the receiver remembers",
        "L1 12.4",
        "/created",
      );
    }
    return ok(created + clock.window);
  }
  const expires = parseTimestamp(packet.expires);
  if (expires === undefined) return no("`expires` is not a timestamp", "core 1.4", "/expires");
  if (expires + CLOCK_SKEW < clock.now) {
    return no("`expires` is more than 300 seconds in the past", "L1 12.4", "/expires");
  }
  const toQuery = !Array.isArray(packet.to) && Object.hasOwn(packet.to, "query");
  if (expires > created + (toQuery ? LONGEST_QUERY : LONGEST_PACKET)) {
    return toQuery
      ? no(
          "a packet addressed to a query expires at most one hour after `created`",
          "L1 12.1",
          "/expires",
        )
      : no("`expires` is more than 7 days after `created`", "L1 12.4", "/expires");
  }
  return ok(expires + CLOCK_SKEW);
}
