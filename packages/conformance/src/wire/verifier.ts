// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The suite as a verifier. What an implementation signs, such as an `Ack` or
 * a `QueryResult`, is judged as any client would judge it: against identity
 * logs the suite holds, with evidence of when each event was first seen.
 */

import { contentId, type Instant, parseTimestamp } from "@oip/core";
import { FirstSeen, LogBook } from "@oip/identity";

import type { WireMind } from "./minds.ts";
import { present } from "./report.ts";

/** The logs the suite holds, and when it first saw each event and proof. */
export class Verifier {
  readonly seen = new FirstSeen();
  readonly book = new LogBook(this.seen);

  /**
   * Holds the log of a mind the suite made. The suite saw each event when it
   * made it: at the event's `created`.
   *
   * @throws TypeError if the log does not verify, which is a mistake in the suite.
   */
  holds(mind: WireMind, now: Instant): void {
    for (const event of mind.events) {
      this.seen.sawEvent(contentId(event), present(parseTimestamp(event.created)));
    }
    if (!this.book.hold(mind.events, now).ok) {
      throw new TypeError("the suite made a log that does not verify");
    }
  }

  /** Takes in a log that an implementation served, first seen at `now`. Whether it verified. */
  learns(events: unknown, now: Instant): boolean {
    return this.book.witness(events, now, this.seen).ok;
  }
}
