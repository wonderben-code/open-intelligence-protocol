// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A resolver (Layer 1, Section 17): it takes in the logs that are
 * published to it, keeps what verifies with the time it first saw it, and
 * serves that.
 *
 * It is a witness. The time it first saw an event is evidence others rely
 * on (core 9.4), so it is recorded once, in the same transaction as the
 * event, and never again; and two events are never first seen at the same
 * reading of the clock, which would leave the resolver unable to say which
 * came first (Layer 1, 7.3).
 *
 * What it holds in memory, a `LogBook` and its evidence, is what the
 * database holds and no more. If a write fails after the memory has moved,
 * the memory is rebuilt from the database.
 */

import { contentId, formatTimestamp, type Instant, mindAddress, OipError } from "@oip/core";
import { divergence, FirstSeen, type IdentityView, LogBook, type VerifiedLog } from "@oip/identity";
import { cutShort, type Bundle, type DuplicityEvidence, type Validation } from "@oip/schema";
import { type Clock, type Database, Unavailable } from "@oip/server";

import { type Held, judgeCopy, type NotTaken } from "./intake.ts";
import { ResolverStore, type Sighting, type Streamed } from "./store.ts";

/** How a resolver is made. */
export interface ResolverOptions {
  /** Its database, opened with `RESOLVER_MIGRATIONS`. */
  readonly db: Database;
  readonly clock: Clock;
  /** core 8.3: the extension namespaces it implements. None by default. */
  readonly understood?: readonly string[];
}

/** What became of a bundle that was published. */
export type Published =
  /** Everything in it verified. `added` events were not held before. */
  | { readonly outcome: "merged"; readonly added: number }
  /**
   * It holds a valid event at a position where the resolver held another
   * first (Layer 1, 7.1). Both are kept, and the pair is evidence.
   */
  | { readonly outcome: "duplicity"; readonly added: number; readonly position: number }
  /** An event of it did not verify. What came before it was merged. */
  | { readonly outcome: "refused"; readonly added: number; readonly refused: NotTaken };

/** The evidence of a resolver, which notes each first sight it records. */
class Sightings extends FirstSeen {
  /** What has been recorded for the first time since this was last emptied. */
  readonly fresh: Sighting[] = [];

  override sawEvent(id: string, at: Instant): Instant {
    if (this.eventSeen(id) === undefined) this.fresh.push({ kind: "event", id, at });
    return super.sawEvent(id, at);
  }

  override sawProof(digest: string, at: Instant): Instant {
    if (this.proofSeen(digest) === undefined) this.fresh.push({ kind: "proof", id: digest, at });
    return super.sawProof(digest, at);
  }
}

/** Every mind that a log's events rest on: its members, at any state it has had. */
function membersOf(log: VerifiedLog): string[] {
  const members = new Set<string>();
  for (const { state } of log.entries) {
    if (state.controller.kind === "member") {
      for (const member of state.controller.members) members.add(member);
    }
  }
  return [...members];
}

/** A resolver. */
export class Resolver {
  readonly #db: Database;
  readonly #store: ResolverStore;
  readonly #clock: Clock;
  readonly #understood: readonly string[];
  #seen = new Sightings();
  #book = new LogBook(this.#seen);
  /** The latest time anything was first seen at. */
  #latest = 0n;

  constructor(options: ResolverOptions) {
    this.#db = options.db;
    this.#store = new ResolverStore(options.db);
    this.#clock = options.clock;
    this.#understood = options.understood ?? [];
    this.#rebuild();
  }

  /** Makes what is held in memory from what the database holds. */
  #rebuild(): void {
    const seen = new Sightings();
    let latest = 0n;
    for (const { kind, id, at } of this.#store.sightings()) {
      if (kind === "event") seen.sawEvent(id, at);
      else seen.sawProof(id, at);
      if (at > latest) latest = at;
    }
    seen.fresh.length = 0;
    const book = new LogBook(seen, { understood: this.#understood });
    // A resolver follows the logs it holds: nothing is published of them that does not
    // reach it. So each is known up to the present.
    const now = this.#reading(latest);
    for (const { events } of this.#store.copies()) book.hold(events, now);
    this.#seen = seen;
    this.#book = book;
    this.#latest = latest;
  }

  /** A reading of the clock that is later than every time recorded so far. */
  #reading(latest = this.#latest): Instant {
    const now = this.#clock.now();
    return now > latest ? now : latest + 1n;
  }

  /** The logs the resolver holds, each known up to `now`, and its evidence. */
  view(now: Instant): IdentityView {
    return {
      evidence: this.#seen,
      log: (mind): Validation<VerifiedLog> => {
        const held = this.#book.log(mind);
        return held.ok ? { ok: true, value: { ...held.value, asOf: now } } : held;
      },
    };
  }

  #held(now: Instant): Held {
    const view = this.view(now);
    return {
      evidence: view.evidence,
      memberLog: (mind) => view.log(mind),
      proofs: (id) => this.#store.proofsOf(id),
      understood: this.#understood,
    };
  }

  /**
   * Layer 1, 17.1: takes in a bundle published for a mind.
   *
   * @param id - The content ID of the mind's genesis, as the request's path names it.
   * @param authorise - Called before anything is stored, with the logs the
   *   resolver holds and the log of the bundle as far as it verified: a
   *   resolver that asks for authenticated publication (17.3) judges the
   *   request's signature against them, and throws to refuse. A mind can
   *   so publish its own log for the first time.
   * @throws OipError `invalid-record` if the bundle is of another mind.
   * @throws Unavailable if the judging was cut short, or the store could
   *   not be written: nothing was merged, and the publisher asks again.
   */
  publish(id: string, bundle: Bundle, authorise?: (view: IdentityView) => void): Published {
    const mind = mindAddress(id);
    if (bundle.mind !== mind) {
      throw new OipError("invalid-record", "the bundle is of another mind than the one named", {
        clause: "L1 17.1",
      });
    }
    const now = this.#reading();
    const taken = judgeCopy(bundle.log, now, this.#held(now));
    if (taken.log !== undefined && taken.log.mind !== mind) {
      throw new OipError("invalid-record", "the log in the bundle is of another mind", {
        clause: "L1 13.1",
      });
    }
    if (authorise !== undefined) {
      const held = this.view(now);
      const published = taken.log;
      authorise({
        evidence: held.evidence,
        log: (other) =>
          other === mind && published !== undefined
            ? { ok: true, value: { ...published, asOf: now } }
            : held.log(other),
      });
    }
    let added = 0;
    let parted: number | undefined;
    if (taken.log !== undefined) {
      const log = taken.log;
      const before = this.#book.log(mind);
      const pair = before.ok ? divergence(before.value, log) : undefined;
      try {
        added = this.#db.transaction(() => {
          this.#seen.fresh.length = 0;
          const held = this.#book.witness(taken.events, now, this.#seen, {
            following: [mind, ...membersOf(log)],
          });
          if (!held.ok) {
            throw new Unavailable(
              held === cutShort()
                ? "the log could not be judged just now"
                : "the log could not be held as it was judged",
            );
          }
          // Each event verified in its copy, with the present for its first sight.
          for (const event of taken.events) {
            const eventId = contentId(event);
            if (this.#seen.eventSeen(eventId) === undefined) this.#seen.sawEvent(eventId, now);
          }
          const fresh = this.#store.add(mind, taken.events, this.#seen.fresh);
          if (pair !== undefined) {
            this.#store.addPair(mind, {
              position: pair.position,
              first: contentId(pair.events[0]),
              other: contentId(pair.events[1]),
            });
          }
          return fresh.length;
        });
      } catch (error) {
        // The memory has moved and the database has not.
        this.#rebuild();
        throw error;
      }
      if (now > this.#latest) this.#latest = now;
      parted = pair?.position;
    }
    if (parted !== undefined) return { outcome: "duplicity", added, position: parted };
    if (taken.refused !== undefined) return { outcome: "refused", added, refused: taken.refused };
    return { outcome: "merged", added };
  }

  /**
   * Layer 1, 17.1: the bundle of a mind: its log as the resolver holds it,
   * which at every position is the first valid event it saw, and the time
   * it first saw each.
   *
   * @returns `undefined` if the resolver holds no log of the mind.
   * @throws Unavailable if the log could not be judged just now.
   */
  resolve(id: string): Bundle | undefined {
    const mind = mindAddress(id);
    const held = this.#book.log(mind);
    if (!held.ok) {
      if (held === cutShort()) throw new Unavailable("the log could not be judged just now");
      return undefined;
    }
    const firstSeen: Record<string, string> = {};
    const log = held.value.entries.map(({ event }) => {
      const seen = this.#seen.eventSeen(contentId(event));
      if (seen !== undefined) firstSeen[contentId(event)] = formatTimestamp(seen);
      return event;
    });
    return { oip: "1", type: "Bundle", mind, log, firstSeen };
  }

  /**
   * Layer 1, 7.2, 17.1: the pairs of conflicting valid events the resolver
   * has seen for a mind.
   *
   * @returns `undefined` if the resolver holds no log of the mind.
   */
  duplicity(id: string): DuplicityEvidence | undefined {
    const mind = mindAddress(id);
    if (this.#store.event(id) === undefined) return undefined;
    const pairs: DuplicityEvidence["pairs"] = [];
    for (const { first, other } of this.#store.pairs(mind)) {
      const events = [this.#store.event(first), this.#store.event(other)];
      if (events[0] !== undefined && events[1] !== undefined) {
        pairs.push(events as unknown as DuplicityEvidence["pairs"][number]);
      }
    }
    return { oip: "1", type: "DuplicityEvidence", mind, pairs };
  }

  /** Layer 1, 17.1: what was taken in after a cursor, in the order it came. */
  stream(after: number, limit: number): Streamed[] {
    return this.#store.streamAfter(after, limit);
  }
}
