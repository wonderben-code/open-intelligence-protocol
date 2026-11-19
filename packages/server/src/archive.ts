// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * An archive of identity logs: what a service that others publish to keeps
 * of them (Layer 1, 7.2, 17.2). It takes in the logs that are published to
 * it, keeps what verifies with the time it first saw it, and gives that
 * back. A resolver is one and little more; a host and an indexer each keep
 * one, to judge the records they are sent.
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

import {
  contentId,
  formatTimestamp,
  type Instant,
  type JsonObject,
  mindAddress,
  OipError,
} from "@oip/core";
import {
  divergence,
  FirstSeen,
  type IdentityView,
  type JudgedRecord,
  judgeRecord,
  LogBook,
  ownSignedTime,
  type VerifiedLog,
  witnessRecord,
} from "@oip/identity";
import { currentLocation } from "@oip/net";
import { cutShort, type Bundle, type DuplicityEvidence, type Validation } from "@oip/schema";
import type { Clock } from "./edges.ts";
import { Unavailable } from "./http.ts";
import type { Database } from "./storage.ts";

import { type Held, judgeCopy, type NotTaken } from "./intake.ts";
import { ArchiveStore, type Sighting, type Streamed } from "./archive-store.ts";

/** How an archive is made. */
export interface ArchiveOptions {
  /** The service's database, whose migrations include `ARCHIVE_SQL`. */
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
  | { readonly outcome: "refused"; readonly added: number; readonly refused: NotTaken }
  /** Its location record or its profile is not signed by the mind's own authority. The log was merged. */
  | { readonly outcome: "not-counted"; readonly added: number; readonly record: OtherRecord };

/** A record a bundle carries besides the log. */
export type OtherRecord = "location" | "participant";

/**
 * The problem that says why a published bundle was not wholly taken (core
 * 10.2), if it was not. What verified of it was merged all the same.
 */
export function publicationProblem(published: Published): OipError | undefined {
  switch (published.outcome) {
    case "merged":
      return undefined;
    case "duplicity":
      return new OipError(
        "duplicity",
        `the log holds another valid event at position ${published.position} than the one seen first here`,
        { clause: "L1 7.1" },
      );
    case "not-counted":
      return new OipError(
        "invalid-proof",
        `the ${published.record} record in the bundle is not signed by the mind's own authority under the current-state rule`,
        { clause: published.record === "location" ? "L1 15.1" : "L1 16.1" },
      );
    case "refused": {
      const { refused } = published;
      const [first] = refused.issues;
      const detail = `event ${refused.position} of the log: ${first.message}`;
      const options = { clause: first.clause, issues: refused.issues };
      // An extension that is not implemented here: the event may be the mind's own.
      if (refused.issues.some((issue) => issue.clause === "core 8.3")) {
        return new OipError("unsupported-critical", detail, options);
      }
      // What cannot be judged with the logs and the evidence held.
      if (refused.undecided) return new OipError("stale-version", detail, options);
      return new OipError("invalid-proof", detail, options);
    }
  }
}

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

/** The proofs that verify on the record with a content ID, among those held. */
function proofsOf(held: readonly JudgedRecord[], id: string): JudgedRecord["proofs"] {
  return held.find((other) => contentId(other.record) === id)?.proofs ?? [];
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

/** An archive of identity logs. */
export class LogArchive {
  readonly #db: Database;
  readonly #store: ArchiveStore;
  readonly #clock: Clock;
  readonly #understood: readonly string[];
  #seen = new Sightings();
  #book = new LogBook(this.#seen);
  /** The location records and profiles held, by mind, each as it was judged. */
  #others = new Map<string, JudgedRecord[]>();
  /** The latest time anything was first seen at. */
  #latest = 0n;
  /** Those to tell when the stream has something new. */
  readonly #listeners = new Set<() => void>();

  constructor(options: ArchiveOptions) {
    this.#db = options.db;
    this.#store = new ArchiveStore(options.db);
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
    const others = new Map<string, JudgedRecord[]>();
    for (const { mind, record } of this.#store.records()) {
      const judged = judgeRecord(record, { understood: this.#understood });
      if (judged.ok) others.set(mind, [...(others.get(mind) ?? []), judged.value]);
    }
    this.#seen = seen;
    this.#book = book;
    this.#others = others;
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
   *   so publish its own log for the first time. It is given the reading of
   *   the clock those logs are held as of, which is the present to judge
   *   at: a later reading would be after the logs were obtained, and a
   *   proof first seen then is not judged by them (core 9.4).
   * @throws OipError `invalid-record` if the bundle is of another mind.
   * @throws Unavailable if the judging was cut short, or the store could
   *   not be written: nothing was merged, and the publisher asks again.
   */
  publish(
    id: string,
    bundle: Bundle,
    authorise?: (view: IdentityView, now: Instant) => void,
  ): Published {
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
      authorise(
        {
          evidence: held.evidence,
          log: (other) =>
            other === mind && published !== undefined
              ? { ok: true, value: { ...published, asOf: now } }
              : held.log(other),
        },
        now,
      );
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
      if (added > 0) this.#tell();
    }
    if (parted !== undefined) return { outcome: "duplicity", added, position: parted };
    if (taken.refused !== undefined) return { outcome: "refused", added, refused: taken.refused };
    for (const [name, type] of [
      ["location", "Location"],
      ["participant", "Participant"],
    ] as const) {
      const record: unknown = bundle[name];
      if (record !== undefined && !this.#take(mind, type, record, now)) {
        return { outcome: "not-counted", added, record: name };
      }
    }
    return { outcome: "merged", added };
  }

  /**
   * Takes in a record of a mind that is no identity event, if the mind's own
   * authority signed it under the current-state rule (Layer 1, 6.1, 15.1,
   * 16). The time its proofs were first seen is recorded with it, and of no
   * record that is not kept.
   *
   * @returns Whether the record counts for the mind.
   */
  #take(mind: string, type: "Location" | "Participant", record: unknown, now: Instant): boolean {
    const judged = judgeRecord(record, { understood: this.#understood });
    if (!judged.ok || judged.value.record.type !== type) return false;
    if ((judged.value.record as { author?: unknown }).author !== mind) return false;
    const digests = new Set(judged.value.proofs.map((proof) => proof.digest));
    const view = this.view(now);
    // Judged as it will be once its proofs are recorded as seen now, and recorded only then.
    const counts = ownSignedTime(judged.value, mind, {
      log: (other) => view.log(other),
      evidence: {
        eventSeen: (id) => this.#seen.eventSeen(id),
        proofSeen: (digest) =>
          this.#seen.proofSeen(digest) ?? (digests.has(digest) ? now : undefined),
      },
    });
    if (counts === undefined) return false;
    const held = this.#others.get(mind) ?? [];
    const id = contentId(judged.value.record);
    if (held.some((other) => contentId(other.record) === id)) return true;
    try {
      this.#db.transaction(() => {
        this.#seen.fresh.length = 0;
        witnessRecord(judged.value, now, this.#seen);
        this.#store.addRecord(
          mind,
          type,
          judged.value.record as unknown as JsonObject,
          this.#seen.fresh,
        );
      });
    } catch (error) {
      this.#rebuild();
      throw error;
    }
    this.#others.set(mind, [...held, judged.value]);
    if (now > this.#latest) this.#latest = now;
    if (type === "Location") this.#tell();
    return true;
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
    // The records that count now, by the logs as they stand at this reading of the clock.
    const others = this.#others.get(mind) ?? [];
    const view = this.view(this.#reading());
    const location = currentLocation(others, mind, view);
    const profile =
      location?.record.participant === undefined
        ? undefined
        : others.find(
            (other) =>
              other.record.type === "Participant" &&
              contentId(other.record) === location.record.participant &&
              ownSignedTime(other, mind, view) !== undefined,
          );
    const proofs = [
      ...(location === undefined ? [] : proofsOf(others, location.id)),
      ...(profile?.proofs ?? []),
    ];
    for (const proof of proofs) {
      const seen = this.#seen.proofSeen(proof.digest);
      if (seen !== undefined) firstSeen[proof.digest] = formatTimestamp(seen);
    }
    return {
      oip: "1",
      type: "Bundle",
      mind,
      log,
      ...(location === undefined ? {} : { location: location.record }),
      ...(profile === undefined ? {} : { participant: profile.record }),
      firstSeen,
    } as Bundle;
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

  /**
   * Runs work that judges with the archive's record of first sight, and
   * stores what the work caused to be recorded in the same transaction as
   * whatever the work itself stores: a packet received and the first sight
   * of its proofs stand or fall together (core 9.4).
   *
   * @param work - Given the record to pass as a receiver's `seen`, and the
   *   reading of the clock it is made at, which is later than every time
   *   recorded so far.
   * @throws What `work` throws. Nothing is stored then, and if anything had
   *   been recorded, what the archive holds in memory is made again from
   *   the database. Work that refuses does so before it records.
   */
  witnessing<T>(work: (seen: FirstSeen, now: Instant) => T): T {
    const now = this.#reading();
    try {
      const result = this.#db.transaction(() => {
        this.#seen.fresh.length = 0;
        const worked = work(this.#seen, now);
        this.#store.add("", [], this.#seen.fresh);
        return worked;
      });
      if (now > this.#latest) this.#latest = now;
      return result;
    } catch (error) {
      // Only if the memory has moved: work that refuses before it records has changed nothing.
      if (this.#seen.fresh.length > 0) this.#rebuild();
      throw error;
    }
  }

  /** Layer 1, 17.1: what was taken in after a cursor, in the order it came. */
  stream(after: number, limit: number): Streamed[] {
    return this.#store.streamAfter(after, limit);
  }

  /**
   * Asks to be told when the stream has something new.
   *
   * @returns How to stop being told.
   */
  subscribe(listener: () => void): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  #tell(): void {
    // A listener that fails is its own affair: the others are told, and the publisher is answered.
    for (const listener of this.#listeners) {
      try {
        listener();
      } catch {
        // Nothing to do here.
      }
    }
  }
}
