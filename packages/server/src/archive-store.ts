// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What an archive of identity logs keeps on disk (Layer 1, 7.2, 17.2): the
 * events that verified, the proofs kept for each, the time each event and
 * each proof was first seen, the pairs of events that show duplicity, and
 * the order in which all of it came, for a stream.
 *
 * Every table but the one that points at a mind's current location is
 * append-only. An event is stored once, under its content ID, and its
 * proofs beside it under their digests: a log published a hundred times
 * takes the room of one. What an archive holds in memory is rebuilt from
 * here when it starts, and whenever a write fails.
 */

import { contentId, type Instant, type JsonObject, proofDigest } from "@oip/core";
import type { Proof } from "@oip/schema";
import { appendOnly, type Database, kept } from "./storage.ts";

const TABLES = `
CREATE TABLE events (id TEXT PRIMARY KEY, mind TEXT NOT NULL, seq INTEGER NOT NULL, prev TEXT, body TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE INDEX events_of_mind ON events (mind, seq);
CREATE TABLE event_proofs (id TEXT NOT NULL REFERENCES events (id), digest TEXT NOT NULL, proof TEXT NOT NULL, UNIQUE (id, digest)) STRICT;
CREATE TABLE seen_events (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE seen_proofs (digest TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE duplicity (mind TEXT NOT NULL, first TEXT NOT NULL, other TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY (mind, first, other)) STRICT, WITHOUT ROWID;
CREATE TABLE stream (cursor INTEGER PRIMARY KEY AUTOINCREMENT, mind TEXT NOT NULL, id TEXT NOT NULL) STRICT;
CREATE TABLE records (id TEXT PRIMARY KEY, mind TEXT NOT NULL, type TEXT NOT NULL, record TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE INDEX records_of_mind ON records (mind);
`;

/**
 * The tables of an archive, for a service's migrations. Each takes rows and
 * lets none be changed or removed.
 */
export const ARCHIVE_SQL = [
  TABLES,
  ...["events", "event_proofs", "seen_events", "seen_proofs", "duplicity", "stream", "records"].map(
    appendOnly,
  ),
].join("\n");

/** A first sight to record: of an identity event, or of a proof. */
export interface Sighting {
  readonly kind: "event" | "proof";
  /** The event's content ID, or the proof's digest. */
  readonly id: string;
  readonly at: Instant;
}

/** Two events that show duplicity: the one held first at a position, and another valid there. */
export interface Pair {
  readonly position: number;
  readonly first: string;
  readonly other: string;
}

/** An entry of the stream: something the archive took in, and its place in the order. */
export interface Streamed {
  readonly cursor: number;
  readonly mind: string;
  readonly record: JsonObject;
}

/** An event without its proofs, as text, and what places it in its log. */
function rowOf(event: JsonObject): { id: string; seq: number; prev: string | null; body: string } {
  const { proof: _, ...subject } = event;
  const { seq, prev } = subject;
  return {
    id: contentId(event),
    seq: typeof seq === "number" ? seq : 0,
    prev: typeof prev === "string" ? prev : null,
    body: JSON.stringify(subject),
  };
}

/** The proofs of an event as it was given. */
function proofsOn(event: JsonObject): Proof[] {
  // An event that verified is signed: it carries a list of proofs.
  return event["proof"] as unknown as Proof[];
}

/** The store of an archive, in a service's database. */
export class ArchiveStore {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  /** The proofs kept for an event, in the order they were stored. */
  proofsOf(id: string): Proof[] {
    return (
      this.#db.prepare("SELECT proof FROM event_proofs WHERE id = ? ORDER BY rowid").all(id) as {
        proof: string;
      }[]
    ).map(({ proof }) => JSON.parse(proof) as Proof);
  }

  /** An event with the proofs kept for it, or `undefined` if it is not held. */
  event(id: string): JsonObject | undefined {
    const row = this.#db.prepare("SELECT body FROM events WHERE id = ?").get(id) as
      { body: string } | undefined;
    if (row === undefined) return undefined;
    return { ...(JSON.parse(row.body) as JsonObject), proof: this.proofsOf(id) as never };
  }

  /**
   * Adds what a published copy gave: its events, their proofs, and what was
   * first seen. What is held already is left as it is. Call it within a
   * transaction, with whatever else must stand or fall with it.
   *
   * @returns The content IDs of the events that were not held before.
   */
  add(mind: string, events: readonly JsonObject[], sightings: readonly Sighting[]): string[] {
    const fresh: string[] = [];
    const insertEvent = this.#db.prepare(
      "INSERT OR IGNORE INTO events (id, mind, seq, prev, body) VALUES (?, ?, ?, ?, ?)",
    );
    const insertProof = this.#db.prepare(
      "INSERT OR IGNORE INTO event_proofs (id, digest, proof) VALUES (?, ?, ?)",
    );
    const insertStream = this.#db.prepare("INSERT INTO stream (mind, id) VALUES (?, ?)");
    for (const event of events) {
      const row = rowOf(event);
      if (Number(insertEvent.run(row.id, mind, row.seq, row.prev, row.body).changes) > 0) {
        fresh.push(row.id);
        insertStream.run(mind, row.id);
      }
      for (const proof of proofsOn(event)) {
        insertProof.run(row.id, proofDigest(proof), JSON.stringify(proof));
      }
    }
    for (const sighting of sightings) {
      this.#db
        .prepare(
          sighting.kind === "event"
            ? "INSERT OR IGNORE INTO seen_events (id, at) VALUES (?, ?)"
            : "INSERT OR IGNORE INTO seen_proofs (digest, at) VALUES (?, ?)",
        )
        .run(sighting.id, sighting.at);
    }
    return fresh;
  }

  /**
   * Adds a record of a mind that is no identity event: its location record,
   * its profile. One held already is left as it is.
   *
   * @returns Whether it was not held before.
   */
  addRecord(
    mind: string,
    type: "Location" | "Participant",
    record: JsonObject,
    sightings: readonly Sighting[],
  ): boolean {
    const id = contentId(record);
    const fresh =
      Number(
        this.#db
          .prepare("INSERT OR IGNORE INTO records (id, mind, type, record) VALUES (?, ?, ?, ?)")
          .run(id, mind, type, JSON.stringify(record)).changes,
      ) > 0;
    // Layer 1, 17.1: the stream tells of identity events and of location records.
    if (fresh && type === "Location") {
      this.#db.prepare("INSERT INTO stream (mind, id) VALUES (?, ?)").run(mind, id);
    }
    this.add(mind, [], sightings);
    return fresh;
  }

  /** Every record held that is no identity event, with its mind. */
  *records(): Generator<{ mind: string; record: JsonObject }> {
    for (const row of this.#db
      .prepare("SELECT mind, record FROM records ORDER BY mind, id")
      .iterate()) {
      const { mind, record } = row as { mind: string; record: string };
      yield { mind, record: JSON.parse(record) as JsonObject };
    }
  }

  /** Records a pair of events that shows duplicity. One recorded already is left as it is. */
  addPair(mind: string, pair: Pair): void {
    this.#db
      .prepare("INSERT OR IGNORE INTO duplicity (mind, first, other, position) VALUES (?, ?, ?, ?)")
      .run(mind, pair.first, pair.other, pair.position);
  }

  /** The pairs recorded for a mind, by position and then in the order of their content IDs. */
  pairs(mind: string): Pair[] {
    return this.#db
      .prepare(
        "SELECT position, first, other FROM duplicity WHERE mind = ? ORDER BY position, first, other",
      )
      .all(mind) as unknown as Pair[];
  }

  /** Every first sight recorded, of events and then of proofs. */
  *sightings(): Generator<Sighting> {
    for (const [kind, sql] of [
      ["event", "SELECT id, at FROM seen_events"],
      ["proof", "SELECT digest AS id, at FROM seen_proofs"],
    ] as const) {
      for (const row of this.#db.prepareWithTimes(sql).iterate()) {
        const { id, at } = row as { id: string; at: bigint };
        yield { kind, id, at };
      }
    }
  }

  /**
   * Everything held of every mind, to rebuild what is held in memory: for
   * each mind, each way through its events from the genesis to an end, as
   * one copy of its log.
   */
  *copies(): Generator<{ mind: string; events: JsonObject[] }> {
    const minds = this.#db.prepare("SELECT DISTINCT mind FROM events ORDER BY mind").all() as {
      mind: string;
    }[];
    for (const { mind } of minds) {
      const rows = this.#db
        .prepare("SELECT id, prev FROM events WHERE mind = ? ORDER BY seq, id")
        .all(mind) as { id: string; prev: string | null }[];
      const before = new Map(rows.map((row) => [row.id, row.prev]));
      const followed = new Set(rows.map((row) => row.prev));
      for (const { id } of rows) {
        // An end: no event held comes after it.
        if (followed.has(id)) continue;
        const path: JsonObject[] = [];
        // Back to the genesis, through events that are held.
        for (
          let at: string | null = id;
          at !== null && before.has(at);
          at = before.get(at) ?? null
        ) {
          path.unshift(kept(this.event(at), "an event"));
        }
        yield { mind, events: path };
      }
    }
  }

  /**
   * What was taken in after a cursor, in order.
   *
   * @param after - The cursor of the last entry the reader has. 0 for the beginning.
   */
  streamAfter(after: number, limit: number): Streamed[] {
    const rows = this.#db
      .prepare("SELECT cursor, mind, id FROM stream WHERE cursor > ? ORDER BY cursor LIMIT ?")
      .all(after, limit) as { cursor: number; mind: string; id: string }[];
    const other = this.#db.prepare("SELECT record FROM records WHERE id = ?");
    return rows.map(({ cursor, mind, id }) => {
      const held = other.get(id) as { record: string } | undefined;
      // An entry of the stream is stored in one transaction with what it tells of.
      const record =
        this.event(id) ?? (JSON.parse(kept(held, "what the stream tells of").record) as JsonObject);
      return { cursor, mind, record };
    });
  }
}
