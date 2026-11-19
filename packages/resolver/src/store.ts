// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a resolver keeps on disk (Layer 1, 7.2, 17.2): the events that
 * verified, the proofs kept for each, the time it first saw each event and
 * each proof, the pairs of events that show duplicity, and the order in
 * which all of it came, for the stream.
 *
 * Every table but the one that points at a mind's current location is
 * append-only. An event is stored once, under its content ID, and its
 * proofs beside it under their digests: a log published a hundred times
 * takes the room of one. What the resolver holds in memory is rebuilt from
 * here when it starts, and whenever a write fails.
 */

import { contentId, type Instant, type JsonObject, proofDigest } from "@oip/core";
import type { Proof } from "@oip/schema";
import { appendOnly, type Database, type Migration, NONCES_SQL } from "@oip/server";

const TABLES = `
CREATE TABLE events (id TEXT PRIMARY KEY, mind TEXT NOT NULL, seq INTEGER NOT NULL, prev TEXT, body TEXT NOT NULL) STRICT, WITHOUT ROWID;
CREATE INDEX events_of_mind ON events (mind, seq);
CREATE TABLE event_proofs (id TEXT NOT NULL REFERENCES events (id), digest TEXT NOT NULL, proof TEXT NOT NULL, UNIQUE (id, digest)) STRICT;
CREATE TABLE seen_events (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE seen_proofs (digest TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE duplicity (mind TEXT NOT NULL, first TEXT NOT NULL, other TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY (mind, first, other)) STRICT, WITHOUT ROWID;
CREATE TABLE stream (cursor INTEGER PRIMARY KEY AUTOINCREMENT, mind TEXT NOT NULL, id TEXT NOT NULL) STRICT;
`;

/** The migrations of a resolver's database. */
export const RESOLVER_MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "logs, first sight, duplicity and the stream",
    sql: [
      TABLES,
      ...["events", "event_proofs", "seen_events", "seen_proofs", "duplicity", "stream"].map(
        appendOnly,
      ),
      NONCES_SQL,
    ].join("\n"),
  },
];

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

/** An entry of the stream: something the resolver took in, and its place in the order. */
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
  const proofs = event["proof"];
  return Array.isArray(proofs) ? proofs : [];
}

/** A resolver's store, in its database. */
export class ResolverStore {
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
        for (let at: string | null | undefined = id; typeof at === "string"; at = before.get(at)) {
          const event = this.event(at);
          if (event !== undefined) path.unshift(event);
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
    return rows.flatMap(({ cursor, mind, id }) => {
      const record = this.event(id);
      return record === undefined ? [] : [{ cursor, mind, record }];
    });
  }
}
