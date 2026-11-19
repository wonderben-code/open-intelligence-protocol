// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a host keeps besides its archive of identity logs: the minds it
 * serves, the packets it has accepted for each and what it answered, each
 * mind's mailbox (Layer 1, 13.2, 13.5), and the feed and the records it
 * serves for each (10.1, 13.1).
 */

import type { Instant, JsonObject } from "@oip/core";
import { ARCHIVE_SQL, type Database, type Migration, NONCES_SQL } from "@oip/server";

const TABLES = `
CREATE TABLE hosted (mind TEXT PRIMARY KEY, since INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE TABLE accepted (mind TEXT NOT NULL, id TEXT NOT NULL, until INTEGER NOT NULL, answer TEXT NOT NULL, PRIMARY KEY (mind, id)) STRICT, WITHOUT ROWID;
CREATE INDEX accepted_until ON accepted (until);
CREATE TABLE mailbox (cursor INTEGER PRIMARY KEY AUTOINCREMENT, mind TEXT NOT NULL, id TEXT NOT NULL, record TEXT NOT NULL, received INTEGER NOT NULL, bytes INTEGER NOT NULL) STRICT;
CREATE UNIQUE INDEX mailbox_once ON mailbox (mind, id);
CREATE INDEX mailbox_received ON mailbox (received);
CREATE TABLE objects (mind TEXT NOT NULL, id TEXT NOT NULL, type TEXT NOT NULL, record TEXT NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY (mind, id)) STRICT, WITHOUT ROWID;
CREATE TABLE feed (mind TEXT NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL, entry TEXT NOT NULL, PRIMARY KEY (mind, seq)) STRICT, WITHOUT ROWID;
`;

/** The migrations of a host's database. */
export const HOST_MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "logs, nonces, hosted minds, accepted packets, mailboxes, objects and feeds",
    sql: [ARCHIVE_SQL, NONCES_SQL, TABLES].join("\n"),
  },
];

/** An item of a mailbox: a record, and its place in the order it came. */
export interface MailboxItem {
  readonly cursor: number;
  readonly record: JsonObject;
}

/** A host's own tables. */
export class HostStore {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  /** Whether the host serves a mind. */
  hosts(mind: string): boolean {
    return this.#db.prepare("SELECT 1 AS yes FROM hosted WHERE mind = ?").get(mind) !== undefined;
  }

  /** Takes a mind on. One served already stays as it was. */
  adopt(mind: string, now: Instant): void {
    this.#db.prepare("INSERT OR IGNORE INTO hosted (mind, since) VALUES (?, ?)").run(mind, now);
  }

  /** What the host answered when it accepted a packet for a mind, if it has and remembers. */
  answered(mind: string, id: string): JsonObject | undefined {
    const row = this.#db
      .prepare("SELECT answer FROM accepted WHERE mind = ? AND id = ?")
      .get(mind, id) as { answer: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.answer) as JsonObject);
  }

  /** Remembers a packet accepted for a mind, with the answer given, until it can no longer be accepted. */
  accept(mind: string, id: string, until: Instant, answer: JsonObject): void {
    this.#db
      .prepare("INSERT INTO accepted (mind, id, until, answer) VALUES (?, ?, ?, ?)")
      .run(mind, id, until, JSON.stringify(answer));
  }

  /** How many items a mind's mailbox holds, and how many bytes they are. */
  held(mind: string): { items: number; bytes: number } {
    return this.#db
      .prepare(
        "SELECT COUNT(*) AS items, COALESCE(SUM(bytes), 0) AS bytes FROM mailbox WHERE mind = ?",
      )
      .get(mind) as { items: number; bytes: number };
  }

  /**
   * Puts a record in a mind's mailbox. One that is there already is not put
   * there twice.
   *
   * @returns Whether it was not there before.
   */
  put(mind: string, id: string, record: JsonObject, now: Instant): boolean {
    const text = JSON.stringify(record);
    const added = this.#db
      .prepare(
        "INSERT OR IGNORE INTO mailbox (mind, id, record, received, bytes) VALUES (?, ?, ?, ?, ?)",
      )
      .run(mind, id, text, now, Buffer.byteLength(text));
    return Number(added.changes) > 0;
  }

  /**
   * The items of a mind's mailbox after a cursor, in the order they came:
   * at most `limit` of them, and no more after the one that brings them to
   * `maxBytes`. A record is read from the database only if it is returned.
   */
  after(mind: string, cursor: number, limit: number, maxBytes: number): MailboxItem[] {
    const rows = this.#db
      .prepare(
        "SELECT cursor, record, bytes FROM mailbox WHERE mind = ? AND cursor > ? ORDER BY cursor LIMIT ?",
      )
      .iterate(mind, cursor, limit) as Iterable<{ cursor: number; record: string; bytes: number }>;
    const items: MailboxItem[] = [];
    let bytes = 0;
    for (const row of rows) {
      items.push({ cursor: row.cursor, record: JSON.parse(row.record) as JsonObject });
      bytes += row.bytes;
      if (bytes >= maxBytes) break;
    }
    return items;
  }

  /** Whether a mind's mailbox holds anything after a cursor. */
  more(mind: string, cursor: number): boolean {
    return (
      this.#db
        .prepare("SELECT 1 AS more FROM mailbox WHERE mind = ? AND cursor > ? LIMIT 1")
        .get(mind, cursor) !== undefined
    );
  }

  /** How many minds the host serves. */
  minds(): number {
    return (this.#db.prepare("SELECT COUNT(*) AS minds FROM hosted").get() as { minds: number })
      .minds;
  }

  /** Removes an item from a mind's mailbox. Whether it was there. */
  remove(mind: string, cursor: number): boolean {
    return (
      Number(
        this.#db.prepare("DELETE FROM mailbox WHERE mind = ? AND cursor = ?").run(mind, cursor)
          .changes,
      ) > 0
    );
  }

  /**
   * Lets go of what is kept only for a time: mailbox items received before
   * `kept`, and accepted packets that can no longer be accepted at `now`.
   *
   * @returns How many rows went.
   */
  prune(now: Instant, kept: Instant): number {
    const mail = this.#db.prepare("DELETE FROM mailbox WHERE received < ?").run(kept).changes;
    const packets = this.#db.prepare("DELETE FROM accepted WHERE until < ?").run(now).changes;
    return Number(mail) + Number(packets);
  }

  /** A record the host serves for a mind by its content ID, if it holds it. */
  object(mind: string, id: string): JsonObject | undefined {
    const row = this.#db
      .prepare("SELECT record FROM objects WHERE mind = ? AND id = ?")
      .get(mind, id) as { record: string } | undefined;
    return row === undefined ? undefined : (JSON.parse(row.record) as JsonObject);
  }

  /** The type and the size of a record held for a mind, if it is held. */
  objectHeld(mind: string, id: string): { type: string; bytes: number } | undefined {
    return this.#db
      .prepare("SELECT type, bytes FROM objects WHERE mind = ? AND id = ?")
      .get(mind, id) as { type: string; bytes: number } | undefined;
  }

  /** How many bytes of records the host holds for a mind. */
  objectBytes(mind: string): number {
    return (
      this.#db
        .prepare("SELECT COALESCE(SUM(bytes), 0) AS bytes FROM objects WHERE mind = ?")
        .get(mind) as { bytes: number }
    ).bytes;
  }

  /** Keeps a record for a mind, in place of the copy held before if there was one. */
  keep(mind: string, id: string, type: string, record: JsonObject): void {
    const text = JSON.stringify(record);
    this.#db
      .prepare(
        "INSERT INTO objects (mind, id, type, record, bytes) VALUES (?, ?, ?, ?, ?) ON CONFLICT (mind, id) DO UPDATE SET record = excluded.record, bytes = excluded.bytes",
      )
      .run(mind, id, type, text, Buffer.byteLength(text));
  }

  /** How many entries the feed held for a mind has: the `seq` of the next. */
  feedLength(mind: string): number {
    return (
      this.#db
        .prepare("SELECT COALESCE(MAX(seq) + 1, 0) AS length FROM feed WHERE mind = ?")
        .get(mind) as { length: number }
    ).length;
  }

  /** The entry of a mind's feed at a position, if the host holds one there. */
  entryAt(mind: string, seq: number): { id: string; entry: JsonObject } | undefined {
    const row = this.#db
      .prepare("SELECT id, entry FROM feed WHERE mind = ? AND seq = ?")
      .get(mind, seq) as { id: string; entry: string } | undefined;
    return row === undefined
      ? undefined
      : { id: row.id, entry: JSON.parse(row.entry) as JsonObject };
  }

  /** Adds an entry to a mind's feed. */
  append(mind: string, seq: number, id: string, entry: JsonObject): void {
    this.#db
      .prepare("INSERT INTO feed (mind, seq, id, entry) VALUES (?, ?, ?, ?)")
      .run(mind, seq, id, JSON.stringify(entry));
  }

  /** Drops the entries of a mind's feed from a position on. */
  truncate(mind: string, from: number): void {
    this.#db.prepare("DELETE FROM feed WHERE mind = ? AND seq >= ?").run(mind, from);
  }

  /**
   * The entries of a mind's feed from a position on, in order: at most
   * `limit` of them, and no more after the one that brings them to `maxBytes`.
   */
  entriesFrom(mind: string, from: number, limit: number, maxBytes: number): JsonObject[] {
    const rows = this.#db
      .prepare("SELECT entry FROM feed WHERE mind = ? AND seq >= ? ORDER BY seq LIMIT ?")
      .iterate(mind, from, limit) as Iterable<{ entry: string }>;
    const entries: JsonObject[] = [];
    let bytes = 0;
    for (const row of rows) {
      entries.push(JSON.parse(row.entry) as JsonObject);
      bytes += Buffer.byteLength(row.entry);
      if (bytes >= maxBytes) break;
    }
    return entries;
  }
}
