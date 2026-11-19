// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a host keeps besides its archive of identity logs: the minds it
 * serves, the packets it has accepted for each and what it answered, and
 * each mind's mailbox (Layer 1, 13.2, 13.5).
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
`;

/** The migrations of a host's database. */
export const HOST_MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "logs, nonces, hosted minds, accepted packets and mailboxes",
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

  /** The items of a mind's mailbox after a cursor, in the order they came. */
  after(mind: string, cursor: number, limit: number): MailboxItem[] {
    const rows = this.#db
      .prepare(
        "SELECT cursor, record FROM mailbox WHERE mind = ? AND cursor > ? ORDER BY cursor LIMIT ?",
      )
      .all(mind, cursor, limit) as { cursor: number; record: string }[];
    return rows.map((row) => ({
      cursor: row.cursor,
      record: JSON.parse(row.record) as JsonObject,
    }));
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
}
