// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What an indexer keeps besides its archive of identity logs: the things a
 * capability query can find (Layer 1, 18.2), and the packets it has
 * forwarded (18.5).
 *
 * One **item** is one thing a result can name: a mind's profile, one
 * capability of it, an Offer or an Intent. Its text is searched with
 * SQLite's FTS5, and its tags are matched exactly or by prefix.
 */

import type { Instant } from "@oip/core";
import { ARCHIVE_SQL, type Database, type Migration, NONCES_SQL } from "@oip/server";

/** The record types a capability query searches (18.2). */
export type Kind = "Participant" | "Offer" | "Intent";

const TABLES = `
CREATE TABLE items (item INTEGER PRIMARY KEY AUTOINCREMENT, mind TEXT NOT NULL, record TEXT NOT NULL, kind TEXT NOT NULL, capability TEXT, expires INTEGER, seen INTEGER NOT NULL) STRICT;
CREATE INDEX items_record ON items (record);
CREATE INDEX items_mind ON items (mind, kind);
CREATE INDEX items_expires ON items (expires) WHERE expires IS NOT NULL;
CREATE TABLE item_tags (item INTEGER NOT NULL, tag TEXT NOT NULL, PRIMARY KEY (item, tag)) STRICT, WITHOUT ROWID;
CREATE INDEX item_tags_tag ON item_tags (tag, item);
CREATE VIRTUAL TABLE item_text USING fts5(body, tokenize = 'unicode61 remove_diacritics 2');
CREATE TABLE forwarded (id TEXT PRIMARY KEY, until INTEGER NOT NULL, minds INTEGER NOT NULL) STRICT, WITHOUT ROWID;
CREATE INDEX forwarded_until ON forwarded (until);
`;

/** The migrations of an indexer's database. */
export const INDEXER_MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: "logs, nonces, what a query finds, and packets forwarded",
    sql: [ARCHIVE_SQL, NONCES_SQL, TABLES].join("\n"),
  },
];

/** One thing a query can find, as it is put into the index. */
export interface Item {
  /** The mind whose record it is. */
  readonly mind: string;
  /** The content ID of the record. */
  readonly record: string;
  readonly kind: Kind;
  /** For a capability of a profile, its `id`. */
  readonly capability?: string;
  /** When the record expires, if it says. */
  readonly expires?: Instant;
  /** The words a query's `want` is matched against. */
  readonly text: string;
  /** The tags a query's `tags` are matched against. */
  readonly tags: readonly string[];
}

/** One thing a query found. */
export interface Found {
  readonly mind: string;
  readonly record: string;
  readonly kind: Kind;
  readonly capability: string | null;
}

/** What a query asks of the index, already read from the query. */
export interface Search {
  /** An FTS5 query made of quoted words, or `undefined` to match by tags and kinds alone. */
  readonly match?: string;
  readonly kinds: readonly Kind[];
  /** Each must be matched: exactly, or as a prefix where `prefix` is set. */
  readonly tags: readonly { readonly value: string; readonly prefix: boolean }[];
  readonly now: Instant;
  readonly limit: number;
}

/** `LIKE` takes `%` and `_` as patterns: in a tag they are themselves. */
const literal = (text: string): string => text.replace(/[\\%_]/gu, (special) => `\\${special}`);

/** An indexer's own tables. */
export class IndexStore {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  /** Puts an item into the index. */
  add(item: Item, seen: Instant): void {
    const added = this.#db
      .prepare(
        "INSERT INTO items (mind, record, kind, capability, expires, seen) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(item.mind, item.record, item.kind, item.capability ?? null, item.expires ?? null, seen);
    const id = added.lastInsertRowid;
    this.#db.prepare("INSERT INTO item_text (rowid, body) VALUES (?, ?)").run(id, item.text);
    const tag = this.#db.prepare("INSERT OR IGNORE INTO item_tags (item, tag) VALUES (?, ?)");
    for (const value of item.tags) tag.run(id, value);
  }

  /** Takes items out of the index, with their text and tags. How many went. */
  #remove(where: string, ...given: (string | bigint)[]): number {
    const items = this.#db.prepare(`SELECT item FROM items WHERE ${where}`).all(...given) as {
      item: number;
    }[];
    for (const { item } of items) {
      this.#db.prepare("DELETE FROM item_text WHERE rowid = ?").run(item);
      this.#db.prepare("DELETE FROM item_tags WHERE item = ?").run(item);
      this.#db.prepare("DELETE FROM items WHERE item = ?").run(item);
    }
    return items.length;
  }

  /** Takes every item of a record out of the index. How many went. */
  removeRecord(record: string): number {
    return this.#remove("record = ?", record);
  }

  /** Takes a mind's profile and its capabilities out of the index. How many items went. */
  removeProfile(mind: string): number {
    return this.#remove("mind = ? AND kind = 'Participant'", mind);
  }

  /** Takes out what has expired at `now`. How many items went. */
  expire(now: Instant): number {
    return this.#remove("expires IS NOT NULL AND expires < ?", now);
  }

  /** The mind whose record this is, if the index holds an item of it. */
  holderOf(record: string): string | undefined {
    const row = this.#db.prepare("SELECT mind FROM items WHERE record = ? LIMIT 1").get(record) as
      { mind: string } | undefined;
    return row?.mind;
  }

  /** How many records of a kind the index holds for a mind. */
  records(mind: string, kind: Kind): number {
    return (
      this.#db
        .prepare("SELECT COUNT(DISTINCT record) AS n FROM items WHERE mind = ? AND kind = ?")
        .get(mind, kind) as { n: number }
    ).n;
  }

  /**
   * What a query finds, best first: by how well its text matches where the
   * query has words, and the newest first where it has none.
   */
  search(search: Search): Found[] {
    if (search.kinds.length === 0 || search.limit <= 0) return [];
    const given: (string | bigint | number)[] = [];
    const where: string[] = [];
    if (search.match !== undefined) {
      where.push("item_text MATCH ?");
      given.push(search.match);
    }
    where.push(`i.kind IN (${search.kinds.map(() => "?").join(", ")})`);
    given.push(...search.kinds);
    where.push("(i.expires IS NULL OR i.expires >= ?)");
    given.push(search.now);
    for (const tag of search.tags) {
      where.push(
        tag.prefix
          ? "EXISTS (SELECT 1 FROM item_tags t WHERE t.item = i.item AND t.tag LIKE ? ESCAPE '\\')"
          : "EXISTS (SELECT 1 FROM item_tags t WHERE t.item = i.item AND t.tag = ?)",
      );
      given.push(tag.prefix ? `${literal(tag.value)}%` : tag.value);
    }
    given.push(search.limit);
    const from =
      search.match === undefined ? "items i" : "item_text JOIN items i ON i.item = item_text.rowid";
    const order =
      search.match === undefined ? "i.seen DESC, i.item DESC" : "bm25(item_text), i.item";
    return this.#db
      .prepare(
        `SELECT i.mind, i.record, i.kind, i.capability FROM ${from} WHERE ${where.join(" AND ")} ORDER BY ${order} LIMIT ?`,
      )
      .all(...given) as unknown as Found[];
  }

  /** How many minds a packet was forwarded to, if the indexer forwarded it and remembers. */
  forwardedTo(id: string): number | undefined {
    const row = this.#db.prepare("SELECT minds FROM forwarded WHERE id = ?").get(id) as
      { minds: number } | undefined;
    return row?.minds;
  }

  /** Remembers a packet that was forwarded, until it can no longer be accepted. */
  forward(id: string, until: Instant, minds: number): void {
    this.#db
      .prepare("INSERT INTO forwarded (id, until, minds) VALUES (?, ?, ?)")
      .run(id, until, minds);
  }

  /** Forgets the packets that can no longer be accepted at `now`. How many went. */
  forget(now: Instant): number {
    return Number(this.#db.prepare("DELETE FROM forwarded WHERE until < ?").run(now).changes);
  }
}
