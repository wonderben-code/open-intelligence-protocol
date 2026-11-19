// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A service's database: SQLite, as Node.js has it built in (ADR-0012).
 *
 * This is the one file that names `node:sqlite`. A service's own store is
 * written against `Database`, and speaks to its callers in the terms of
 * the protocol, so that another engine can stand behind the same store
 * (BUILD.md 3.6).
 *
 * What a service keeps is evidence: the time it first saw a proof must not
 * change once it has been served (core 9.4). So a commit reaches the disk
 * before it returns, what is recorded once is never rewritten
 * (`appendOnly`), and a database made by other code than this is not
 * opened.
 */

import { DatabaseSync, type SQLInputValue, type StatementSync } from "node:sqlite";

import { bytesToHex, sha256, utf8 } from "@oip/core";

import type { Clock } from "./edges.ts";

/** One step in the history of a database's schema. */
export interface Migration {
  /** 1 for the first, and one more for each that follows. */
  readonly version: number;
  /** A few words, for the record of what was applied. */
  readonly name: string;
  /** The SQL of the step. It is run in one transaction. */
  readonly sql: string;
}

/** How a database is opened. */
export interface DatabaseOptions {
  /** The file, or `:memory:` for a database that lasts as long as it is open. */
  readonly path: string;
  /** How long a write waits for another connection's lock, in milliseconds. 5,000 by default. */
  readonly busyTimeoutMs?: number;
  /**
   * Whether a commit reaches the disk before it returns. It does by default.
   * Without it a commit survives the process and not a loss of power: for
   * tests, and for data that is no evidence.
   */
  readonly durable?: boolean;
}

/** A failure of the storage that is no fault of what was being stored. */
export class StorageError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "StorageError";
  }
}

/**
 * A thing a service reads back that it stored in one transaction with what
 * led it there: an event with its first sight, a pair with its two events.
 * It is there, or the database is not as the service wrote it, and the
 * service says so loudly and serves nothing made up in its place.
 *
 * @param what - What is missing, for the error. Built from constants: it is logged.
 * @throws StorageError if the value is `undefined`.
 */
export function kept<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new StorageError(
      `the database does not hold ${what}, which was stored with what names it`,
    );
  }
  return value;
}

const IDENTIFIER = /^[a-z][a-z0-9_]*$/u;

/**
 * The SQL that makes a table append-only: a row is inserted, and never
 * changed or removed. First-seen times, identity events and feed entries
 * are kept so (BUILD.md 3.6).
 */
export function appendOnly(table: string): string {
  if (!IDENTIFIER.test(table))
    throw new TypeError("a table name is lower-case letters, digits and _");
  return [
    `CREATE TRIGGER ${table}_no_update BEFORE UPDATE ON ${table}`,
    `BEGIN SELECT RAISE(ABORT, '${table} is append-only'); END;`,
    `CREATE TRIGGER ${table}_no_delete BEFORE DELETE ON ${table}`,
    `BEGIN SELECT RAISE(ABORT, '${table} is append-only'); END;`,
  ].join("\n");
}

/** SQLite's primary result code of an error from `node:sqlite`, or `undefined`. */
function resultCode(error: unknown): number | undefined {
  const code = (error as { errcode?: unknown } | null)?.errcode;
  // The low byte is the primary code; the rest says which kind.
  return typeof code === "number" ? code & 0xff : undefined;
}

/** Whether a failure is another connection holding the lock for longer than the wait allowed. */
export function isBusy(error: unknown): boolean {
  const code = resultCode(error);
  return code === 5 || code === 6;
}

/** Whether a failure is a constraint of the schema: a duplicate key, or a row of an append-only table touched. */
export function isConstraint(error: unknown): boolean {
  return resultCode(error) === 19;
}

function checked(migrations: readonly Migration[]): readonly Migration[] {
  const names = new Set<string>();
  migrations.forEach((migration, position) => {
    if (migration.version !== position + 1) {
      throw new TypeError("migrations are numbered from 1, each one more than the last");
    }
    if (migration.name === "" || names.has(migration.name)) {
      throw new TypeError("each migration has a name of its own");
    }
    names.add(migration.name);
  });
  return migrations;
}

/** The fingerprint of a migration's SQL, to tell whether what was applied is what the code holds. */
function digest(migration: Migration): string {
  return bytesToHex(sha256(utf8(migration.sql)));
}

/** A SQLite database, opened for one service. */
export class Database {
  readonly #db: DatabaseSync;
  readonly #statements = new Map<string, StatementSync>();
  #depth = 0;
  #failed = false;

  private constructor(db: DatabaseSync) {
    this.#db = db;
  }

  /**
   * Opens a database and brings its schema up to the last of `migrations`.
   *
   * @throws StorageError if the database was made by other migrations than
   *   these, or by more of them: a program older than its data must not
   *   write to it.
   */
  static open(options: DatabaseOptions, migrations: readonly Migration[], clock: Clock): Database {
    const steps = checked(migrations);
    const db = new DatabaseSync(options.path, {
      timeout: options.busyTimeoutMs ?? 5000,
      enableForeignKeyConstraints: true,
      enableDoubleQuotedStringLiterals: false,
      allowExtension: false,
    });
    try {
      // Readers do not block the writer, and a reader sees one state of the whole.
      db.exec("PRAGMA journal_mode = WAL");
      db.exec(`PRAGMA synchronous = ${options.durable === false ? "NORMAL" : "FULL"}`);
      // A schema that a file brings with it runs no functions of its own choosing.
      db.exec("PRAGMA trusted_schema = OFF");
      // A row replaced is a row removed. Without this, SQLite removes it without asking the
      // trigger that keeps a table append-only.
      db.exec("PRAGMA recursive_triggers = ON");
      // The triggers that keep a table append-only cannot be put aside through the schema table.
      db.enableDefensive(true);
      const database = new Database(db);
      database.#migrate(steps, clock);
      return database;
    } catch (error) {
      db.close();
      throw error;
    }
  }

  #migrate(steps: readonly Migration[], clock: Clock): void {
    this.#db.exec(
      "CREATE TABLE IF NOT EXISTS oip_schema (version INTEGER PRIMARY KEY, name TEXT NOT NULL, digest TEXT NOT NULL, applied INTEGER NOT NULL) STRICT",
    );
    const applied = this.#db
      .prepare("SELECT version, name, digest FROM oip_schema ORDER BY version")
      .all() as { version: number; name: string; digest: string }[];
    applied.forEach((row, position) => {
      const step = steps[position];
      if (step === undefined) {
        throw new StorageError(
          `the database is at version ${applied.length}, and this program knows ${steps.length}: it is older than its data`,
        );
      }
      if (row.version !== step.version || row.name !== step.name || row.digest !== digest(step)) {
        throw new StorageError(
          `the database was not made by this program's migrations: version ${row.version} differs`,
        );
      }
    });
    for (const step of steps.slice(applied.length)) {
      this.transaction(() => {
        this.#db.exec(step.sql);
        this.#db
          .prepare("INSERT INTO oip_schema (version, name, digest, applied) VALUES (?, ?, ?, ?)")
          .run(step.version, step.name, digest(step), clock.now());
      });
    }
  }

  /** The version of the schema: how many migrations have been applied. */
  get version(): number {
    const row = this.#db.prepare("SELECT COUNT(*) AS n FROM oip_schema").get() as { n: number };
    return row.n;
  }

  /**
   * Runs `work` in one transaction: all of what it writes is kept, or none.
   * It is kept if `work` returns, and undone if it throws. The write lock
   * is taken at the start, so that two writers wait for each other and
   * neither fails half way. A call within a call is part of the outer one.
   *
   * `work` is synchronous. One that returns a promise would be committed
   * before it had finished: it is undone, and this throws.
   */
  transaction<T>(work: () => T): T {
    if (this.#depth > 0) {
      this.#depth++;
      try {
        return work();
      } catch (error) {
        // What an inner call wrote goes with the whole, whatever the outer does with the error.
        this.#failed = true;
        throw error;
      } finally {
        this.#depth--;
      }
    }
    this.#db.exec("BEGIN IMMEDIATE");
    this.#depth = 1;
    this.#failed = false;
    let result: T;
    try {
      result = work();
      if (this.#partFailed()) {
        throw new StorageError("part of the transaction failed, so none of it is kept");
      }
      if (typeof (result as { then?: unknown } | null)?.then === "function") {
        throw new TypeError("a transaction is synchronous: its work returned a promise");
      }
      this.#db.exec("COMMIT");
    } catch (error) {
      // SQLite undoes a transaction itself for some failures, a full disk among them.
      if (this.#db.isTransaction) this.#db.exec("ROLLBACK");
      throw error;
    } finally {
      this.#depth = 0;
    }
    return result;
  }

  /** Whether a call within the transaction threw, whatever became of what it threw. */
  #partFailed(): boolean {
    return this.#failed;
  }

  /** A statement, prepared once and kept. Integers are read as numbers. */
  prepare(sql: string): StatementSync {
    let statement = this.#statements.get(sql);
    if (statement === undefined) {
      statement = this.#db.prepare(sql);
      this.#statements.set(sql, statement);
    }
    return statement;
  }

  /**
   * As `prepare`, with integers read as `bigint`: for a statement that
   * reads times, which are nanoseconds and do not fit a number.
   */
  prepareWithTimes(sql: string): StatementSync {
    const key = `\u0000${sql}`;
    let statement = this.#statements.get(key);
    if (statement === undefined) {
      statement = this.#db.prepare(sql);
      statement.setReadBigInts(true);
      this.#statements.set(key, statement);
    }
    return statement;
  }

  /** Runs SQL that has no parameters and gives no rows. */
  exec(sql: string): void {
    this.#db.exec(sql);
  }

  /** Moves what the log holds into the database file. A service does so before it stops. */
  checkpoint(): void {
    this.#db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  }

  /** Closes the database. Closing twice is closing once. */
  close(): void {
    if (!this.#db.isOpen) return;
    this.#statements.clear();
    this.#db.close();
  }
}

export type { SQLInputValue, StatementSync };
