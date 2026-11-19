// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  appendOnly,
  type Clock,
  Database,
  isBusy,
  isConstraint,
  kept,
  type Migration,
  StorageError,
} from "../src/index.ts";

/** A clock that says what it is told to. */
function clockAt(instant: bigint): Clock {
  return { now: () => instant };
}

const SEEN: Migration = {
  version: 1,
  name: "first sight",
  sql: `CREATE TABLE seen (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT;\n${appendOnly("seen")}`,
};
const NOTES: Migration = {
  version: 2,
  name: "notes",
  sql: "CREATE TABLE notes (id INTEGER PRIMARY KEY, seen TEXT NOT NULL REFERENCES seen (id), text TEXT NOT NULL) STRICT",
};

let directory: string;
let opened: Database[];

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-server-"));
  opened = [];
});
afterEach(() => {
  for (const db of opened) db.close();
  rmSync(directory, { recursive: true, force: true });
});

const file = (name = "service.db"): string => join(directory, name);

function open(
  migrations: readonly Migration[],
  options: { path?: string; busyTimeoutMs?: number; at?: bigint } = {},
): Database {
  const db = Database.open(
    {
      path: options.path ?? file(),
      // A test's data is no evidence, and a disk that is slow to flush would only slow it.
      durable: false,
      ...(options.busyTimeoutMs === undefined ? {} : { busyTimeoutMs: options.busyTimeoutMs }),
    },
    migrations,
    clockAt(options.at ?? 1_000n),
  );
  opened.push(db);
  return db;
}

const count = (db: Database, table: string): number =>
  (db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n;

describe("a database's schema", () => {
  it("is brought up to the last migration, each applied once and recorded with its time", () => {
    const first = open([SEEN], { at: 5_000_000_000_000_000_000n });
    expect(first.version).toBe(1);
    first.prepare("INSERT INTO seen (id, at) VALUES (?, ?)").run("a", 7n);
    first.close();

    const second = open([SEEN, NOTES], { at: 6_000_000_000_000_000_000n });
    expect(second.version).toBe(2);
    // What the first held is there, and the first migration was not run again.
    expect(count(second, "seen")).toBe(1);
    expect(
      second
        .prepareWithTimes("SELECT version, name, applied FROM oip_schema ORDER BY version")
        .all(),
    ).toEqual([
      { version: 1n, name: "first sight", applied: 5_000_000_000_000_000_000n },
      { version: 2n, name: "notes", applied: 6_000_000_000_000_000_000n },
    ]);
    second.close();
    // Opened again with the same migrations, nothing changes.
    expect(open([SEEN, NOTES]).version).toBe(2);
  });

  it("is not opened by a program older than its data", () => {
    open([SEEN, NOTES]).close();
    expect(() => open([SEEN])).toThrow(StorageError);
    expect(() => open([SEEN])).toThrow(/older than its data/u);
    expect(() => open([])).toThrow(StorageError);
  });

  it("is not opened where a migration it was made by is not the one the program holds", () => {
    open([SEEN, NOTES]).close();
    const renamed = { ...NOTES, name: "remarks" };
    const rewritten = { ...NOTES, sql: `${NOTES.sql} ` };
    for (const other of [renamed, rewritten]) {
      expect(() => open([SEEN, other])).toThrow(/version 2 differs/u);
    }
    expect(() => open([{ ...SEEN, sql: "CREATE TABLE seen (id TEXT) STRICT" }, NOTES])).toThrow(
      /version 1 differs/u,
    );
    // And the database is as it was.
    expect(open([SEEN, NOTES]).version).toBe(2);
  });

  it("takes migrations numbered from 1, each with a name of its own", () => {
    for (const wrong of [
      [NOTES],
      [SEEN, { ...NOTES, version: 3 }],
      [SEEN, { ...NOTES, version: 1 }],
      [{ ...SEEN, version: 0 }],
      [SEEN, { ...NOTES, name: SEEN.name }],
      [{ ...SEEN, name: "" }],
    ]) {
      expect(() => open(wrong, { path: file("never.db") })).toThrow(TypeError);
    }
  });

  it("keeps nothing of a migration that fails", () => {
    const broken: Migration = {
      version: 2,
      name: "notes",
      sql: "CREATE TABLE notes (id INTEGER PRIMARY KEY) STRICT; CREATE TABLE seen (id TEXT) STRICT",
    };
    expect(() => open([SEEN, broken])).toThrow(/already exists/u);
    const db = open([SEEN]);
    expect(db.version).toBe(1);
    expect(() => db.prepare("SELECT * FROM notes")).toThrow(/no such table/u);
    db.close();
    // Put right, it is applied: the one that failed was never recorded.
    expect(open([SEEN, NOTES]).version).toBe(2);
  });
});

describe("a transaction", () => {
  it("keeps all of what its work wrote when the work returns, and gives what it returned", () => {
    const db = open([SEEN]);
    const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
    expect(
      db.transaction(() => {
        insert.run("a", 1n);
        insert.run("b", 2n);
        return "done";
      }),
    ).toBe("done");
    expect(count(db, "seen")).toBe(2);
  });

  it("keeps none of it when the work throws, and throws what the work threw", () => {
    const db = open([SEEN]);
    const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
    const mistake = new Error("half way");
    expect(() =>
      db.transaction(() => {
        insert.run("a", 1n);
        throw mistake;
      }),
    ).toThrow(mistake);
    expect(count(db, "seen")).toBe(0);
    // And the next one starts clean.
    db.transaction(() => insert.run("b", 2n));
    expect(count(db, "seen")).toBe(1);
  });

  it("takes a call within a call as part of the whole", () => {
    const db = open([SEEN]);
    const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
    db.transaction(() => {
      insert.run("a", 1n);
      db.transaction(() => insert.run("b", 2n));
    });
    expect(count(db, "seen")).toBe(2);
    expect(() =>
      db.transaction(() => {
        insert.run("c", 3n);
        db.transaction(() => {
          insert.run("d", 4n);
          throw new Error("inner");
        });
      }),
    ).toThrow("inner");
    expect(count(db, "seen")).toBe(2);
  });

  it("keeps nothing where part of it failed, even if the work went on", () => {
    const db = open([SEEN]);
    const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
    expect(() =>
      db.transaction(() => {
        insert.run("a", 1n);
        try {
          db.transaction(() => {
            insert.run("b", 2n);
            throw new Error("inner");
          });
        } catch {
          // The outer work goes on as if nothing had happened.
        }
        insert.run("c", 3n);
      }),
    ).toThrow(StorageError);
    expect(count(db, "seen")).toBe(0);
    db.transaction(() => insert.run("d", 4n));
    expect(count(db, "seen")).toBe(1);
  });

  it("is synchronous: work that returns a promise is undone", () => {
    const db = open([SEEN]);
    const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
    expect(() =>
      // eslint-disable-next-line @typescript-eslint/require-await
      db.transaction(async () => {
        insert.run("a", 1n);
      }),
    ).toThrow(TypeError);
    expect(count(db, "seen")).toBe(0);
  });

  it("leaves no transaction open when a constraint fails inside it", () => {
    const db = open([SEEN]);
    const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
    insert.run("a", 1n);
    let failure: unknown;
    try {
      db.transaction(() => {
        insert.run("b", 2n);
        insert.run("a", 3n);
      });
    } catch (error) {
      failure = error;
    }
    expect(isConstraint(failure)).toBe(true);
    expect(isBusy(failure)).toBe(false);
    expect(count(db, "seen")).toBe(1);
    db.transaction(() => insert.run("c", 4n));
    expect(count(db, "seen")).toBe(2);
  });
});

describe("an append-only table", () => {
  it("takes a row, and lets none be changed or removed", () => {
    const db = open([SEEN]);
    db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)").run("a", 1n);
    for (const sql of [
      "UPDATE seen SET at = 2 WHERE id = 'a'",
      "DELETE FROM seen WHERE id = 'a'",
      "DELETE FROM seen",
      // A row replaced is a row removed, and one overwritten on conflict is changed.
      "INSERT OR REPLACE INTO seen (id, at) VALUES ('a', 2)",
      "REPLACE INTO seen (id, at) VALUES ('a', 2)",
      "INSERT INTO seen (id, at) VALUES ('a', 2) ON CONFLICT (id) DO UPDATE SET at = excluded.at",
    ]) {
      let failure: unknown;
      try {
        db.exec(sql);
      } catch (error) {
        failure = error;
      }
      expect(isConstraint(failure), sql).toBe(true);
    }
    expect(db.prepareWithTimes("SELECT id, at FROM seen").all()).toEqual([{ id: "a", at: 1n }]);
  });

  it("keeps its guard: the schema table cannot be written, and takes no other name than a plain one", () => {
    const db = open([SEEN]);
    expect(() => {
      db.exec("PRAGMA writable_schema = ON; DELETE FROM sqlite_master WHERE type = 'trigger'");
    }).toThrow(/may not be modified/u);
    for (const name of ["Seen", "seen; DROP TABLE seen", "", "1seen", "seen-table", 'se"en']) {
      expect(() => appendOnly(name)).toThrow(TypeError);
    }
  });
});

describe("what a database holds", () => {
  it("gives a time back as it was given: nanoseconds, beyond what a number holds", () => {
    const db = open([SEEN]);
    const instant = 1_795_000_000_123_456_789n;
    db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)").run("a", instant);
    expect(db.prepareWithTimes("SELECT at FROM seen WHERE id = ?").get("a")).toEqual({
      at: instant,
    });
    // The same statement, prepared once.
    expect(db.prepareWithTimes("SELECT at FROM seen WHERE id = ?")).toBe(
      db.prepareWithTimes("SELECT at FROM seen WHERE id = ?"),
    );
    expect(db.prepare("SELECT at FROM seen WHERE id = ?")).not.toBe(
      db.prepareWithTimes("SELECT at FROM seen WHERE id = ?"),
    );
    // A statement that reads integers as numbers refuses one it cannot hold.
    expect(() => db.prepare("SELECT at FROM seen WHERE id = ?").get("a")).toThrow(/too large/u);
    expect(db.prepare("SELECT COUNT(*) AS n FROM seen").get()).toEqual({ n: 1 });
  });

  it("holds to its references, and takes a quoted name for a name and not for text", () => {
    const db = open([SEEN, NOTES]);
    let failure: unknown;
    try {
      db.prepare("INSERT INTO notes (seen, text) VALUES (?, ?)").run("nobody", "x");
    } catch (error) {
      failure = error;
    }
    expect(isConstraint(failure)).toBe(true);
    expect(() => db.prepare('SELECT "no such column" FROM seen')).toThrow(/no such column/u);
  });

  it("is written by one connection at a time: the other waits, then is told, and has written nothing", () => {
    const first = open([SEEN]);
    const second = open([SEEN], { busyTimeoutMs: 50 });
    const sql = "INSERT INTO seen (id, at) VALUES (?, ?)";
    let failure: unknown;
    first.transaction(() => {
      first.prepare(sql).run("a", 1n);
      try {
        second.transaction(() => second.prepare(sql).run("b", 2n));
      } catch (error) {
        failure = error;
      }
      // A reader is not kept waiting, and sees the state before this transaction.
      expect(count(second, "seen")).toBe(0);
    });
    expect(isBusy(failure)).toBe(true);
    expect(isConstraint(failure)).toBe(false);
    expect(count(second, "seen")).toBe(1);
    second.transaction(() => second.prepare(sql).run("b", 2n));
    expect(count(first, "seen")).toBe(2);
  });

  it("is in one file once its log is moved into it, and closing twice is closing once", () => {
    const db = open([SEEN]);
    db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)").run("a", 1n);
    expect(statSync(`${file()}-wal`).size).toBeGreaterThan(0);
    db.checkpoint();
    expect(statSync(`${file()}-wal`).size).toBe(0);
    db.close();
    db.close();
    expect(count(open([SEEN]), "seen")).toBe(1);
  });

  it("is whole after the process is killed in the middle of a transaction", () => {
    const path = file("crash.db");
    const child = spawnSync(
      process.execPath,
      [
        "--conditions=@oip/source",
        fileURLToPath(new URL("./crash.node.ts", import.meta.url)),
        path,
      ],
      { encoding: "utf8", timeout: 60_000 },
    );
    expect(child.signal).toBe("SIGKILL");
    const db = Database.open(
      { path },
      // As the script made it.
      [
        {
          version: 1,
          name: "seen",
          sql: "CREATE TABLE seen (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT",
        },
      ],
      clockAt(1n),
    );
    opened.push(db);
    // What was committed is there. What was in flight is not, in whole or in part.
    expect(db.prepareWithTimes("SELECT id, at FROM seen").all()).toEqual([
      { id: "committed", at: 1n },
    ]);
    db.transaction(() => db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)").run("after", 3n));
    expect(count(db, "seen")).toBe(2);
  });
});

describe("failures that are no SQLite failure", () => {
  it("are neither a lock held nor a constraint", () => {
    for (const value of [
      undefined,
      null,
      new Error("x"),
      { errcode: "5" },
      { errcode: 1 },
      "busy",
    ]) {
      expect(isBusy(value)).toBe(false);
      expect(isConstraint(value)).toBe(false);
    }
    // The kinds SQLite tells apart within one code are the same failure here.
    expect(isBusy({ errcode: 5 })).toBe(true);
    expect(isBusy({ errcode: 261 })).toBe(true);
    expect(isBusy({ errcode: 6 })).toBe(true);
    expect(isConstraint({ errcode: 19 })).toBe(true);
    expect(isConstraint({ errcode: 1811 })).toBe(true);
    expect(isConstraint({ errcode: 2067 })).toBe(true);
  });
});

describe("what a service reads back that it stored with what names it", () => {
  it("is given as it is, and its absence is a failure of the storage that is said loudly", () => {
    expect(kept(0, "a count")).toBe(0);
    expect(kept("", "a text")).toBe("");
    expect(kept(null, "a null")).toBeNull();
    let thrown: unknown;
    try {
      kept(undefined, "the first sight of an event");
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(StorageError);
    expect((thrown as Error).message).toBe(
      "the database does not hold the first sight of an event, which was stored with what names it",
    );
  });
});
