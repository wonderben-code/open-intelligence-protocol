// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A process that is killed in the middle of a transaction. `storage.test.ts`
 * runs it and then opens the database it leaves behind.
 *
 * Usage: node --conditions=@oip/source crash.node.ts <database file>
 */

import { Database, systemClock } from "../src/index.ts";

const path = process.argv[2];
if (path === undefined) throw new Error("no database file was named");

const db = Database.open(
  { path },
  [
    {
      version: 1,
      name: "seen",
      sql: "CREATE TABLE seen (id TEXT PRIMARY KEY, at INTEGER NOT NULL) STRICT",
    },
  ],
  systemClock,
);
const insert = db.prepare("INSERT INTO seen (id, at) VALUES (?, ?)");
db.transaction(() => {
  insert.run("committed", 1n);
});
db.transaction(() => {
  insert.run("in flight", 2n);
  // No handler runs, nothing is flushed, no file is closed.
  process.kill(process.pid, "SIGKILL");
});
