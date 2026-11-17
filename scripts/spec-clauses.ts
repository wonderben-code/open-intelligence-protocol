// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Extracts every numbered clause of `spec/*.md`, with its BCP 14 key words,
 * into `spec/clauses.json`. Tests cite these IDs with `clause("L1 6.4")`, and
 * `pnpm spec:coverage` reports which clauses have tests.
 *
 * With `--check` it writes nothing and fails if the file is out of date.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { readClauses, repoRoot } from "./lib/spec.ts";

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");

const clauses = readClauses(sha256);
const ids = new Set<string>();
for (const clause of clauses) {
  if (ids.has(clause.id)) throw new Error(`clause ${clause.id} appears twice in the specifications`);
  ids.add(clause.id);
}

const revision = /\*\*Revision ([0-9-]+)/.exec(readFileSync(join(repoRoot, "spec/core.md"), "utf8"))?.[1];
if (revision === undefined) throw new Error("spec/core.md does not state its revision");

const output = `${JSON.stringify({ revision, clauses }, null, 2)}\n`;
const file = join(repoRoot, "spec/clauses.json");

if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(file, "utf8");
  } catch {
    // A missing file is out of date.
  }
  if (current !== output) {
    console.error("spec/clauses.json is out of date. Run `pnpm spec:clauses` and commit the result.");
    process.exit(1);
  }
  console.log(`spec/clauses.json is current (${clauses.length} clauses).`);
} else {
  writeFileSync(file, output);
  const must = clauses.filter((clause) => clause.level === "MUST").length;
  console.log(`spec/clauses.json: ${clauses.length} clauses, ${must} with MUST-level key words.`);
}
