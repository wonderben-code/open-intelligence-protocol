// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/testkit`: how tests cite the specification. It is used only by tests,
 * never by a package's source, so it may read files.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root, for tests that read the specifications or the vectors. */
export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** One numbered clause of the specifications, as `scripts/spec-clauses.ts` extracts it. */
export interface SpecClause {
  readonly id: string;
  readonly document: string;
  readonly section: string;
  readonly summary: string;
  readonly level: "MUST" | "SHOULD" | "MAY" | "none";
}

interface ClauseFile {
  readonly revision: string;
  readonly clauses: readonly SpecClause[];
}

const clauseFile = JSON.parse(
  readFileSync(join(repoRoot, "spec", "clauses.json"), "utf8"),
) as ClauseFile;

/** The specification revision the clause list was extracted from. */
export const specRevision: string = clauseFile.revision;

/** Every clause of the specifications, by ID. */
export const specClauses: ReadonlyMap<string, SpecClause> = new Map(
  clauseFile.clauses.map((clause) => [clause.id, clause]),
);

/** How a clause citation looks inside a test name. `pnpm spec:coverage` reads test names for it. */
export const CITATION = /\[((?:core|L0|L1|L2) [0-9]+(?:\.[0-9]+)?)\]/g;

/**
 * Cites the clauses a test enforces. Put the result in the test's name:
 *
 * ```ts
 * it(`${clause("L1 11.1")} rejects a delegation to its own author`, () => { … });
 * ```
 *
 * It throws on an ID that is not a clause of the specification, so a typing
 * mistake or a renumbered clause fails the test run instead of going unseen.
 */
export function clause(...ids: [string, ...string[]]): string {
  for (const id of ids) {
    if (!specClauses.has(id)) {
      throw new Error(
        `"${id}" is not a clause of specification revision ${specRevision}. ` +
          "Clause IDs look like \"core 4.4\" or \"L1 6.4\"; see spec/clauses.json.",
      );
    }
  }
  return ids.map((id) => `[${id}]`).join(" ");
}

/** The clause IDs cited in a test name. */
export function citedClauses(testName: string): string[] {
  return [...testName.matchAll(CITATION)].map((match) => match[1] ?? "");
}

/** A JSON object whose members are not yet known. */
export type JsonObject = Record<string, unknown>;

/** One must-accept case, negative case or control of the test vectors. */
export interface VectorCase extends JsonObject {
  readonly name: string;
  readonly kind: string;
  readonly reason?: string;
}

/** The test vectors, as far as tests below `@oip/conformance` need to know them. */
export interface RawVectors {
  readonly spec_revision: string;
  readonly cases: Readonly<Record<string, unknown>>;
  readonly valid: readonly VectorCase[];
  readonly negative: readonly VectorCase[];
  readonly controls: readonly VectorCase[];
}

let cachedVectors: RawVectors | undefined;

/** Reads `spec/test-vectors/vectors.json`. `@oip/conformance` has the typed loader and the runners. */
export function readVectors(): RawVectors {
  cachedVectors ??= JSON.parse(
    readFileSync(join(repoRoot, "spec", "test-vectors", "vectors.json"), "utf8"),
  ) as RawVectors;
  return cachedVectors;
}

function isRecord(value: unknown): value is JsonObject {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (value as JsonObject)["oip"] === "1" &&
    typeof (value as JsonObject)["type"] === "string"
  );
}

/**
 * Every record in the positive part of the vectors (`cases`), with a name
 * that says where it came from: single records, and each event of each log.
 */
export function positiveVectorRecords(): { name: string; record: JsonObject }[] {
  const found: { name: string; record: JsonObject }[] = [];
  for (const [name, value] of Object.entries(readVectors().cases)) {
    if (isRecord(value)) {
      found.push({ name, record: value });
    } else if (Array.isArray(value)) {
      value.forEach((item: unknown, i) => {
        if (isRecord(item)) found.push({ name: `${name}[${i}]`, record: item });
      });
    }
  }
  return found;
}

/** A deep copy of a JSON value, for tests that change a record. */
export function copy<T>(value: T): T {
  return structuredClone(value);
}
