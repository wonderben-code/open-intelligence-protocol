// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/testkit`: how tests cite the specification. It is used only by tests,
 * never by a package's source, so it may read files.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "./vectors.ts";

export { type AmbientAllowance, withAmbientTrapped } from "./ambient.ts";
export { heapInUse, heapKeptBy } from "./heap.ts";
export { inNode, tally } from "./node.ts";
export {
  AMINA,
  CID,
  LEXIS_AGENT,
  OTHER_CID,
  sampleProofRecord,
  sampleRecords,
  T0,
} from "./samples.ts";
export { withStackSpent } from "./stack.ts";
export {
  copy,
  type JsonObject,
  positiveVectorRecords,
  type RawVectors,
  readVectors,
  repoRoot,
  type VectorCase,
} from "./vectors.ts";

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
          'Clause IDs look like "core 4.4" or "L1 6.4"; see spec/clauses.json.',
      );
    }
  }
  return ids.map((id) => `[${id}]`).join(" ");
}

/** The clause IDs cited in a test name. */
export function citedClauses(testName: string): string[] {
  return [...testName.matchAll(CITATION)].map((match) => match[1] ?? "");
}
