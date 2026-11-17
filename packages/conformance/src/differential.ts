// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Differential testing: this implementation and an independent judge, on the same cases. */

import type { ConformanceAdapter } from "./adapter.ts";
import { claimHolds } from "./runner.ts";
import type { VectorCase, Vectors } from "./vectors.ts";

/** An independent judge of cases in the vectors' format, such as the Python checker. */
export interface Judge {
  judge(vectorCase: unknown): Promise<{ readonly holds: boolean; readonly error?: string }>;
}

/**
 * How the two verdicts on a case must relate.
 *
 * - `same`: both accept or both reject. The rule for verification.
 * - `no-laxer`: whatever this implementation accepts, the judge accepts too.
 *   For `record` cases, where the judge's structural checks are a subset of
 *   this implementation's schemas, so this implementation may reject more.
 */
export type Agreement = "same" | "no-laxer";

/** A case on which the two implementations disagree. */
export interface Disagreement {
  readonly case: VectorCase;
  readonly implementation: boolean;
  readonly judge: boolean;
  readonly judgeError?: string;
}

/**
 * Judges one case both ways. Returns the disagreement, or `undefined` when
 * the verdicts relate as required or the adapter cannot judge the case yet.
 */
export async function compareVerdicts(
  adapter: ConformanceAdapter,
  judge: Judge,
  vectors: Vectors,
  vectorCase: VectorCase,
  agreement: Agreement = "same",
): Promise<Disagreement | undefined> {
  const ours = claimHolds(adapter, vectors, vectorCase);
  if (ours === undefined) return undefined;
  const theirs = await judge.judge(vectorCase);
  const agree = agreement === "same" ? ours === theirs.holds : !ours || theirs.holds;
  if (agree) return undefined;
  return {
    case: vectorCase,
    implementation: ours,
    judge: theirs.holds,
    ...(theirs.error === undefined ? {} : { judgeError: theirs.error }),
  };
}
