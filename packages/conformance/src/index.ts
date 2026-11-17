// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/conformance`: the golden test vectors, run against any implementation
 * through an adapter, and differential testing against the independent
 * Python checker.
 *
 * @packageDocumentation
 */

export { type ConformanceAdapter, METHOD_FOR_KIND, type VerifierView } from "./adapter.ts";
export { type Agreement, compareVerdicts, type Disagreement, type Judge } from "./differential.ts";
export {
  loadVectors,
  PythonJudge,
  type PythonJudgeOptions,
  pythonJudgeUnavailable,
  VECTORS_DIRECTORY,
  type Verdict,
} from "./node.ts";
export { referenceAdapter } from "./reference.ts";
export {
  type CaseResult,
  claimHolds,
  claimMustHold,
  type Outcome,
  POSITIVE_CHECKS,
  type PositiveCheck,
  runCase,
  runVectors,
  tally,
  viewFor,
} from "./runner.ts";
export {
  type AssuranceCase,
  CASE_KINDS,
  type CaseKind,
  type CountsForCase,
  type ExpectedStatus,
  type JsonObject,
  type Log,
  type LogCase,
  namedLog,
  namedRecord,
  parseVectors,
  positiveRecords,
  type RecordCase,
  type Section,
  SECTIONS,
  type Seen,
  type SentForCase,
  type StatusCase,
  type TestKey,
  type VectorCase,
  type Vectors,
} from "./vectors.ts";
