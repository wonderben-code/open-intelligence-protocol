// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Runs the golden vectors against an implementation, case by case. */

import { type ConformanceAdapter, METHOD_FOR_KIND, type VerifierView } from "./adapter.ts";
import {
  type CaseKind,
  namedLog,
  namedRecord,
  positiveRecords,
  type Section,
  SECTIONS,
  type VectorCase,
  type Vectors,
} from "./vectors.ts";

/**
 * `pass`: the implementation gave the required verdict. `fail`: it did not.
 * `pending`: the adapter does not implement what the case needs yet.
 */
export type Outcome = "pass" | "fail" | "pending";

export interface CaseResult {
  readonly section: Section | "positive";
  readonly kind: CaseKind | "reproduce";
  readonly name: string;
  readonly outcome: Outcome;
  /** For a failure, what was required and what happened. */
  readonly detail?: string;
}

/** The verifier's view for a case: the baseline plus what the case adds. */
export function viewFor(vectors: Vectors, vectorCase: VectorCase): VerifierView {
  return {
    logs: vectors.baseline.logs.map((name) => namedLog(vectors, name)),
    extraLogs: vectorCase.extraLogs ?? [],
    branches: vectorCase.branches ?? [],
    records: vectors.baseline.records.map((name) => namedRecord(vectors, name)),
    extraRecords: vectorCase.extraRecords ?? [],
    seen: vectorCase.seen,
  };
}

/**
 * Whether a case's claim holds for the implementation: the log verifies, the
 * record counts for (or was sent for) the mind, the status or assurance is
 * the one expected, or the record is well formed. `undefined` when the
 * adapter lacks the method the case needs.
 *
 * It lets an exception from the adapter through. A verifier judges hostile
 * input and answers; one that throws has not answered, and must never pass a
 * negative case by crashing on it.
 */
export function claimHolds(
  adapter: ConformanceAdapter,
  vectors: Vectors,
  vectorCase: VectorCase,
): boolean | undefined {
  if (adapter[METHOD_FOR_KIND[vectorCase.kind]] === undefined) return undefined;
  const view = viewFor(vectors, vectorCase);
  switch (vectorCase.kind) {
    case "log":
      return verdict(adapter.logVerifies?.(vectorCase.log, view));
    case "countsFor":
      return verdict(adapter.countsFor?.(vectorCase.record, vectorCase.mind, view));
    case "sentFor":
      return verdict(adapter.sentFor?.(vectorCase.record, vectorCase.mind, view));
    case "status":
      return (
        named(adapter.status?.(vectorCase.of, vectorCase.records, vectorCase.at, view)) ===
        vectorCase.expect
      );
    case "assurance":
      return named(adapter.assurance?.(vectorCase.record, view)) === vectorCase.expect;
    case "record":
      return verdict(adapter.recordIsWellFormed?.(vectorCase.record));
  }
}

/**
 * An answer must be exactly `true` or `false`. Anything else (`undefined`
 * from a method that forgot to return, a truthy object) is not a verdict,
 * and reading it as "rejected" would pass the negative cases.
 */
function verdict(answer: unknown): boolean {
  if (typeof answer !== "boolean") {
    throw new TypeError(`the adapter answered ${describe(answer)}, not true or false`);
  }
  return answer;
}

function named(answer: unknown): string {
  if (typeof answer !== "string") {
    throw new TypeError(`the adapter answered ${describe(answer)}, not a string`);
  }
  return answer;
}

function describe(answer: unknown): string {
  if (answer === null || answer === undefined) return String(answer);
  return typeof answer === "object" ? "an object" : `a ${typeof answer}`;
}

/**
 * Whether a case requires its claim to hold. Must-accept cases and controls
 * do. A negative case requires it not to hold, except for `status` and
 * `assurance` cases, whose `expect` already is the safe result (not the one
 * an attacker wanted).
 */
export function claimMustHold(section: Section, kind: CaseKind): boolean {
  return section !== "negative" || kind === "status" || kind === "assurance";
}

/** Runs one case. An adapter that throws fails the case, whatever the case requires. */
export function runCase(
  adapter: ConformanceAdapter,
  vectors: Vectors,
  section: Section,
  vectorCase: VectorCase,
): CaseResult {
  const base = { section, kind: vectorCase.kind, name: vectorCase.name };
  let holds: boolean | undefined;
  try {
    holds = claimHolds(adapter, vectors, vectorCase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ...base, outcome: "fail", detail: `the implementation threw: ${message}` };
  }
  if (holds === undefined) return { ...base, outcome: "pending" };
  const required = claimMustHold(section, vectorCase.kind);
  if (holds === required) return { ...base, outcome: "pass" };
  const wanted = required ? "accepted" : "rejected";
  const reason = vectorCase.reason === undefined ? "" : ` ${vectorCase.reason}`;
  return { ...base, outcome: "fail", detail: `must be ${wanted}.${reason}` };
}

/** One check of the positive part of the vectors: values an implementation must reproduce. */
export interface PositiveCheck {
  readonly name: string;
  /** The milestone of the reference implementation in which the check turns green. */
  readonly milestone: string;
  /** Returns `undefined` when the adapter cannot run it yet, or a list of mismatches (empty for a pass). */
  run(adapter: ConformanceAdapter, vectors: Vectors): string[] | undefined;
}

const later = (name: string, milestone: string): PositiveCheck => ({
  name,
  milestone,
  run: () => undefined,
});

/**
 * The checks of the positive part, in the order of the Python checker's
 * `check()`. Those that need parts of the implementation that do not exist
 * yet are pending, and name the milestone that fills them in.
 */
export const POSITIVE_CHECKS: readonly PositiveCheck[] = [
  {
    name: "every record in the positive vectors is well formed",
    milestone: "M0",
    run(adapter, vectors) {
      if (adapter.recordIsWellFormed === undefined) return undefined;
      return positiveRecords(vectors)
        .filter(({ record }) => adapter.recordIsWellFormed?.(record) !== true)
        .map(({ name }) => `${name} was rejected`);
    },
  },
  {
    name: "JCS example",
    milestone: "M1",
    run(adapter, vectors) {
      if (adapter.canonicalize === undefined) return undefined;
      const example = vectors.cases["jcs_example"] as { input: unknown; output: string };
      const got = adapter.canonicalize(example.input);
      return got === example.output ? [] : [`expected ${example.output}, got ${got}`];
    },
  },
  later("content IDs use the canonical spelling and reproduce", "M1"),
  later("every proofValue reproduces from its test key", "M1"),
  later("identity logs verify; addresses derive from genesis", "M2"),
  later("2-of-3 pre-rotation with distinct keys", "M2"),
  later("lineage acknowledged by a Fork event and by a Lineage record", "M2"),
  later("signatures count for their authors (purpose and key checks)", "M2"),
  later("DID documents, current and versioned", "M2"),
  later("packet sent on Amina's behalf under a /oip/send delegation", "M3"),
  later("co-signing keeps the content ID; delegated party proof", "M3"),
  later("two agents sign for their principals, in either order", "M3"),
  later("delegation policy enforced (120, 500 ok; 500.01, 900 not)", "M3"),
  later("two-step delegation chain (150 ok; 300 beyond the sub-limit)", "M3"),
  later("collective signs by 2-of-3 threshold and by a charter role", "M3"),
  later("Layer 2 status (every state of Intent, Offer and Commitment)", "M3"),
  later("feed entries commit to proofs; checkpoint Merkle root", "M4"),
  later("packet opens its session; Ack names the packet", "M4"),
  later("a bridged mind, attested in its gateway's feed", "M9"),
];

function runPositive(
  check: PositiveCheck,
  adapter: ConformanceAdapter,
  vectors: Vectors,
): CaseResult {
  const base = { section: "positive", kind: "reproduce", name: check.name } as const;
  let mismatches: string[] | undefined;
  try {
    mismatches = check.run(adapter, vectors);
  } catch (error) {
    mismatches = [`threw ${error instanceof Error ? error.message : String(error)}`];
  }
  if (mismatches === undefined) return { ...base, outcome: "pending" };
  if (mismatches.length === 0) return { ...base, outcome: "pass" };
  return { ...base, outcome: "fail", detail: mismatches.join("; ") };
}

/** Runs every positive check and every case. */
export function runVectors(adapter: ConformanceAdapter, vectors: Vectors): CaseResult[] {
  return [
    ...POSITIVE_CHECKS.map((check) => runPositive(check, adapter, vectors)),
    ...SECTIONS.flatMap((section) =>
      vectors[section].map((vectorCase) => runCase(adapter, vectors, section, vectorCase)),
    ),
  ];
}

/** How many results had each outcome. */
export function tally(results: readonly CaseResult[]): Record<Outcome, number> {
  const counts: Record<Outcome, number> = { pass: 0, fail: 0, pending: 0 };
  for (const result of results) counts[result.outcome]++;
  return counts;
}
