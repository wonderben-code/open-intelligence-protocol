// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Reports which clauses of the specifications have tests, and how far the
 * golden vectors have turned green. It runs the test suite, reads the clause
 * citations out of the names of the tests that passed, and writes
 * `docs/conformance/coverage.md`.
 *
 * It fails when a MUST-level clause, or a kind of vector case, owed by a
 * milestone that `docs/conformance/plan.json` lists as completed is not
 * covered by a passing test.
 *
 *   --from <file>   read a Vitest JSON report instead of running the tests
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { type Clause, repoRoot, SPEC_DOCUMENTS } from "./lib/spec.ts";

interface Plan {
  readonly completed: readonly string[];
  readonly clauses: Readonly<Record<string, string>>;
  /** Clauses that state no requirement, each with the reason. Every other clause is gated. */
  readonly informative: Readonly<Record<string, string>>;
  readonly vectors: Readonly<Record<string, string>>;
}

interface TestResult {
  readonly ancestorTitles: readonly string[];
  readonly fullName: string;
  readonly title: string;
  readonly status: string;
}

interface VitestReport {
  readonly success: boolean;
  readonly numFailedTests: number;
  readonly testResults: readonly { readonly assertionResults: readonly TestResult[] }[];
}

const CITATION = /\[((?:core|L0|L1|L2) [0-9]+(?:\.[0-9]+)?)\]/g;
// BUILD.md, Section 2: by M12 no requirement is left untested.
const LAST_MILESTONE = 12;

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function runTests(): VitestReport {
  const directory = mkdtempSync(join(tmpdir(), "oip-spec-coverage-"));
  const file = join(directory, "report.json");
  try {
    const run = spawnSync(
      "pnpm",
      ["exec", "vitest", "run", "--reporter=json", `--outputFile=${file}`],
      { cwd: repoRoot, stdio: ["ignore", "ignore", "inherit"], env: process.env },
    );
    if (run.error !== undefined) throw run.error;
    return readJson(file) as VitestReport;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function milestoneNumber(milestone: string): number {
  const match = /^M([0-9]+)$/.exec(milestone);
  if (match === null) throw new Error(`"${milestone}" is not a milestone such as M3`);
  return Number(match[1]);
}

/** The milestone that owes a clause: by its ID, then its section, then its document. */
function milestoneFor(plan: Plan, id: string): string {
  const [document = "", number = ""] = id.split(" ");
  const section = `${document} ${number.split(".")[0] ?? ""}`;
  const found = plan.clauses[id] ?? plan.clauses[section] ?? plan.clauses[document];
  if (found === undefined) throw new Error(`plan.json assigns no milestone to clause ${id}`);
  return found;
}

const from = process.argv.indexOf("--from");
const report = from === -1 ? runTests() : (readJson(process.argv[from + 1] ?? "") as VitestReport);
const tests = report.testResults.flatMap((file) => file.assertionResults);

const { revision, clauses } = readJson(join(repoRoot, "spec/clauses.json")) as {
  revision: string;
  clauses: Clause[];
};
const plan = readJson(join(repoRoot, "docs/conformance/plan.json")) as Plan;
const completed = new Set(plan.completed);
const known = new Set(clauses.map((clause) => clause.id));
const problems: string[] = [];

for (const key of Object.keys(plan.clauses)) {
  const isDocument = SPEC_DOCUMENTS.some((document) => document.prefix === key);
  const isSection = clauses.some((clause) => clause.id === key || clause.id.startsWith(`${key}.`));
  if (!isDocument && !isSection)
    problems.push(`plan.json names "${key}", which is not in the specifications`);
}

// Which passing tests cite each clause.
const passing = new Map<string, number>();
for (const test of tests) {
  for (const match of test.fullName.matchAll(CITATION)) {
    const id = match[1] ?? "";
    if (!known.has(id)) {
      problems.push(`the test "${test.fullName}" cites ${id}, which is not a clause`);
    } else if (test.status === "passed") {
      passing.set(id, (passing.get(id) ?? 0) + 1);
    }
  }
}

if (report.numFailedTests > 0) problems.push(`${report.numFailedTests} tests failed`);

for (const id of Object.keys(plan.informative)) {
  if (!known.has(id))
    problems.push(`plan.json lists "${id}" as informative, which is not a clause`);
}

interface Row {
  clause: Clause;
  milestone: string;
  tests: number;
  status: string;
}
const rows: Row[] = clauses.map((clause) => {
  const milestone = milestoneFor(plan, clause.id);
  const count = passing.get(clause.id) ?? 0;
  const done = completed.has(milestone);
  const gated = !Object.hasOwn(plan.informative, clause.id);
  let status: string;
  if (count > 0) status = done ? "tested" : `tested in part (due ${milestone})`;
  else if (!gated) status = "informative";
  else if (!done) status = `pending ${milestone}`;
  else status = "**untested**";
  if (gated) {
    if (done && count === 0) {
      problems.push(`${clause.id} is owed by ${milestone}, and no passing test cites it`);
    }
    if (milestoneNumber(milestone) > LAST_MILESTONE) {
      problems.push(
        `${clause.id} is planned for ${milestone}; no requirement may wait beyond M${LAST_MILESTONE}`,
      );
    }
  }
  return { clause, milestone: gated ? milestone : "", tests: count, status };
});

// The golden vectors: tests named "vectors: <section>: <kind>" and "vectors: positive".
interface Counts {
  passed: number;
  pending: number;
  failed: number;
}
const vectorCounts = new Map<string, Counts>();
const positive: { name: string; status: string }[] = [];
for (const test of tests) {
  const group = test.ancestorTitles[0] ?? "";
  if (!group.startsWith("vectors: ")) continue;
  const outcome =
    test.status === "passed" ? "passed" : test.status === "failed" ? "failed" : "pending";
  if (group === "vectors: positive") {
    positive.push({ name: test.title, status: outcome });
    continue;
  }
  const counts = vectorCounts.get(group) ?? { passed: 0, pending: 0, failed: 0 };
  counts[outcome]++;
  vectorCounts.set(group, counts);
}
if (vectorCounts.size === 0) problems.push("the report contains no golden-vector tests");

const vectorRows = [...vectorCounts.entries()].map(([group, counts]) => {
  const [, section = "", kind = ""] = group.split(": ");
  const milestone = plan.vectors[kind];
  if (milestone === undefined) {
    problems.push(`plan.json assigns no milestone to vector cases of kind ${kind}`);
  } else if (completed.has(milestone) && counts.pending + counts.failed > 0) {
    problems.push(
      `${counts.pending + counts.failed} ${section} ${kind} vector cases are owed by ${milestone} and do not pass`,
    );
  }
  return { section, kind, milestone: milestone ?? "?", ...counts };
});
for (const check of positive) {
  const milestone = /\((M[0-9]+)\)$/.exec(check.name)?.[1];
  if (milestone !== undefined && completed.has(milestone) && check.status !== "passed") {
    problems.push(`the positive check "${check.name}" is owed by ${milestone} and does not pass`);
  }
}

const lines: string[] = [
  "# Conformance coverage",
  "",
  "<!-- Generated by scripts/spec-coverage.ts. Do not edit; run `pnpm spec:coverage`. -->",
  "",
  `This page lists every numbered clause of the specifications (revision ${revision}) and whether a test cites it, and how far the golden test vectors have turned green. It is generated from the test run.`,
  "",
  `- A test cites a clause by putting \`clause("L1 6.4")\` in its name. Only tests that pass count.`,
  "- [plan.json](plan.json) says which milestone of [BUILD.md](../../BUILD.md) owes each clause and each kind of vector case.",
  `- Completed milestones: ${[...completed].join(", ") || "none"}. A clause owed by a completed milestone must have a test, or \`pnpm spec:coverage\` fails. That holds for every clause not listed as informative in plan.json, with or without a key word: most of the verification algorithms are written without one.`,
  "- A citation says a test enforces part of a clause, not all of it. The milestone reviews check the rest.",
  '- "Tested in part" means an earlier milestone already tests some of a clause that a later milestone completes.',
  "",
  "## Summary",
  "",
  "| Document | Clauses | Gated | Gated with a passing test | MUST-level | MUST-level with a passing test |",
  "|---|---:|---:|---:|---:|---:|",
];
const isGated = (row: Row) => row.status !== "informative";
const summary = (label: string, mine: Row[]) => {
  const gated = mine.filter(isGated);
  const must = mine.filter((row) => row.clause.level === "MUST");
  const tested = (list: Row[]) => list.filter((row) => row.tests > 0).length;
  return `| ${label} | ${mine.length} | ${gated.length} | ${tested(gated)} | ${must.length} | ${tested(must)} |`;
};
for (const { prefix, file } of SPEC_DOCUMENTS) {
  lines.push(
    summary(
      `[${prefix}](../../${file})`,
      rows.filter((row) => row.clause.document === prefix),
    ),
  );
}
lines.push(
  summary("**All**", rows),
  "",
  "## Golden vectors",
  "",
  "Cases the implementation cannot answer yet are pending, never passed.",
  "",
  "| Section | Kind | Owed by | Passing | Pending | Failing |",
  "|---|---|---|---:|---:|---:|",
  ...vectorRows.map(
    (row) =>
      `| ${row.section} | \`${row.kind}\` | ${row.milestone} | ${row.passed} | ${row.pending} | ${row.failed} |`,
  ),
  "",
  "| Positive check (and the milestone that owes it) | Status |",
  "|---|---|",
  ...positive.map((check) => `| ${check.name} | ${check.status} |`),
  "",
);
for (const { prefix, file } of SPEC_DOCUMENTS) {
  lines.push(
    `## ${prefix}`,
    "",
    `[${file}](../../${file})`,
    "",
    "| Clause | Level | Owed by | Tests | Status | Text |",
    "|---|---|---|---:|---|---|",
    ...rows
      .filter((row) => row.clause.document === prefix)
      .map(
        ({ clause, milestone, tests: count, status }) =>
          `| ${clause.id} | ${clause.level === "none" ? "" : clause.level} | ${milestone} | ${count} | ${status} | ${clause.summary.replaceAll("|", "\\|")} |`,
      ),
    "",
  );
}

writeFileSync(join(repoRoot, "docs/conformance/coverage.md"), lines.join("\n"));

const cited = rows.filter((row) => row.tests > 0).length;
console.log(`docs/conformance/coverage.md: ${rows.length} clauses, ${cited} with a passing test.`);
for (const row of vectorRows) {
  console.log(
    `  vectors ${row.section} ${row.kind}: ${row.passed} passing, ${row.pending} pending, ${row.failed} failing`,
  );
}
if (problems.length > 0) {
  console.error(
    `\nspec:coverage failed:\n${[...new Set(problems)].map((problem) => `  - ${problem}`).join("\n")}`,
  );
  process.exit(1);
}
