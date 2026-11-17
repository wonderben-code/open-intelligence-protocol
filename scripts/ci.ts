// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Every check that gates a merge, in order. `pnpm run ci` runs this locally,
 * and the main CI job runs exactly this, so the two cannot drift apart.
 *
 * It starts from a clean build, because the API reports depend on it: the
 * order of a union's members in a declaration file can differ between an
 * incremental build and a clean one.
 *
 * It needs Python 3 with `cryptography`, and the REUSE tool. Both are
 * installed from `.github/requirements/` in CI. Locally, a missing REUSE
 * tool is reported and skipped; everything else is required.
 */

import { spawnSync } from "node:child_process";

import { repoRoot } from "./lib/spec.ts";

interface Step {
  readonly name: string;
  readonly command: string;
  /** A command whose absence lets the step be skipped outside CI. */
  readonly optionalTool?: string;
}

// The file in the index must be what the step just produced. After a change
// that regenerates it, stage the new file and run again.
const unchanged = (path: string) =>
  `git diff --exit-code -- ${path} || { echo "${path} was regenerated and differs from the staged file: stage it and run again"; exit 1; }`;

const STEPS: readonly Step[] = [
  { name: "Lint, format, layering, and the guards themselves", command: "pnpm lint" },
  { name: "Typecheck", command: "pnpm typecheck" },
  { name: "Generated files are current", command: "pnpm generated:check" },
  { name: "Clean build, and the API reports are current", command: "pnpm api:check" },
  {
    name: "Spec coverage, and docs/conformance/coverage.md is current",
    command: `pnpm spec:coverage && ${unchanged("docs/conformance/coverage.md")}`,
  },
  {
    name: "The Python checker regenerates the vectors unchanged",
    command: `python3 spec/test-vectors/oip_vectors.py && ${unchanged("spec/test-vectors/vectors.json")}`,
  },
  { name: "Tests, with coverage thresholds", command: "pnpm test:coverage" },
  { name: "Golden vectors, by case kind", command: "pnpm test:vectors" },
  { name: "API reference builds", command: "pnpm run docs" },
  { name: "Benchmarks run", command: "pnpm bench" },
  { name: "Licensing (REUSE)", command: "reuse lint", optionalTool: "reuse" },
];

const inActions = process.env["GITHUB_ACTIONS"] === "true";
// The differential tests fail, rather than skip, if Python is missing.
const env = { ...process.env, OIP_REQUIRE_PYTHON: "1" };

for (const step of STEPS) {
  if (step.optionalTool !== undefined && !inActions) {
    const found = spawnSync("sh", ["-c", `command -v ${step.optionalTool}`], { stdio: "ignore" });
    if (found.status !== 0) {
      console.log(
        `\n--- ${step.name}: SKIPPED, ${step.optionalTool} is not installed (CI runs it)`,
      );
      continue;
    }
  }
  console.log(inActions ? `::group::${step.name}` : `\n--- ${step.name}`);
  const run = spawnSync("sh", ["-c", step.command], { cwd: repoRoot, stdio: "inherit", env });
  if (inActions) console.log("::endgroup::");
  if (run.status !== 0) {
    console.error(`\nFAILED: ${step.name}\n  ${step.command}`);
    process.exit(run.status ?? 1);
  }
}
console.log(`\nAll ${STEPS.length} checks passed.`);
