// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Checks that the guards still guard. A rule that silently stops matching
 * looks exactly like a clean codebase, so this script feeds each guard
 * something it must reject:
 *
 *   - the layering rules (.dependency-cruiser.cjs) get the files under
 *     scripts/fixtures/layering, each of which names the rule it breaks;
 *   - the purity rules (eslint.config.js) get source text, linted as if it
 *     were a file of a pure package.
 */

import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

import { ESLint } from "eslint";

import { repoRoot } from "./lib/spec.ts";

const problems: string[] = [];

// --- Layering -----------------------------------------------------------------

const fixtures = join(repoRoot, "scripts", "fixtures", "layering");

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return entry.name.endsWith(".ts") ? [path] : [];
  });
}

const expected = new Map<string, string>();
for (const file of sourceFiles(join(fixtures, "packages"))) {
  const rule = /^\/\/ expect: (\S+)/.exec(readFileSync(file, "utf8"))?.[1];
  if (rule !== undefined) expected.set(relative(fixtures, file), rule);
}

const cruise = spawnSync(
  "pnpm",
  [
    "exec",
    "depcruise",
    "packages",
    "--config",
    join(repoRoot, ".dependency-cruiser.cjs"),
    "--output-type",
    "json",
  ],
  { cwd: fixtures, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
);
if (cruise.error !== undefined) throw cruise.error;

interface CruiseResult {
  readonly summary: {
    readonly violations: readonly {
      readonly from: string;
      readonly rule: { readonly name: string };
    }[];
  };
}
const reported = new Set(
  (JSON.parse(cruise.stdout) as CruiseResult).summary.violations.map(
    (violation) => `${violation.from} ${violation.rule.name}`,
  ),
);
if (expected.size < 5) problems.push("the layering fixtures are missing");
for (const [file, rule] of expected) {
  if (!reported.has(`${file} ${rule}`)) {
    problems.push(`dependency-cruiser did not report ${rule} for ${file}`);
  }
}

// --- Purity -------------------------------------------------------------------

const impure: [rule: string, code: string][] = [
  [
    "no-restricted-imports",
    'import { readFileSync } from "node:fs";\nexport const x = readFileSync;',
  ],
  ["no-restricted-properties", "export const x = Date.now();"],
  ["no-restricted-properties", "export const x = Math.random();"],
  ["no-restricted-syntax", "export const x = new Date();"],
  ["no-restricted-globals", "export const x = process.env;"],
  ["no-restricted-globals", 'export const x = fetch("https://example.com");'],
  ["no-console", 'console.log("x");\nexport {};'],
  ["@typescript-eslint/no-explicit-any", "export const x = (value: any) => value;"],
];

const eslint = new ESLint({ cwd: repoRoot });
// An existing file of a pure package, so that the typed rules have a project to work in.
const asFile = join(repoRoot, "packages", "schema", "src", "runtime.ts");
for (const [rule, code] of impure) {
  const [result] = await eslint.lintText(code, { filePath: asFile });
  const rules = new Set(result?.messages.map((message) => message.ruleId));
  if (!rules.has(rule)) {
    problems.push(`ESLint did not report ${rule} for: ${code.replaceAll("\n", " ")}`);
  }
}

if (problems.length > 0) {
  console.error(`The guards have gaps:\n${problems.map((problem) => `  - ${problem}`).join("\n")}`);
  process.exit(1);
}
console.log(
  `Guards hold: ${expected.size} layering fixtures and ${impure.length} purity probes rejected.`,
);
