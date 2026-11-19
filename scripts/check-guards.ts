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
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
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
  const rule = /^\/\/ expect: (\S+)/m.exec(readFileSync(file, "utf8"))?.[1];
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
if (expected.size < 6) problems.push("the layering fixtures are missing");
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
  ["no-restricted-syntax", 'export const x = await import("node:" + "fs");'],
  ["no-restricted-globals", "export const x = Date.now();"],
  ["no-restricted-globals", "export const x = new Date();"],
  ["no-restricted-globals", "const Clock = Date;\nexport const x = new Clock();"],
  ["no-restricted-globals", "export const x = new Date(...[]);"],
  ["no-restricted-globals", "export const x = globalThis.Date.now();"],
  ["no-restricted-globals", "export const x = Reflect.construct(Date, []);"],
  ["no-restricted-globals", 'export const x = Reflect.get(globalThis, "process");'],
  ["no-restricted-globals", "export const x = new Intl.DateTimeFormat().format();"],
  ["no-restricted-globals", "export const x = performance.now();"],
  ["no-restricted-globals", "export const x = process.env;"],
  ["no-restricted-globals", 'export const x = fetch("https://example.com");'],
  ["no-restricted-globals", "export const x = crypto.getRandomValues(new Uint8Array(8));"],
  ["no-restricted-globals", "export const x = setTimeout(() => undefined, 0);"],
  ["no-restricted-properties", "export const x = Math.random();"],
  ["no-restricted-properties", "const { random } = Math;\nexport const x = random();"],
  ["no-restricted-syntax", 'export const x = "a".localeCompare("b");'],
  ["no-eval", 'export const x = eval("1");'],
  ["no-restricted-globals", 'export const x = new Function("return 1")();'],
  ["no-console", 'console.log("x");\nexport {};'],
  ["@typescript-eslint/no-explicit-any", "export const x = (value: any) => value;"],
  // A comment must not switch a rule off.
  [
    "no-restricted-globals",
    "// eslint-disable-next-line no-restricted-globals\nexport const x = Date.now();",
  ],
  ["no-restricted-globals", "/* eslint-disable */\nexport const x = Date.now();"],
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

// --- Nothing escapes the lists ---------------------------------------------------

const { LAYERS, PURE, TEST_ONLY } = createRequire(import.meta.url)("./layers.cjs") as {
  LAYERS: string[][];
  PURE: string[];
  TEST_ONLY: string[];
};
const listed = new Set([...LAYERS.flat(), ...TEST_ONLY]);
for (const entry of readdirSync(join(repoRoot, "packages"), { withFileTypes: true })) {
  if (entry.isDirectory() && !listed.has(entry.name)) {
    problems.push(
      `packages/${entry.name} is not in scripts/layers.cjs, so no layering rule binds it`,
    );
  }
}
for (const name of PURE) {
  if (!LAYERS.flat().includes(name)) problems.push(`the pure package ${name} has no layer`);
}

// The purity rules apply to every kind of TypeScript source file in a pure package.
for (const extension of ["ts", "mts", "cts", "tsx"]) {
  const config = (await eslint.calculateConfigForFile(
    join(repoRoot, "packages", "schema", "src", `probe.${extension}`),
  )) as { rules?: Record<string, unknown> } | undefined;
  if (config?.rules?.["no-restricted-globals"] === undefined) {
    problems.push(`the purity rules do not apply to .${extension} files`);
  }
}

// `pnpm lint` cruises every workspace directory that exists.
const lint =
  (
    JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    }
  ).scripts["lint"] ?? "";
const cruised = /depcruise ([^&]*?) --config/.exec(lint)?.[1]?.split(" ") ?? [];
for (const workspace of ["packages", "apps", "examples", "scripts"]) {
  if (existsSync(join(repoRoot, workspace)) && !cruised.includes(workspace)) {
    problems.push(`pnpm lint does not run dependency-cruiser over ${workspace}/`);
  }
}

if (problems.length > 0) {
  console.error(`The guards have gaps:\n${problems.map((problem) => `  - ${problem}`).join("\n")}`);
  process.exit(1);
}
console.log(
  `Guards hold: ${expected.size} layering fixtures and ${impure.length} purity probes rejected.`,
);
