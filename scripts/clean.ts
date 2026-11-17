// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Removes build output: every package's `dist` and `temp`, and the coverage
 * and API documentation directories.
 */

import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "./lib/spec.ts";

const targets = [join(repoRoot, "coverage"), join(repoRoot, "docs", "api")];
for (const workspace of ["packages", "apps", "examples"]) {
  const directory = join(repoRoot, workspace);
  // apps/ and examples/ appear with the milestones that fill them.
  if (!existsSync(directory)) continue;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    for (const output of ["dist", "temp"]) {
      targets.push(join(repoRoot, workspace, entry.name, output));
    }
  }
}
for (const target of targets) rmSync(target, { recursive: true, force: true });
console.log(`Removed ${targets.length} build directories.`);
