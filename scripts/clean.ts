// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Removes build output: every package's `dist`, and the coverage and API documentation directories. */

import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "./lib/spec.ts";

const targets = [join(repoRoot, "coverage"), join(repoRoot, "docs", "api")];
for (const workspace of ["packages", "apps", "examples"]) {
  for (const entry of readdirSync(join(repoRoot, workspace), { withFileTypes: true })) {
    if (entry.isDirectory()) targets.push(join(repoRoot, workspace, entry.name, "dist"));
  }
}
for (const target of targets) rmSync(target, { recursive: true, force: true });
console.log(`Removed ${targets.length} build directories.`);
