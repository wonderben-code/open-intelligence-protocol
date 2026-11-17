// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { report } from "../examples/run-vectors.ts";
import { referenceAdapter } from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "conformance");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/run-vectors.ts unchanged", () => {
    const example = readFileSync(join(packageRoot, "examples", "run-vectors.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = example.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", () => {
    const output = report(() => true);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("reports no failure for the reference implementation", () => {
    const output = report((record) => referenceAdapter.recordIsWellFormed?.(record) === true);
    expect(output).toHaveLength(1);
    expect(output[0]).toMatch(/^my implementation: 33 passed, 0 failed, \d+ pending$/);
  });
});
