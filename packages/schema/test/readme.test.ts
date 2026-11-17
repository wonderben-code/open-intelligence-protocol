// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { describeRecord } from "../examples/validate.ts";
import { samples } from "./fixtures.ts";

const packageRoot = join(repoRoot, "packages", "schema");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/validate.ts unchanged", () => {
    const example = readFileSync(join(packageRoot, "examples", "validate.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = example.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", () => {
    expect(describeRecord(JSON.stringify(samples.Intent))).toMatch(/^a well-formed Intent: /);
    expect(describeRecord(JSON.stringify(samples.Checkpoint))).toBe("a well-formed Checkpoint");
    const toSelf = { ...samples.Delegation, delegate: samples.Delegation["author"] };
    const output = describeRecord(JSON.stringify(toSelf));
    expect(output).toBe("L1 11.1 /delegate: a delegation's delegate must differ from its author");
    expect(readme).toContain(`\`\`\`\n${output}\n\`\`\``);
  });
});
