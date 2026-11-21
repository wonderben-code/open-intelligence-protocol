// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { example } from "../examples/agent-limit.ts";
import * as delegation from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "delegation");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

/** The four test keys the README's output was made with. They are public: never use them. */
const keys = [1, 2, 3, 4].map((byte) => new Uint8Array(32).fill(byte)) as [
  Uint8Array,
  Uint8Array,
  Uint8Array,
  Uint8Array,
];

describe("the README", () => {
  it("shows examples/agent-limit.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "agent-limit.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", () => {
    const output = example(keys);
    expect(output).toHaveLength(3);
    expect(output[0]).toContain("counts from 2026-11-18T10:00:01Z");
    expect(output[1]).toContain("does not count");
    expect(output[2]).toContain("does not count");
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("names only things the package exports, and every function it exports", () => {
    const table = readme.slice(readme.indexOf("## What it exports"), readme.indexOf("## Chains"));
    // The first column of each row names exports; the second describes them.
    const named = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => [...(line.split("|")[1] ?? "").matchAll(/`([A-Za-z_]+)/g)])
      .map((match) => match[1] ?? "");
    expect(named.length).toBeGreaterThan(20);
    // Types are not there at run time; everything else named must be.
    const values = Object.keys(delegation);
    const types = named.filter((name) => !values.includes(name));
    expect(types.sort()).toEqual([
      "DelegableType",
      "DelegatedOptions",
      "DelegationContext",
      "DelegationFields",
      "RecordView",
      "SubDelegationFields",
    ]);
    expect(values.filter((name) => !named.includes(name))).toEqual([]);
  });

  it("uses in its example only what the package exports", () => {
    const example = /```ts\n([\s\S]*?)```/.exec(readme)?.[1] ?? "";
    const imported = [...example.matchAll(/import \{([^}]*)\} from "@oip\/delegation";/g)].flatMap(
      (match) =>
        (match[1] ?? "")
          .split(",")
          .map((name) => name.trim())
          .filter((name) => name !== ""),
    );
    expect(imported.length).toBeGreaterThan(2);
    for (const name of imported) expect(Object.keys(delegation), name).toContain(name);
  });
});
