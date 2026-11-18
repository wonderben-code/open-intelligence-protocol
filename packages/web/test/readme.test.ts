// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { example } from "../examples/deal.ts";
import * as web from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "web");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

/** The six test keys the README's output was made with. They are public: never use them. */
const keys = [1, 2, 3, 4, 5, 6].map((byte) => new Uint8Array(32).fill(byte));

describe("the README", () => {
  it("shows examples/deal.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "deal.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", () => {
    const output = example(keys);
    expect(output).toHaveLength(5);
    expect(output[1]).toContain("the Commitment is proposed");
    expect(output[2]).toContain("the Intent is satisfied, the Commitment is accepted");
    expect(output[3]).toContain("the Commitment is fulfilled");
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
    expect(() => example(keys.slice(0, 5))).toThrow(TypeError);
  });

  it("names only things the package exports, and every function it exports", () => {
    const table = readme.slice(
      readme.indexOf("## What it exports"),
      readme.indexOf("## Signing for a party"),
    );
    // The first column of each row names exports; the second describes them.
    const named = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => [...(line.split("|")[1] ?? "").matchAll(/`([A-Za-z_]+)/g)])
      .map((match) => match[1] ?? "");
    expect(named.length).toBeGreaterThan(15);
    // Types are not there at run time; everything else named must be.
    const values = Object.keys(web);
    const types = named.filter((name) => !values.includes(name));
    expect(types.sort()).toEqual([
      "CharterStatus",
      "CommitmentStatus",
      "IntentStatus",
      "OfferStatus",
      "Status",
      "WebContext",
      "WebRecords",
    ]);
    expect(values.filter((name) => !named.includes(name))).toEqual([]);
  });

  it("uses in its example only what the packages it names export", () => {
    const example = /```ts\n([\s\S]*?)```/.exec(readme)?.[1] ?? "";
    const imported = [...example.matchAll(/import \{([^}]*)\} from "@oip\/web";/g)].flatMap(
      (match) =>
        (match[1] ?? "")
          .split(",")
          .map((name) => name.trim())
          .filter((name) => name !== ""),
    );
    expect(imported.length).toBeGreaterThan(2);
    for (const name of imported) expect(Object.keys(web), name).toContain(name);
  });
});
