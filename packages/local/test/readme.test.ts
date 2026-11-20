// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import * as local from "../src/index.ts";

const readme = readFileSync(join(repoRoot, "packages", "local", "README.md"), "utf8");

describe("the README", () => {
  it("names only things the package exports, and every one of them", () => {
    const [, after = ""] = readme.split("\n## What it exports\n");
    const [section = ""] = after.split("\n## ");
    const named = section
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => {
        const [, names = ""] = line.split("|");
        return [...names.matchAll(/`([A-Za-z_]+)`/gu)].map(([, name = ""]) => name);
      });
    const values = Object.keys(local);
    for (const value of values) expect(named, value).toContain(value);
    // What is named besides is a type, which leaves nothing in the module to see.
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      ["Config", "KeptPacket", "KeptRecord", "Machine", "NetworkFile", "Opened", "Where"].sort(),
    );
    expect(new Set(named).size).toBe(named.length);
  });

  it("shows an example that uses what the package has", () => {
    const [, example = ""] = /```ts\n([\s\S]*?)\n```/u.exec(readme) ?? [];
    const [, imported = ""] = /import \{([^}]*)\} from "@oip\/local";/u.exec(example) ?? [];
    const names = imported.split(",").map((name) => name.trim().replace(/^type /u, ""));
    expect(names).toStrictEqual(["directoryOf", "Machine", "withMind"]);
    expect(typeof local.directoryOf).toBe("function");
    expect(typeof local.withMind).toBe("function");
    // The variables it says the package reads are the ones it reads.
    expect(readme).toContain("`OIP_PASSPHRASE`");
    expect(readme).toContain("`OIP_DIR`");
  });
});
