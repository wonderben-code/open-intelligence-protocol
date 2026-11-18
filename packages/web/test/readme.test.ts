// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import * as web from "../src/index.ts";

const readme = readFileSync(join(repoRoot, "packages", "web", "README.md"), "utf8");

describe("the README", () => {
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
      (match) => (match[1] ?? "").split(",").map((name) => name.trim()),
    );
    expect(imported.length).toBeGreaterThan(2);
    for (const name of imported) expect(Object.keys(web), name).toContain(name);
  });
});
