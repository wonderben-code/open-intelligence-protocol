// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { KeyMind } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { example } from "../examples/witness.ts";
import * as resolver from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "resolver");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/witness.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "witness.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", async () => {
    const first = new KeyMind("ada").update(10);
    const other = new KeyMind("ada").update(11);
    // Noon on 18 November 2026.
    const clock = { at: 1_795_003_200_000_000_000n, now: () => clock.at };
    const output = await example(first.address, [first.events, other.events], clock);
    expect(output).toStrictEqual([
      "published at 2026-11-18T12:00:00Z: 202 added 2",
      "published at 2026-11-18T13:00:00Z: 409 urn:oip:error:duplicity",
      "serves 2 events, the second of them the one it saw first: true",
      "first seen: 2026-11-18T12:00:00Z, 2026-11-18T12:00:00Z",
      "pairs of conflicting events held as evidence: 1",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("names every setting, with the default the code has", () => {
    for (const [name, setting] of Object.entries(resolver.SETTINGS)) {
      expect(readme, name).toContain(`\`${name}\``);
      const fallback = (setting as { fallback?: unknown }).fallback;
      if (typeof fallback === "number" || typeof fallback === "boolean") {
        expect(readme, name).toContain(`\`${String(fallback)}\``);
      }
    }
  });

  it("names only things the package exports, and every value it exports", () => {
    const table = readme.slice(
      readme.indexOf("## What it exports"),
      readme.indexOf("## What to know"),
    );
    const named = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => [...(line.split("|")[1] ?? "").matchAll(/`([A-Za-z_0-9]+)`/g)])
      .map((match) => match[1] ?? "");
    const values = Object.keys(resolver);
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      ["Arrival", "Arrived", "ResolverAppOptions", "Running"].sort(),
    );
  });
});
