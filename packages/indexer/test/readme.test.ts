// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { at, KeyMind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { example } from "../examples/find.ts";
import * as indexer from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "indexer");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/find.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "find.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", async () => {
    const [ian, ada, bob] = [new KeyMind("ian"), new KeyMind("ada"), new KeyMind("bob")];
    const bundle = (mind: KeyMind) => ({
      oip: "1",
      type: "Bundle",
      mind: mind.address,
      log: mind.events,
    });
    const profile = (mind: KeyMind, name: string, capabilities: Record<string, string>) =>
      mind.sign({
        oip: "1",
        type: "Participant",
        author: mind.address,
        created: T(100),
        name,
        kind: "agent",
        capabilities: Object.entries(capabilities).map(([id, summary]) => ({ id, summary })),
      });
    const output = await example(
      { address: ian.address, bundle: bundle(ian), signer: ian.operational() },
      [
        bundle(ada),
        profile(ada, "Ada", {
          translate: "Translates leases from Dutch to English",
          review: "Reviews contracts for small firms",
        }),
        bundle(bob),
        profile(bob, "Bob", { bake: "Bakes sourdough bread to order" }),
        // A profile nobody signed for the mind it describes.
        profile(ada, "Not Bob", { bake: "Bakes" }),
      ].map((record, index) => (index === 4 ? { ...record, author: bob.address } : record)),
      { want: "Who translates a lease, or reviews contracts?" },
      { now: () => at(120) },
    );
    expect(output).toStrictEqual([
      "submitted: 202, 4 taken, 1 refused",
      "answered: 200, by the indexer: true, with a proof that verifies: true",
      // `reviews` and `contracts` are two of the query's words; `translates` is one.
      "1. review, score 1",
      "2. translate, score 0.5",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("names every setting, with the default the code has", () => {
    for (const [name, setting] of Object.entries(indexer.SETTINGS)) {
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
    expect(new Set(named).size).toBe(named.length);
    const values = Object.keys(indexer);
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "BrokerOptions",
        "Edges",
        "Forwarding",
        "Found",
        "IndexerAppOptions",
        "IndexerLimits",
        "IndexerOptions",
        "Item",
        "Kind",
        "Running",
        "Search",
        "Submission",
      ].sort(),
    );
  });
});
