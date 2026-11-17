// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { MAX_VALUES } from "@oip/schema";
import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { example } from "../examples/sign-and-verify.ts";
import * as core from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "core");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

/** The two test keys the README's output was made with. They are public: never use them. */
const keys = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)] as const;

describe("the README", () => {
  it("shows examples/sign-and-verify.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "sign-and-verify.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", async () => {
    const output = await example(...keys);
    expect(output).toHaveLength(3);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("reports what is wrong with a record it cannot read, instead of an address", async () => {
    // A control key that is not 32 bytes is the caller's mistake, and is not caught.
    await expect(example(new Uint8Array(31), keys[1])).rejects.toThrow(TypeError);
  });

  it("names only things the package exports", () => {
    const table = readme.slice(readme.indexOf("## What it exports"), readme.indexOf("## Results"));
    // The first column of each row names exports; the second describes them.
    const firstColumns = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .map((line) => line.split("|")[1] ?? "");
    const names = firstColumns.flatMap((cell) =>
      [...cell.matchAll(/`([A-Za-z0-9_]+)(?:\([^`]*\))?`/g)].map((match) => match[1]),
    );
    expect(names.length).toBeGreaterThan(60);
    const typesOnly = ["Signer", "SyncSigner", "Instant"];
    for (const name of names) {
      if (name === undefined || typesOnly.includes(name)) continue;
      expect(Object.hasOwn(core, name), name).toBe(true);
    }
  });

  it("gives the limits the code has", () => {
    // The table is laid out by the formatter, so cells are matched without their padding.
    const row = (...cells: string[]) =>
      new RegExp(
        `\\| ${cells.map((cell) => cell.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s+\\| ")}`,
      );
    expect(readme).toMatch(row("Proofs on a record", "256"));
    expect(core.MAX_PROOFS).toBe(256);
    expect(readme).toMatch(row("Nesting of arrays and objects", "64"));
    expect(readme).toMatch(row("Text parsed in one call", "8 MiB by default"));
    expect(core.MAX_TEXT_LENGTH).toBe(8 * 1024 * 1024);
    expect(readme).toMatch(row("Order checks of public keys remembered", "4,096"));
    expect(core.ORDER_CHECK_CACHE_SIZE).toBe(4096);
    expect(readme).toMatch(row("Canonical form of a record", "1 MiB"));
    expect(core.MAX_RECORD_BYTES).toBe(1024 * 1024);
    expect(readme).toMatch(row("A `Sealed` record", "`ciphertext` of 1,398,123 characters"));
    expect(core.MAX_SEALED_CIPHERTEXT_LENGTH).toBe(1_398_123);
    expect(readme).toMatch(row("A duration", "64 characters"));
    expect(core.MAX_DURATION_LENGTH).toBe(64);
    expect(readme).toMatch(row("A decimal", "64 characters"));
    expect(core.MAX_DECIMAL_LENGTH).toBe(64);
    expect(readme).toMatch(row("Values in one value that did not come from text", "4,194,304"));
    expect(MAX_VALUES).toBe(4_194_304);
  });
});
