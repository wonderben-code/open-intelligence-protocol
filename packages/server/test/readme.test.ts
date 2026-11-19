// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { intentBy, KeyMind } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { example } from "../examples/endpoint.ts";
import * as server from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "server");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/endpoint.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "endpoint.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", async () => {
    const ada = new KeyMind("ada");
    // Noon on 18 November 2026.
    const clock = { at: 1_795_003_200_000_000_000n, now: () => clock.at };
    const output = await example(ada.sign(intentBy(ada, 10)), clock);
    expect(output).toStrictEqual([
      "202 2026-11-18T12:00:00Z",
      "202 2026-11-18T12:00:00Z",
      "400 urn:oip:error:invalid-record",
      "202 2026-11-18T12:00:00Z",
      "429 urn:oip:error:rate-limited",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
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
    expect(named.length).toBeGreaterThan(60);
    expect(new Set(named).size).toBe(named.length);
    const values = Object.keys(server);
    // Every value the package exports is named, and what is named besides is a type.
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Address",
        "Allowance",
        "ArchiveOptions",
        "Arrival",
        "Arrived",
        "Asked",
        "Authentication",
        "Clock",
        "ConfigOf",
        "Counter",
        "DatabaseOptions",
        "FetchLimits",
        "FetchRefusal",
        "Fetched",
        "FieldValue",
        "Fields",
        "GateOptions",
        "Gauge",
        "Handler",
        "Held",
        "GuardedFetcherOptions",
        "Histogram",
        "Labels",
        "Level",
        "LogOptions",
        "Migration",
        "NotTaken",
        "OtherRecord",
        "Pair",
        "Published",
        "Randomness",
        "RateLimit",
        "Resolve",
        "Resolved",
        "SQLInputValue",
        "Setting",
        "Settings",
        "Sighting",
        "ShutdownOptions",
        "StatementSync",
        "Stop",
        "StopSignal",
        "Streamed",
        "Taken",
      ].sort(),
    );
  });
});
