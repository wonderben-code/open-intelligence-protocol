// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type Keychain, keychainLock } from "@oip/keystore";
import { repoRoot } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { example } from "../examples/first-mind.ts";
import * as client from "../src/index.ts";
import { World } from "./world.ts";

const packageRoot = join(repoRoot, "packages", "client");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

let world: World;
beforeEach(() => {
  world = new World(100);
});
afterEach(() => {
  world.close();
});

function memoryKeychain(): Keychain {
  const kept = new Map<string, string>();
  return {
    get: (service, account) => Promise.resolve(kept.get(`${service}\n${account}`)),
    set: (service, account, secret) => {
      kept.set(`${service}\n${account}`, secret);
      return Promise.resolve();
    },
    delete: (service, account) => {
      kept.delete(`${service}\n${account}`);
      return Promise.resolve();
    },
  };
}

describe("the README", () => {
  it("shows examples/first-mind.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "first-mind.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives, against two resolvers", async () => {
    const resolvers = ["https://resolver-one.example", "https://resolver-two.example"];
    for (const resolver of resolvers) world.resolver(resolver);
    const output = await example(resolvers, keychainLock(memoryKeychain(), "example"), {
      fetch: world.fetch,
      clock: world.clock,
    });
    expect(output).toStrictEqual([
      "a mind is made, and 2 resolvers have its genesis",
      "it signs an Intent with 1 proof",
      "another client verifies its log: 1 event",
      "after an update it is at event 1, at https://new-home.example",
      "a backup is due for: control, operational, invocation, agreement",
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
    expect(new Set(named).size).toBe(named.length);
    const values = Object.keys(client);
    expect(values.length).toBeGreaterThan(10);
    // Every value the package exports is named, and what is named besides is a type.
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Answer",
        "Asking",
        "Clock",
        "ControlOptions",
        "Fetch",
        "IdentityChanges",
        "KeyEntry",
        "LookupOptions",
        "MindOptions",
        "NewMind",
        "Publication",
        "Resolved",
        "ResolverAnswer",
        "TransportFailure",
        "TransportOptions",
      ].sort(),
    );
  });

  it("gives the bounds the code has", () => {
    expect(readme).toContain("8 MiB and 10 seconds");
    expect([client.DEFAULT_MAX_BYTES, client.DEFAULT_TIMEOUT_MS]).toStrictEqual([
      8 * 2 ** 20,
      10_000,
    ]);
    expect(readme).toContain("cut to 256 printable characters");
    expect(client.MAX_DETAIL_LENGTH).toBe(256);
    expect(readme).toContain("64 logs at most for one mind");
    expect(client.DEFAULT_MAX_LOGS).toBe(64);
  });
});
