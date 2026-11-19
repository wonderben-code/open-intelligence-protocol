// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { formatKeyRef } from "@oip/core";
import { repoRoot } from "@oip/testkit";
import { KeyMind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { example } from "../examples/mailbox.ts";
import * as host from "../src/index.ts";

const packageRoot = join(repoRoot, "packages", "host");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/mailbox.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "mailbox.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives", async () => {
    const [ada, bob] = [new KeyMind("ada"), new KeyMind("bob")];
    // Two minutes after the minds were made.
    const clock = { at: 1_767_225_720_000_000_000n, now: () => clock.at };
    const bundle = (mind: KeyMind) => ({
      oip: "1",
      type: "Bundle",
      mind: mind.address,
      log: mind.events,
    });
    const packet = ada.sign({
      oip: "1",
      type: "Packet",
      from: ada.address,
      to: [bob.address],
      created: T(100),
      expires: T(3700),
      nonce: "nonce-0001",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "Hello." },
    });
    const output = await example(
      {
        address: bob.address,
        keyRef: formatKeyRef(bob.address, bob.versionId(), bob.operational().publicKey),
        signer: bob.operational(),
      },
      bundle(bob),
      bundle(ada),
      packet,
      clock,
    );
    expect(output).toStrictEqual([
      "the mind brings its bundle at 2026-01-01T00:02:00Z: 201",
      'the packet is delivered, first: 202 {"stored":true}',
      'the packet is delivered, again: 202 {"stored":true}',
      "anyone asks for the mind's mail: 401",
      "the mind drains its mailbox: 1 item, the packet: true",
      "the mind removes it: 204",
      "left in the mailbox: 0",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("names every setting, with the default the code has", () => {
    for (const [name, setting] of Object.entries(host.SETTINGS)) {
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
    const values = Object.keys(host);
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Answer",
        "Connection",
        "Edges",
        "HostAppOptions",
        "HostLimits",
        "HostOptions",
        "MailboxItem",
        "Running",
        "SocketsOptions",
        "UpgradeOptions",
        "Wire",
      ].sort(),
    );
  });
});
