// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the MCP Registry is told of the server (`server.json`), held to the
 * package: the Registry checks that the two agree before it lists one.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { VERSION } from "../src/index.ts";

const directory = join(repoRoot, "packages", "mcp-server");
const read = (name: string): unknown => JSON.parse(readFileSync(join(directory, name), "utf8"));

const manifest = read("package.json") as {
  name: string;
  version: string;
  mcpName: string;
  files: string[];
  repository: { url: string; directory: string };
};
const listing = read("server.json") as {
  $schema: string;
  name: string;
  title: string;
  description: string;
  version: string;
  repository: { url: string; source: string; subfolder: string };
  packages: {
    registryType: string;
    identifier: string;
    version: string;
    transport: { type: string };
    environmentVariables: { name: string; isRequired: boolean; isSecret: boolean }[];
  }[];
};

describe("what the MCP Registry is told", () => {
  it("names the server as the package names itself: that is how the Registry knows whose it is", () => {
    expect(listing.name).toBe(manifest.mcpName);
    expect(listing.name).toMatch(/^io\.github\.[a-zA-Z0-9-]+\/[a-zA-Z0-9._-]+$/u);
    // The namespace is the owner of the repository the package says it comes from.
    const [, owner = ""] = /github\.com\/([^/]+)\//u.exec(manifest.repository.url) ?? [];
    expect(listing.name.startsWith(`io.github.${owner}/`)).toBe(true);
    expect(manifest.files).toContain("server.json");
  });

  it("names one package, of the version the program says it is, over standard input and output", () => {
    expect(listing.packages).toHaveLength(1);
    const [listed] = listing.packages;
    expect(listed).toMatchObject({
      registryType: "npm",
      identifier: manifest.name,
      version: manifest.version,
      transport: { type: "stdio" },
    });
    expect(listing.version).toBe(manifest.version);
    expect(listing.version).toBe(VERSION);
  });

  it("says where the source is, and keeps to the Registry's lengths", () => {
    expect(manifest.repository.url).toBe(`git+${listing.repository.url}.git`);
    expect(listing.repository).toMatchObject({
      source: "github",
      subfolder: manifest.repository.directory,
    });
    expect(listing.description.length).toBeLessThanOrEqual(100);
    expect(listing.title.length).toBeLessThanOrEqual(100);
    expect(listing.$schema).toMatch(
      /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/[0-9-]+\/server\.schema\.json$/u,
    );
  });

  it("names the variables the program reads, asks for none, and marks the passphrase a secret", () => {
    expect(listing.packages[0]?.environmentVariables).toMatchObject([
      { name: "OIP_DIR", isRequired: false, isSecret: false },
      { name: "OIP_PASSPHRASE", isRequired: false, isSecret: true },
    ]);
  });
});
