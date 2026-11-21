// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The README says what is so: its tables name what there is, and its numbers are the program's. */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { MAX_LISTED, MAX_PAGES } from "../src/connect.ts";
import * as bridge from "../src/index.ts";
import { PASS_MS, SIDE_BY_SIDE } from "../src/main.ts";

const directory = join(repoRoot, "packages", "bridge-mcp");
const readme = readFileSync(join(directory, "README.md"), "utf8");
const manifest = JSON.parse(readFileSync(join(directory, "package.json"), "utf8")) as {
  bin: Record<string, string>;
};

/** The rows of the table under a heading, each as its cells. */
function table(heading: string): string[][] {
  const [, rest = ""] = readme.split(`\n${heading}\n`);
  const [section = ""] = rest.split("\n## ");
  return section
    .split("\n")
    .filter((line) => line.startsWith("| ") && !line.startsWith("| -"))
    .slice(1)
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
}

describe("the README", () => {
  it("says what the program takes, as the program's own help does", async () => {
    expect(manifest.bin).toStrictEqual({ "oip-bridge-mcp": "./dist/bin.js" });
    const written = { out: "" };
    const code = await bridge.main(["--help"], {
      env: {},
      stdout: { write: (text) => (written.out += text) },
      stderr: { write: () => undefined },
      once: () => undefined,
    });
    expect(code).toBe(0);
    const rows = table("### What the program takes");
    const settings = rows.map(([name = ""]) => name.replace(/`/gu, ""));
    expect(settings).toStrictEqual([
      "bridge <url>",
      "bridge --stdio <label>",
      "servers",
      "serve",
      "--dir <path>",
      "--name <name>",
      "--credentials <file>",
      "--every <seconds>",
      "OIP_PASSPHRASE",
      "OIP_BRIDGE_FETCH_ALLOW",
      "--help",
      "--version",
    ]);
    for (const setting of settings) expect(written.out, setting).toContain(setting);
    // A default the README gives is the one the help gives.
    for (const [name = "", says = ""] of rows) {
      const [, given] = /Default: (`?[^`\s,]+`?)/u.exec(says) ?? [];
      if (given === undefined || name.includes("--name")) continue;
      // The line of the help that describes the setting begins with it.
      const line = written.out
        .split("\n")
        .find((one) => one.trimStart().startsWith(name.replace(/`/gu, "")));
      expect(line, name).toContain(`Default: ${given.replace(/`/gu, "")}`);
    }
    for (const command of [
      "bridge https://tools.example/mcp",
      "bridge --stdio files -- npx a-files-server /srv/files",
      "servers",
      "serve",
    ]) {
      expect(readme).toContain(`oip-bridge-mcp ${command}\n`);
    }
  });

  it("gives the limits the program has", () => {
    const limits = Object.fromEntries(
      table("## Limits").map(([what = "", value = ""]) => [what, Number(value)]),
    );
    expect(limits).toStrictEqual({
      "Capabilities of one profile": bridge.MAX_CAPABILITIES,
      "Characters of a tool's name": bridge.MAX_NAME,
      "Characters of a capability's summary": bridge.MAX_SUMMARY,
      "Bytes of one input schema": bridge.MAX_SCHEMA_BYTES,
      "Bytes of all the schemas of a profile": bridge.MAX_SCHEMAS_BYTES,
      "Bytes of all a server wrote, in a profile": bridge.MAX_CAPABILITIES_BYTES,
      "Pages of a list of tools": MAX_PAGES,
      "Tools of a list that are looked at": MAX_LISTED,
      "Bytes of a result a packet carries": bridge.MAX_RESULT_BYTES,
      "Depth of JSON text in a request": 64,
      "References of a request that are looked at": bridge.MAX_REFS,
      "Seconds a request with no `expires` waits": bridge.MAX_WAITING_SECONDS,
      "Seconds one pass for one server takes, under `serve`": PASS_MS / 1000,
      "Servers relayed for side by side, under `serve`": SIDE_BY_SIDE,
    });
    expect(readme).toContain(
      `takes ${String(bridge.MAX_CAPABILITIES_BYTES / 1024)} KiB of a profile`,
    );
    expect(readme).toContain(
      `for ${String(MAX_PAGES)} pages and ${MAX_LISTED.toLocaleString("en-GB")} tools at most`,
    );
    expect(readme).toContain("the first eight entries of `context.refs`");
    expect(bridge.MAX_REFS).toBe(8);
    expect(readme).toContain(`\`${bridge.WITHHELD}\``);
    expect(readme).toContain(`(\`${bridge.RELAY_HOLD_FILE}\`)`);
    expect(readme).toContain(`(\`${bridge.HOLD_FILE}\`)`);
    expect(readme).toContain(`\`${bridge.ALLOW_VARIABLE}\``);
    // The same numbers, where the text gives them in other units.
    expect(readme).toContain(`larger than ${String(bridge.MAX_SCHEMA_BYTES / 1024)} KiB`);
    expect(readme).toContain(`fill ${String(bridge.MAX_SCHEMAS_BYTES / 1024)} KiB`);
    expect(readme).toContain(`larger than ${String(bridge.MAX_RESULT_BYTES / 1024)} KiB`);
    expect(readme).toContain(`longer than ${String(bridge.MAX_NAME)} characters`);
    expect(readme).toContain(`${String(bridge.MAX_CAPABILITIES)} capabilities at most`);
  });

  it("names the files and the words of a policy as the program has them", () => {
    expect(readme).toContain(`\`${bridge.POLICY_FILE}\``);
    expect(readme).toContain(`\`${bridge.CREDENTIALS_FILE}\``);
    expect(readme).toContain(`"${bridge.ANYONE}"`);
    expect(readme).toContain(`\`${bridge.EVERY_TOOL}\``);
    expect(readme).toContain(`ext["${bridge.MCP_NAMESPACE}"].inputSchema`);
    expect(readme).toContain(`(\`${bridge.PROTOCOL}\`)`);
    // Each example of JSON is JSON, and each call the README shows is a call as the gateway
    // reads one.
    const examples = [...readme.matchAll(/```json\n([\s\S]*?)\n```/gu)].map(
      ([, text = ""]) => JSON.parse(text) as Record<string, unknown>,
    );
    expect(examples).toHaveLength(4);
    // The credentials the README shows are credentials as the gateway reads them.
    expect(Object.keys(examples.find((example) => "headers" in example) ?? {})).toStrictEqual([
      "headers",
      "query",
    ]);
    const shown = examples.filter((example) => "mediaType" in example);
    expect(shown.map((content) => bridge.readCall(content))).toStrictEqual([
      { tool: "search", args: { query: "leases" } },
      { tool: "scale", args: { by: 0.25 } },
    ]);
  });

  it("names only things the package exports, and every one of them", () => {
    const named = table("## What it exports").flatMap(([names = ""]) =>
      [...names.matchAll(/`([^`]+)`/gu)].map(([, name = ""]) => name),
    );
    const values = Object.keys(bridge);
    for (const value of values) expect(named, value).toContain(value);
    // What is named besides is a type, which leaves nothing in the module to see.
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Bridged",
        "BridgedNow",
        "Connect",
        "Credentials",
        "GatewayEdges",
        "Host",
        "Mapped",
        "Policy",
        "Reach",
        "Relayed",
        "RelayEdges",
        "Server",
        "Serving",
        "Target",
        "ToolCapability",
      ].sort(),
    );
    expect(new Set(named).size).toBe(named.length);
  });
});
