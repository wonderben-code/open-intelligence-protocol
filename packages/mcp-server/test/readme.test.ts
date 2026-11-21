// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The README says what is so: its snippets work, its tables name what there is, and its policy does what it says. */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import * as server from "../src/index.ts";
import { permits, POLICY_FILE, readPolicy, TOOLS } from "../src/index.ts";

const directory = join(repoRoot, "packages", "mcp-server");
const readme = readFileSync(join(directory, "README.md"), "utf8");
const manifest = JSON.parse(readFileSync(join(directory, "package.json"), "utf8")) as {
  bin: Record<string, string>;
};

/** The code block that follows a marker, as `<!-- host: other -->`. */
function after(marker: string, language: string): string {
  const [, rest = ""] = readme.split(`<!-- ${marker} -->`);
  const [, block = ""] =
    new RegExp(`\`\`\`${language}\\n([\\s\\S]*?)\\n\`\`\``, "u").exec(rest) ?? [];
  return block;
}

/** The rows of the table under a heading, each as its cells. */
function table(heading: string): string[][] {
  const [, rest = ""] = readme.split(`\n${heading}\n`);
  const [section = ""] = rest.split("\n## ");
  return section
    .split("\n")
    .filter((line) => line.startsWith("| `"))
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
}

describe("the README", () => {
  it("configures a host with a command that is the program, and options the program has", () => {
    const program = manifest.bin["oip-mcp"]?.replace(/^\.\//u, "");
    expect(program).toBe("dist/bin.js");
    for (const marker of ["host: claude-desktop", "host: other"]) {
      const { mcpServers } = JSON.parse(after(marker, "json")) as {
        mcpServers: Record<
          string,
          { command: string; args: string[]; env?: Record<string, string> }
        >;
      };
      expect(Object.keys(mcpServers)).toStrictEqual(["oip"]);
      const { command, args, env = {} } = mcpServers["oip"] ?? { command: "", args: [] };
      expect(command).toBe("node");
      const [path = "", ...options] = args;
      expect(path.endsWith(`/packages/mcp-server/${String(program)}`)).toBe(true);
      // What follows the program is `--dir` and a directory, or nothing.
      expect(options.length === 0 || (options.length === 2 && options[0] === "--dir")).toBe(true);
      for (const name of Object.keys(env)) expect(["OIP_DIR", "OIP_PASSPHRASE"]).toContain(name);
    }
    expect(readme).toContain(
      "claude mcp add oip -- node /path/to/open-intelligence-protocol/packages/mcp-server/dist/bin.js",
    );
  });

  it("says what the program takes, as the program's own help does", () => {
    const written = { out: "" };
    server.main(
      ["--help"],
      {
        env: {},
        stdout: { write: (text) => (written.out += text) },
        stderr: { write: () => undefined },
        once: () => undefined,
      },
      () => ({ close: () => Promise.resolve() }),
    );
    const settings = table("### What the program takes").map(([name = ""]) =>
      name.replace(/`/gu, "").replace(" <path>", ""),
    );
    expect(settings).toStrictEqual(["--dir", "OIP_DIR", "OIP_PASSPHRASE", "--help", "--version"]);
    for (const setting of settings) expect(written.out).toContain(setting);
  });

  it("lists the nine tools in the order a host is given them, and says which ask the person", () => {
    const rows = table("## The tools");
    expect(rows.map(([name = ""]) => name.replace(/`/gu, ""))).toStrictEqual(
      TOOLS.map(({ name }) => name),
    );
    for (const [name = "", , asks = ""] of rows) {
      const tool = TOOLS.find((one) => `\`${one.name}\`` === name);
      const confirmed = tool?.name === "oip_commit" || tool?.name === "oip_receipt";
      expect(asks.startsWith("yes"), name).toBe(confirmed);
      // What is asked about is said to be in the tool's own description too.
      expect((tool?.description ?? "").includes("asks them to confirm"), name).toBe(confirmed);
    }
  });

  it("shows a policy that is one, and that permits what it is said to", () => {
    const dir = mkdtempSync(join(tmpdir(), "oip-mcp-readme-"));
    try {
      writeFileSync(join(dir, POLICY_FILE), after("policy", "json"));
      const policy = readPolicy(dir);
      const priced = (amount: string, currency: string) => ({
        type: "Commitment",
        terms: { price: { amount, currency } },
      });
      expect(permits(policy.commit, priced("50", "USD"))).toBe(true);
      expect(permits(policy.commit, priced("50.01", "USD"))).toBe(false);
      expect(permits(policy.commit, priced("5", "EUR"))).toBe(false);
      expect(permits(policy.commit, { type: "Commitment", terms: {} })).toBe(false);
      expect(permits(policy.receipt, { type: "Receipt", outcome: "progress" })).toBe(true);
      expect(permits(policy.receipt, { type: "Receipt", outcome: "fulfilled" })).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("shows a result as the server gives one: the notice, and another's words under `untrusted`", () => {
    const [, example = ""] = /## The tools[\s\S]*?```json\n([\s\S]*?)\n```/u.exec(readme) ?? [];
    const shown = JSON.parse(example) as { notice: string; packets: Record<string, unknown>[] };
    expect(server.NOTICE.startsWith(shown.notice.replace(/ …$/u, ""))).toBe(true);
    expect(Object.keys(shown.packets[0] ?? {})).toStrictEqual([
      "packet",
      "from",
      "receivedAt",
      "sealed",
      "untrusted",
    ]);
  });

  it("names only things the package exports, and every one of them", () => {
    const named = table("## What it exports").flatMap(([names = ""]) =>
      [...names.matchAll(/`([A-Za-z_]+)`/gu)].map(([, name = ""]) => name),
    );
    const values = Object.keys(server);
    for (const value of values) expect(named, value).toContain(value);
    // What is named besides is a type, which leaves nothing in the module to see.
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Confirming",
        "Given",
        "Host",
        "Policy",
        "Question",
        "Reading",
        "Said",
        "Serve",
        "ServerOptions",
        "Tool",
        "Untrusted",
      ].sort(),
    );
    expect(new Set(named).size).toBe(named.length);
  });

  it("shows a program that uses what the package has", () => {
    const [, example = ""] = /```ts\n([\s\S]*?)\n```/u.exec(readme) ?? [];
    const [, imported = ""] = /import \{([^}]*)\} from "@oip\/mcp-server";/u.exec(example) ?? [];
    expect(imported.split(",").map((name) => name.trim())).toStrictEqual([
      "readPolicy",
      "serverFactory",
      "Work",
    ]);
    expect(typeof server.readPolicy).toBe("function");
    expect(typeof server.serverFactory).toBe("function");
    expect(typeof server.Work).toBe("function");
  });
});
