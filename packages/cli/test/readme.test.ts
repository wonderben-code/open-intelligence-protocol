// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import * as cli from "../src/index.ts";
import { Home } from "../src/home.ts";

const packageRoot = join(repoRoot, "packages", "cli");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");
const { COMMANDS, GLOBAL_FLAGS, VERSION } = cli;

/** The rows of the table under a heading, each as its cells. */
function table(heading: string): string[][] {
  const [, after = ""] = readme.split(`\n## ${heading}\n`);
  const [section = ""] = after.split("\n## ");
  return section
    .split("\n")
    .filter((line) => line.startsWith("| ") && !/^\| -+ /u.test(line))
    .slice(1)
    .map((line) =>
      line
        .slice(1, -1)
        .split("|")
        .map((cell) => cell.trim()),
    );
}

/** The fenced blocks of shell the README shows, each as its text. */
const shells = [...readme.matchAll(/```sh\n([\s\S]*?)\n```/gu)].map(([, block = ""]) => block);

describe("the README", () => {
  it("lists every command with what it does, as the command says it of itself", () => {
    expect(table("Commands")).toStrictEqual(
      COMMANDS.map(({ name, positionals, summary }) => [
        `\`oip ${name}${positionals === undefined ? "" : ` ${positionals}`}\``,
        summary,
      ]),
    );
  });

  it("lists every option that every command takes", () => {
    const listed = table("What every command takes").map(([option = ""]) =>
      option.replace(/^`--([a-z-]+).*$/u, "$1"),
    );
    expect(listed.sort()).toStrictEqual(Object.keys(GLOBAL_FLAGS).sort());
  });

  it("shows no command that is none, and no option a command does not take", () => {
    const shown: string[] = [];
    for (const block of shells) {
      // A line that ends with a backslash goes on in the next.
      const text = block.replace(/\\\n\s*/gu, " ");
      // Every place the command is called, one inside another too: `"$(oip show --get mind)"`.
      for (const [, words = ""] of text.matchAll(/(?=\boip ([^\n)#]*))/gu)) {
        const argv = words.match(/"[^"]*"|\S+/gu) ?? [];
        const named = argv.filter((word) => /^[a-z][a-z-]*$/u.test(word));
        const command =
          COMMANDS.find(({ name }) => name === named.slice(0, 2).join(" ")) ??
          COMMANDS.find(({ name }) => name === named[0]);
        expect(command, `oip ${words}`).toBeDefined();
        shown.push(command?.name ?? "");
        const known = new Set([...Object.keys(command?.flags ?? {}), ...Object.keys(GLOBAL_FLAGS)]);
        for (const word of argv) {
          const [, flag] = /^--([a-z-]+)/u.exec(word) ?? [];
          if (flag !== undefined) expect(known.has(flag), `oip ${words}: --${flag}`).toBe(true);
        }
      }
    }
    // The path a newcomer follows makes minds, publishes, finds, commits, reads and verifies.
    for (const name of [
      "demo",
      "init",
      "publish profile",
      "find",
      "commit",
      "inbox",
      "show",
      "status",
      "verify",
    ]) {
      expect(shown, name).toContain(name);
    }
  });

  it("marks the lines the newcomer run follows, in the order it follows them", () => {
    const marks = [...readme.matchAll(/<!-- newcomer: ([a-z ]+) -->/gu)].map(([, name]) => name);
    expect(marks).toStrictEqual(["the network", "the path", "end"]);
    const [, network = ""] =
      /<!-- newcomer: the network -->\s+```sh\n([\s\S]*?)\n```/u.exec(readme) ?? [];
    expect(network).toBe("oip demo");
    const [, path = ""] =
      /<!-- newcomer: the path -->\s+```sh\n([\s\S]*?)\n```/u.exec(readme) ?? [];
    expect(path.split("\n").filter((line) => /^(oip|WHO=|DEAL=)/u.test(line)).length).toBe(10);
    // What `--get` is asked for there is what those commands answer with.
    expect(path).toContain("--get found.0.mind");
    expect(path).toContain("--get id");
    expect(path).toContain("--get mind");
  });

  it("names what a mind's directory holds, as the command keeps it", () => {
    const home = new Home("/x");
    const kept = table("A mind's directory").map(([name = ""]) => name.replace(/`/gu, ""));
    expect(kept).toStrictEqual([
      "config.json",
      ...[home.keys, home.memory, home.records, home.inbox].map((path) => `${path.slice(3)}/`),
    ]);
  });

  it("names only things the package exports, and every one of them", () => {
    const named = table("From another program").flatMap(([names = ""]) =>
      [...names.matchAll(/`([A-Za-z_]+)`/gu)].map(([, name = ""]) => name),
    );
    const values = Object.keys(cli);
    for (const value of values) expect(named, value).toContain(value);
    // What is named besides is a type, which leaves nothing in the module to see.
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Arguments",
        "Command",
        "Config",
        "Context",
        "Edges",
        "ExitCode",
        "Flag",
        "Network",
        "NetworkFile",
        "NetworkOptions",
        "Process",
        "Result",
      ].sort(),
    );
    expect(readme).toContain('import { run, systemEdges } from "@oip/cli";');
  });

  it("says the version the package has", () => {
    const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as {
      version: string;
      bin: Record<string, string>;
    };
    expect(VERSION).toBe(manifest.version);
    expect(manifest.bin).toStrictEqual({ oip: "./dist/bin.js" });
  });

  it("names the variables the command reads, and no option for a passphrase", () => {
    for (const variable of ["OIP_PASSPHRASE", "OIP_BACKUP_PASSPHRASE", "OIP_DIR"]) {
      expect(readme).toContain(`\`${variable}\``);
    }
    for (const command of COMMANDS) {
      for (const flag of Object.keys(command.flags)) expect(flag).not.toMatch(/pass(phrase|word)/u);
    }
  });
});
