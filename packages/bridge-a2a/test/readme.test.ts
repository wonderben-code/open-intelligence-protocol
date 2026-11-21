// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The README says what is so: its tables name what there is, and its numbers are the program's. */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import * as bridge from "../src/index.ts";

const directory = join(repoRoot, "packages", "bridge-a2a");
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
    expect(manifest.bin).toStrictEqual({ "oip-bridge-a2a": "./dist/bin.js" });
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
      "bridge <origin>",
      "agents",
      "serve",
      "--dir <path>",
      "--keys <file>",
      "--base <url>",
      "--port <port>",
      "--host <address>",
      "--every <seconds>",
      "OIP_PASSPHRASE",
      "--help",
      "--version",
    ]);
    for (const setting of settings) expect(written.out, setting).toContain(setting);
    // A default the README gives is the one the help gives.
    for (const [name = "", says = ""] of rows) {
      const [, given] = /Default: (`?[^`\s,]+`?)/u.exec(says) ?? [];
      if (given === undefined) continue;
      // The line of the help that describes the setting begins with it.
      const line = written.out
        .split("\n")
        .find((one) => one.trimStart().startsWith(name.replace(/`/gu, "")));
      expect(line, name).toContain(`Default: ${given.replace(/`/gu, "")}`);
    }
    for (const command of [
      "bridge https://agent.example",
      "agents",
      "serve --base https://gateway.example/a2a",
    ]) {
      expect(readme).toContain(`oip-bridge-a2a ${command}\n`);
    }
  });

  it("gives the limits the program has", () => {
    const limits: Record<string, string> = Object.fromEntries(
      table("## Limits").map(([what = "", much = ""]) => [what, much]),
    );
    const days = (seconds: number): string => `${String(seconds / 86_400)} days`;
    const kib = (bytes: number): string => `${String(bytes / 1024)} KiB`;
    expect(limits).toStrictEqual({
      "An Agent Card": kib(bridge.MAX_CARD_BYTES),
      "An agent's content carried in one packet": kib(bridge.MAX_CARRIED_BYTES),
      "Files of one task fetched for their digest": String(bridge.MAX_FETCHED),
      "Tasks of one agent followed at a time": String(bridge.MAX_OPEN_TASKS),
      "How long a task that does not end is followed": days(bridge.MAX_FOLLOWED_SECONDS),
      "A request of an A2A client": `${String(bridge.MAX_REQUEST_BYTES / 1_048_576)} MiB`,
      "How long a client waits for a mind": "1 minute",
      "How long a task that has ended is kept": days(bridge.MAX_KEPT_SECONDS),
    });
  });

  it("names the extension, the card's path and the version of A2A as the program has them", () => {
    expect(readme).toContain(`declares the extension \`${bridge.OIP_EXTENSION}\``);
    expect(readme).toContain(`<the mind's ID>${bridge.CARD_PATH}"`);
    expect(readme).toContain(`fetches \`${bridge.CARD_PATH}\``);
    expect(readme).toContain(`A2A](https://a2a-protocol.org/) ${bridge.A2A_VERSION} `);
    expect(readme).toContain(`media type \`${bridge.OIP_MEDIA_TYPE}\``);
  });

  it("maps every state of a task that says something, as the program does", () => {
    const rows = table("### What the relay does").map(
      ([network = "", agent = ""]) => `${network} ${agent}`,
    );
    const said: Record<string, string> = {
      TASK_STATE_COMPLETED: "`completed`",
      TASK_STATE_FAILED: "`failed`",
      TASK_STATE_CANCELED: "`canceled`",
      TASK_STATE_REJECTED: "`rejected`",
    };
    for (const [state, word] of Object.entries(said)) {
      const row = rows.find((one) => one.includes(word)) ?? "";
      const maps = bridge.saidOf(state);
      const means =
        maps.as === "receipt"
          ? `outcome \`${maps.outcome}\``
          : maps.as === "packet"
            ? `verb \`${maps.verb}\``
            : "nothing";
      expect(row, state).toContain(means);
    }
    expect(bridge.saidOf("TASK_STATE_INPUT_REQUIRED")).toStrictEqual({
      as: "packet",
      verb: "request",
    });
    expect(rows.find((one) => one.includes("needs input"))).toContain(
      "verb `request` to the requester",
    );
  });

  it("names only things the package exports, and every one of them", () => {
    const named = table("## What it exports").flatMap(([names = ""]) =>
      [...names.matchAll(/`([A-Za-z0-9_]+)`/gu)].map(([, name = ""]) => name),
    );
    const values = Object.keys(bridge);
    for (const value of values) expect(named, value).toContain(value);
    // What is named besides is a type, which leaves nothing in the module to see.
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "A2aMessage",
        "Agent",
        "AgentCard",
        "AgentExtension",
        "AgentInterface",
        "AgentSkill",
        "Answer",
        "Answered",
        "Artifact",
        "Ask",
        "Asked",
        "Asking",
        "Bridged",
        "CardSignature",
        "CardSignatures",
        "FrontOptions",
        "GatewayEdges",
        "Get",
        "Held",
        "Host",
        "KeySource",
        "Listening",
        "Page",
        "Part",
        "PublicJwk",
        "Reach",
        "ReadCard",
        "Relayed",
        "Said",
        "Served",
        "ServedInterface",
        "ServedMind",
        "Serving",
        "Taking",
        "Task",
        "TaskState",
      ].sort(),
    );
    expect(new Set(named).size).toBe(named.length);
  });

  it("shows a program that imports what the package has", () => {
    const [, imported = ""] = /import \{([^}]*)\} from "@oip\/bridge-a2a";/u.exec(readme) ?? [];
    const names = imported.split(",").map((name) => name.trim());
    expect(names).toStrictEqual(["Front", "A2aServer", "Gateway", "listen"]);
    for (const name of names)
      expect(typeof (bridge as Record<string, unknown>)[name]).toBe("function");
  });
});
