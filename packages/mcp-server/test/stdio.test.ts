// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip-mcp`, run as a process of its own, as a host runs it: started from
 * the source, spoken to over its standard input and output.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import type { JsonObject } from "@oip/core";
import { clause, repoRoot } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { POLICY_FILE, TOOLS, VERSION } from "../src/index.ts";
import { PASSPHRASE, Place } from "./harness.ts";

const bin = join(repoRoot, "packages", "mcp-server", "src", "bin.ts");

let place: Place;
let ada: string;
let bob: string;
let dir: string;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada", { name: "Ada" }, "person");
  bob = await place.make("bob", { name: "Bob" });
  dir = place.where("ada").dir;
});
afterAll(async () => {
  await place.close();
});

/** What the process is started with: nothing of this process's environment but where programs are. */
const environment = (more: Record<string, string> = {}): Record<string, string> => ({
  PATH: process.env["PATH"] ?? "",
  HOME: place.root,
  USERPROFILE: place.root,
  OIP_PASSPHRASE: PASSPHRASE,
  ...more,
});

interface Ended {
  readonly code: number | null;
  readonly out: string;
  readonly err: string;
}

/** Starts the program. `ended` settles when the process has. */
function start(argv: readonly string[], env = environment()) {
  const child: ChildProcess = spawn(process.execPath, ["--conditions=@oip/source", bin, ...argv], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  let out = "";
  let err = "";
  child.stdout?.on("data", (chunk: Buffer) => (out += chunk.toString("utf8")));
  child.stderr?.on("data", (chunk: Buffer) => (err += chunk.toString("utf8")));
  const ended = new Promise<Ended>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, out, err });
    });
  });
  return { child, ended, out: () => out, err: () => err };
}

/** Waits until something is so, or says what was not after a while. */
async function until(so: () => boolean, what: string): Promise<void> {
  for (let waited = 0; !so(); waited += 20) {
    if (waited > 60_000) throw new Error(`${what} did not happen`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

describe("oip-mcp, as a process", () => {
  it("says its version and what it takes, and serves nothing then", async () => {
    const version = start(["--version"]);
    version.child.stdin?.end();
    expect(await version.ended).toStrictEqual({ code: 0, out: `${VERSION}\n`, err: "" });
    const help = start(["--help"]);
    help.child.stdin?.end();
    const said = await help.ended;
    expect(said.code).toBe(0);
    expect(said.err).toBe("");
    expect(said.out).toContain("oip-mcp [--dir <path>]");
    expect(said.out).toContain("OIP_PASSPHRASE");
    expect(said.out).toContain("policy.json");
  });

  it("ends with 2, and writes nothing to its output, where it was started wrongly", async () => {
    for (const [argv, why] of [
      [["--passphrase", "x"], "Unknown option '--passphrase'"],
      [["serve"], "Unexpected argument 'serve'"],
    ] as const) {
      const wrong = start(argv);
      wrong.child.stdin?.end();
      const said = await wrong.ended;
      expect(said.code, why).toBe(2);
      expect(said.out).toBe("");
      expect(said.err).toContain(why);
      expect(said.err).toContain("`oip-mcp --help` shows what it takes");
    }
  });

  it("does not start with a policy it cannot read: it does not guess what the person permits", async () => {
    const file = join(dir, POLICY_FILE);
    writeFileSync(file, JSON.stringify({ commit: [] }));
    try {
      const wrong = start(["--dir", dir]);
      wrong.child.stdin?.end();
      const said = await wrong.ended;
      expect(said.code).toBe(2);
      expect(said.out).toBe("");
      expect(said.err).toContain("has no statement under `commit`");
    } finally {
      rmSync(file);
    }
  });

  it(`${clause("L0 2.2")} speaks MCP on its output and nothing else, logs to its error, and ends when its input does`, async () => {
    const served = start(["--dir", dir]);
    const send = (message: JsonObject): void => {
      served.child.stdin?.write(`${JSON.stringify(message)}\n`);
    };
    const lines = (): JsonObject[] =>
      served
        .out()
        .split("\n")
        .filter((line) => line !== "")
        .map((line) => JSON.parse(line) as JsonObject);
    await until(() => served.err().includes("serving the mind of"), "the server starting");
    expect(served.err()).toContain(`oip-mcp ${VERSION}: serving the mind of ${dir}.`);
    expect(served.err()).toContain(
      "Every Commitment and every Receipt is confirmed by the person.",
    );
    expect(served.out()).toBe("");
    // The older handshake, written by hand.
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "by-hand", version: "1" },
      },
    });
    await until(() => lines().length === 1, "the answer to initialize");
    expect(lines()[0]).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      result: { protocolVersion: "2025-06-18", serverInfo: { name: "oip", version: VERSION } },
    });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    send({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "oip_whoami", arguments: {} },
    });
    await until(() => lines().length === 3, "the answers to the calls");
    const answers = lines();
    const listed = answers.find(({ id }) => id === 2) as { result: { tools: { name: string }[] } };
    expect(listed.result.tools.map(({ name }) => name)).toEqual(TOOLS.map(({ name }) => name));
    const who = answers.find(({ id }) => id === 3) as {
      result: { structuredContent: JsonObject };
    };
    expect(who.result.structuredContent).toMatchObject({ address: ada, kind: "person" });
    // Every line of the output is a message of the protocol: one object, on one line.
    for (const line of served.out().split("\n").slice(0, -1)) {
      expect(JSON.parse(line)).toMatchObject({ jsonrpc: "2.0" });
    }
    expect(served.out().endsWith("\n")).toBe(true);
    // Nothing of the passphrase is in what it wrote, to either.
    expect(served.out() + served.err()).not.toContain(PASSPHRASE);
    served.child.stdin?.end();
    expect((await served.ended).code).toBe(0);
  });

  it("ends when it is asked to stop", async () => {
    const served = start(["--dir", dir]);
    await until(() => served.err().includes("serving the mind of"), "the server starting");
    served.child.kill("SIGTERM");
    const said = await served.ended;
    expect(said.out).toBe("");
    expect([0, null]).toContain(said.code);
  });
});

describe.each(["legacy", "auto"] as const)("oip-mcp, to a host that opens the %s way", (mode) => {
  it(`${clause("L0 2.2")} gives its tools, and signs once the person has confirmed`, async () => {
    const questions: string[] = [];
    const client = new Client(
      { name: "a-test-host", version: "1.0.0" },
      { capabilities: { elicitation: { form: {} } }, versionNegotiation: { mode } },
    );
    client.setRequestHandler("elicitation/create", (request) => {
      questions.push((request.params as { message: string }).message);
      return Promise.resolve({ action: "accept" as const, content: { sign: true } });
    });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: ["--conditions=@oip/source", bin],
        // The directory by the environment, as a host's configuration gives it.
        env: environment({ OIP_DIR: dir }),
        stderr: "ignore",
      }),
    );
    try {
      expect((await client.listTools()).tools).toHaveLength(9);
      const result = await client.callTool({
        name: "oip_commit",
        arguments: {
          debtors: [bob],
          creditors: ["me"],
          promise: `A page proofread, asked the ${mode} way`,
          price: { amount: "7", currency: "USD" },
        },
      });
      expect(result.structuredContent).toMatchObject({
        signed: true,
        confirmedBy: "the user",
        says: { author: ada, terms: { price: { amount: "7", payer: ada, payee: bob } } },
      });
      expect(questions).toHaveLength(1);
      expect(questions[0]).toContain(`A page proofread, asked the ${mode} way`);
      expect(questions[0]).toContain("Price: 7 USD");
    } finally {
      await client.close();
    }
  });
});
