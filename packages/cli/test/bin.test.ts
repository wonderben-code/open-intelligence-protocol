// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The command `oip`, run as a process of its own from the source: its terminal, its signals, its exit. */

import { type ChildProcess, spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { VERSION } from "../src/index.ts";

const bin = join(repoRoot, "packages", "cli", "src", "bin.ts");

let home: string;
beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), "oip-cli-bin-"));
});
afterAll(() => {
  rmSync(home, { recursive: true, force: true });
});

/** What a process is started with: nothing of this process's environment but where programs are. */
const environment = (more: Record<string, string> = {}): Record<string, string> => ({
  PATH: process.env["PATH"] ?? "",
  HOME: home,
  USERPROFILE: home,
  ...more,
});

interface Ended {
  readonly code: number | null;
  readonly out: string;
  readonly err: string;
}

/** Starts the command. `ended` settles when the process has. */
function start(argv: readonly string[], env = environment()) {
  const child: ChildProcess = spawn(process.execPath, ["--conditions=@oip/source", bin, ...argv], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
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
  return { child, ended, said: () => out };
}

const oip = (argv: readonly string[], env?: Record<string, string>): Promise<Ended> =>
  start(argv, env).ended;

describe("the command oip, as a process", () => {
  it("says its version, and ends with 2 where it was asked wrongly", async () => {
    expect(await oip(["--version"])).toStrictEqual({ code: 0, out: `${VERSION}\n`, err: "" });
    const wrong = await oip(["no-such-command"]);
    expect(wrong.code).toBe(2);
    expect(wrong.out).toBe("");
    expect(wrong.err).toContain("there is no command `no-such-command`");
  });

  it("runs a network until it is told to stop, and makes a mind on it from another process", async () => {
    const network = start(["demo"]);
    for (let turn = 0; turn < 3000 && !network.said().includes("indexer"); turn++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(network.said()).toContain("https://resolver.oip.localhost");
    expect(existsSync(join(home, ".oip-demo", "network.json"))).toBe(true);
    // A mind, made by a process of its own, with its passphrase from the environment.
    const env = environment({ OIP_PASSPHRASE: "correct horse battery staple" });
    const made = await oip(["init", "--local", "--json"], env);
    expect(made.err).toBe("");
    expect(made.code).toBe(0);
    const { mind, directory } = JSON.parse(made.out) as { mind: string; directory: string };
    expect(directory).toBe(join(home, ".oip"));
    // Shown with no passphrase at all: it reads, and unlocks nothing.
    const shown = await oip(["show"]);
    expect(shown.code).toBe(0);
    expect(shown.out.startsWith(`${mind}\n`)).toBe(true);
    // With no terminal and no passphrase, a command that signs says how to give one.
    const locked = await oip(["rotate"]);
    expect(locked.code).toBe(2);
    expect(locked.err).toContain("set OIP_PASSPHRASE, or run this where one can be typed");
    expect((await oip(["rotate"], env)).code).toBe(0);
    // Told to stop, the network ends as it should, and leaves nothing that says it runs.
    network.child.kill("SIGTERM");
    const stopped = await network.ended;
    expect(stopped.code).toBe(0);
    expect(stopped.out.endsWith("The network has stopped.\n")).toBe(true);
    expect(existsSync(join(home, ".oip-demo", "network.json"))).toBe(false);
    // And with no network, a command that needs one says so.
    const alone = await oip(["show"]);
    expect(alone.code).toBe(2);
    expect(alone.err).toContain("no network is running from");
  });
});
