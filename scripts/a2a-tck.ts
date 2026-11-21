// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind served as an A2A agent, under the A2A TCK (BUILD.md, M9).
 *
 * The TCK is the A2A project's own test of an agent from outside. This
 * starts the system of `packages/bridge-a2a/test/tck/sut.ts` (a network on this
 * machine, a gateway, and an OIP mind the gateway serves as an A2A agent),
 * and runs the TCK against the mind's A2A interface, over the JSON-RPC
 * binding, which is the one the gateway speaks.
 *
 * The run passes if no requirement of level MUST fails. The requirements
 * for what the card says the agent does not do (streaming, push
 * notifications, an extended card) are skipped by the TCK itself.
 *
 * The TCK is no dependency of this repository. It is cloned at the commit
 * pinned here and run with `uv`, which fetches the Python it asks for, in a
 * job that holds no secret.
 *
 *   --tck <directory>   use a checkout of the TCK that is there already
 *   --level <level>     must (the default), should or may: what the TCK is asked to run
 */

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { repoRoot } from "./lib/spec.ts";

/** The TCK that is run: its tests and its scenarios are those of this commit. */
const TCK = "https://github.com/a2aproject/a2a-tck";
const COMMIT = "5e6f37c2d38eb3d7684686243c34d365c83df49b";
const SUT = join(repoRoot, "packages", "bridge-a2a", "test", "tck", "sut.ts");
/** How long the system has to say where it is, in milliseconds. */
const START_MS = 60_000;

const made: { sut?: ChildProcess; checkout?: string } = {};

/** Clears up, and ends the run. */
function finish(code: number, problem?: string): never {
  made.sut?.kill("SIGTERM");
  if (made.checkout !== undefined) rmSync(made.checkout, { recursive: true, force: true });
  if (problem !== undefined) process.stderr.write(`${problem}\n`);
  process.exit(code);
}

const option = (name: string): string | undefined => {
  const at = process.argv.indexOf(name);
  return at === -1 ? undefined : process.argv[at + 1];
};

/** Runs a command to its end, with its output shown. */
function run(command: string, args: readonly string[], cwd: string): number {
  const done = spawnSync(command, args, { cwd, stdio: "inherit", env: process.env });
  if (done.error !== undefined) finish(1, `${command} could not be run: ${done.error.message}`);
  return done.status ?? 1;
}

let tck = option("--tck");
if (tck === undefined) {
  made.checkout = mkdtempSync(join(tmpdir(), "a2a-tck-"));
  tck = made.checkout;
  // One commit, by its name: what is run is what was read.
  for (const args of [
    ["init", "--quiet"],
    ["remote", "add", "origin", TCK],
    ["fetch", "--quiet", "--depth", "1", "origin", COMMIT],
    ["checkout", "--quiet", "FETCH_HEAD"],
  ]) {
    if (run("git", args, tck) !== 0)
      finish(1, `the TCK could not be fetched: git ${args[0] ?? ""}`);
  }
}

const sut = spawn(process.execPath, ["--conditions=@oip/source", SUT], {
  cwd: repoRoot,
  stdio: ["ignore", "pipe", "inherit"],
});
made.sut = sut;
const host = await new Promise<string>((resolve) => {
  const waited = setTimeout(() => {
    finish(1, "the system did not start in a minute");
  }, START_MS);
  sut.once("exit", (code) => {
    finish(1, `the system ended before it was asked: ${String(code)}`);
  });
  createInterface({ input: sut.stdout }).on("line", (line) => {
    if (!line.startsWith("SUT ")) return;
    clearTimeout(waited);
    resolve(line.slice("SUT ".length));
  });
});
sut.removeAllListeners("exit");

const status = run(
  "uv",
  [
    "run",
    "./run_tck.py",
    "--sut-host",
    host,
    "--transport",
    "jsonrpc",
    "--level",
    option("--level") ?? "must",
  ],
  tck,
);
finish(status, status === 0 ? undefined : "the TCK found requirements that are not met");
