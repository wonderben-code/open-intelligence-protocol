// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The five-minute promise, measured (BUILD.md, Section 1.2 and M7).
 *
 * A newcomer who has Node.js follows the README of `@oip/cli` and, within
 * five minutes, has a published, resolvable mind that finds another by what
 * it can do and makes a signed Commitment with it.
 *
 * This runs what that README says, as it stands: it installs and builds the
 * repository, starts the network the README starts, and runs the lines the
 * README gives, in a shell, in a home directory that holds nothing. It
 * fails if a line fails, if the Commitment is not accepted, or if the whole
 * of it takes five minutes or more.
 *
 *   --no-install   leave out `pnpm install` and `pnpm build`: for a tree that is built
 */

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { repoRoot } from "./lib/spec.ts";

/** The promise: under five minutes, in seconds. */
const LIMIT_SECONDS = 300;
const README = join(repoRoot, "packages", "cli", "README.md");
const BIN = join(repoRoot, "packages", "cli", "dist", "bin.js");

/** The lines of the fenced block that follows a marker in the README. */
function blockAfter(readme: string, marker: string): string {
  const at = readme.indexOf(`<!-- newcomer: ${marker} -->`);
  if (at < 0) throw new Error(`the README has no marker for ${marker}`);
  const block = /```sh\n([\s\S]*?)\n```/u.exec(readme.slice(at));
  if (block?.[1] === undefined)
    throw new Error(`no block of commands follows the marker ${marker}`);
  return block[1];
}

const started = Date.now();
const timings: [string, number][] = [];
/** Runs a step, and notes how long it took. It ends the run if the step fails. */
function step(name: string, work: () => number | null): void {
  const from = Date.now();
  const status = work();
  timings.push([name, (Date.now() - from) / 1000]);
  if (status !== 0) finish(`${name} failed, with ${String(status)}`);
}

/** What is running and what was made, for `finish` to end and to clear up. */
const made: { network?: ChildProcess; home?: string } = {};

/** Says how long each step took, clears up, and ends the run. */
function finish(problem?: string): never {
  made.network?.kill("SIGTERM");
  if (made.home !== undefined) rmSync(made.home, { recursive: true, force: true });
  const total = (Date.now() - started) / 1000;
  for (const [name, seconds] of timings) {
    console.log(`  ${seconds.toFixed(1).padStart(6)} s  ${name}`);
  }
  console.log(`  ${total.toFixed(1).padStart(6)} s  in all, of ${String(LIMIT_SECONDS)} allowed`);
  if (problem !== undefined) {
    console.error(`\nnewcomer: ${problem}`);
    process.exit(1);
  }
  if (total >= LIMIT_SECONDS) {
    console.error(
      `\nnewcomer: the README took ${total.toFixed(0)} seconds to follow: the promise is under ${String(LIMIT_SECONDS)}`,
    );
    process.exit(1);
  }
  console.log(
    "\nA newcomer has two minds and an accepted Commitment between them, in under five minutes.",
  );
  process.exit(0);
}

const readme = readFileSync(README, "utf8");
const networkBlock = blockAfter(readme, "the network").trim();
const path = blockAfter(readme, "the path");
if (networkBlock !== "oip demo") {
  throw new Error(
    `the README starts its network with \`${networkBlock}\`, which this does not know how to run`,
  );
}

if (!process.argv.includes("--no-install")) {
  const pnpm =
    (...argv: string[]) =>
    (): number | null =>
      spawnSync("pnpm", argv, { cwd: repoRoot, stdio: ["ignore", "ignore", "inherit"] }).status;
  step("pnpm install", pnpm("install", "--frozen-lockfile"));
  step("pnpm build", pnpm("build"));
}
if (!existsSync(BIN))
  finish(`${BIN} is not there: build the repository, or leave out --no-install`);

// A home directory that holds nothing: no mind, no network, no configuration.
const home = mkdtempSync(join(tmpdir(), "oip-newcomer-"));
made.home = home;
const env = { PATH: process.env["PATH"] ?? "", HOME: home, USERPROFILE: home };

// The network the README starts in a terminal of its own.
let said = "";
const network = spawn(process.execPath, [BIN, "demo"], {
  env,
  stdio: ["ignore", "pipe", "inherit"],
});
made.network = network;
network.stdout.on("data", (chunk: Buffer) => (said += chunk.toString("utf8")));
const from = Date.now();
while (!existsSync(join(home, ".oip-demo", "network.json"))) {
  if (network.exitCode !== null)
    finish(`\`oip demo\` ended at once, with ${String(network.exitCode)}`);
  if (Date.now() - from > 60_000) finish("`oip demo` did not start its network within a minute");
  await new Promise((resolve) => setTimeout(resolve, 50));
}
timings.push(["oip demo, until its network is ready", (Date.now() - from) / 1000]);

// The lines of the README, as a newcomer's shell would run them: `oip` is the built command.
let output = "";
step("the lines of the README", () => {
  const shell = spawnSync(
    "bash",
    ["-euo", "pipefail", "-c", `oip() { "${process.execPath}" "${BIN}" "$@"; }\n${path}`],
    { cwd: home, env, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
  );
  output = shell.stdout;
  process.stdout.write(output.replace(/^/gmu, "    "));
  return shell.status;
});

// What the README promises of its last lines: the Commitment is accepted, and it verifies.
if (!/^ {2}status {5}accepted$/mu.test(output)) finish("the Commitment was not accepted");
if (!output.trimEnd().endsWith("It verifies.")) finish("the Commitment did not verify");
if (said === "") finish("`oip demo` said nothing of where its services are");
finish();
