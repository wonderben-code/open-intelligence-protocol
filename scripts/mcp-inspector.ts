// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The MCP server under the MCP Inspector (BUILD.md, M8).
 *
 * The Inspector is the protocol's own tool for looking at a server from
 * outside. This starts the network of `oip demo`, makes two minds with the
 * built command, and has the Inspector's command line talk to the built
 * `oip-mcp` for one of them:
 *
 * - it lists the tools, with the Inspector's strict check of their schemas;
 * - it calls `oip_whoami`, and is told the address the command shows;
 * - it calls `oip_find`, and what the other mind says is under `untrusted`;
 * - it calls `oip_commit`, and gets no signature: the Inspector's command
 *   line cannot put a question to a person.
 *
 * The Inspector is no dependency of this repository. It is run by `npx`,
 * at the version pinned here, in a job that holds no secret.
 *
 *   --no-install   leave out `pnpm install` and `pnpm build`: for a tree that is built
 */

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { repoRoot } from "./lib/spec.ts";

/** The Inspector that is run. Its command line and its exit codes are those of this version. */
const INSPECTOR = "@modelcontextprotocol/inspector@2.16.0";
/** What the Inspector's command line exits with for a tool that answered `isError`. */
const TOOL_IS_ERROR = 5;
/** The tools of Layer 0, 2.2, in the order a host is given them. */
const TOOLS = [
  "oip_whoami",
  "oip_find",
  "oip_send",
  "oip_inbox",
  "oip_publish_intent",
  "oip_make_offer",
  "oip_commit",
  "oip_receipt",
  "oip_status",
];

const OIP = join(repoRoot, "packages", "cli", "dist", "bin.js");
const SERVER = join(repoRoot, "packages", "mcp-server", "dist", "bin.js");
// Made for this run, and for minds that live as long as it does.
const PASSPHRASE = "the-inspector-run-of-this-commit";

/** What is running and what was made, for `finish` to end and to clear up. */
const made: { network?: ChildProcess; home?: string } = {};

/** Clears up, and ends the run. */
function finish(problem?: string): never {
  made.network?.kill("SIGTERM");
  if (made.home !== undefined) rmSync(made.home, { recursive: true, force: true });
  if (problem !== undefined) {
    console.error(`\nmcp-inspector: ${problem}`);
    process.exit(1);
  }
  console.log("\nThe MCP Inspector lists the tools, calls them, and gets no signature unasked.");
  process.exit(0);
}

if (!process.argv.includes("--no-install")) {
  for (const argv of [["install", "--frozen-lockfile"], ["build"]]) {
    const { status } = spawnSync("pnpm", argv, {
      cwd: repoRoot,
      stdio: ["ignore", "ignore", "inherit"],
    });
    if (status !== 0) finish(`pnpm ${argv.join(" ")} failed, with ${String(status)}`);
  }
}
for (const program of [OIP, SERVER]) {
  if (!existsSync(program)) {
    finish(`${program} is not there: build the repository, or leave out --no-install`);
  }
}

// A home directory that holds nothing: no mind, no network, no Inspector catalog.
const home = mkdtempSync(join(tmpdir(), "oip-inspector-"));
made.home = home;
const env = {
  PATH: process.env["PATH"] ?? "",
  HOME: home,
  USERPROFILE: home,
  OIP_PASSPHRASE: PASSPHRASE,
  MCP_CATALOG_PATH: join(home, "inspector-catalog.json"),
};

const network = spawn(process.execPath, [OIP, "demo"], { env, stdio: "ignore" });
made.network = network;
const from = Date.now();
while (!existsSync(join(home, ".oip-demo", "network.json"))) {
  if (network.exitCode !== null) {
    finish(`\`oip demo\` ended at once, with ${String(network.exitCode)}`);
  }
  if (Date.now() - from > 60_000) finish("`oip demo` did not start its network within a minute");
  await new Promise((resolve) => setTimeout(resolve, 50));
}

/** Runs the built command, and gives what it printed. It ends the run if the command fails. */
function oip(...argv: string[]): string {
  const ran = spawnSync(process.execPath, [OIP, ...argv], {
    cwd: home,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
  if (ran.status !== 0) finish(`oip ${argv.join(" ")} failed, with ${String(ran.status)}`);
  return ran.stdout.trim();
}

const bobs = join(home, "bob");
oip("init", "--local");
oip("init", "--local", "--dir", bobs);
oip(
  "publish",
  "profile",
  "--dir",
  bobs,
  "--name",
  "Bob",
  "--capability",
  "translate=Translates a lease",
);
const ada = oip("show", "--get", "mind");
const bob = oip("show", "--dir", bobs, "--get", "mind");

/** What the Inspector's command line came back with. */
interface Inspected {
  readonly status: number | null;
  /** What it printed, read as JSON, or `undefined` if that is none. */
  readonly said: unknown;
  readonly err: string;
}

/** Has the Inspector make one request of the server for the first mind. */
function inspect(...request: string[]): Inspected {
  const ran = spawnSync(
    "npx",
    [
      "-y",
      INSPECTOR,
      "--cli",
      "-e",
      `OIP_DIR=${join(home, ".oip")}`,
      "-e",
      `OIP_PASSPHRASE=${PASSPHRASE}`,
      "-e",
      `HOME=${home}`,
      ...request,
      process.execPath,
      SERVER,
    ],
    {
      cwd: home,
      // The Inspector is fetched as this process would fetch it: with its registry, its
      // proxy and its cache. What the server is given is named above, and nothing else is its.
      env: { ...process.env, MCP_CATALOG_PATH: env.MCP_CATALOG_PATH },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 300_000,
    },
  );
  let said: unknown;
  try {
    said = JSON.parse(ran.stdout);
  } catch {
    said = undefined;
  }
  return { status: ran.status, said, err: ran.stderr };
}

/** A member of what was said, by the names that lead to it. */
function member(value: unknown, ...path: (string | number)[]): unknown {
  let at = value;
  for (const name of path) {
    if (typeof at !== "object" || at === null) return undefined;
    at = (at as Readonly<Record<string | number, unknown>>)[name];
  }
  return at;
}

/** Ends the run unless something is so. */
function check(so: boolean, what: string, seen: Inspected): void {
  if (so) {
    console.log(`  ok  ${what}`);
    return;
  }
  console.error(seen.err);
  finish(`${what}: it is not so. The Inspector ended with ${String(seen.status)}`);
}

const listed = inspect("--method", "tools/list", "--strict");
const names = member(listed.said, "tools");
check(
  listed.status === 0,
  "the tools are listed, and the strict check of their schemas finds no error",
  listed,
);
check(
  Array.isArray(names) &&
    JSON.stringify(names.map((tool) => member(tool, "name"))) === JSON.stringify(TOOLS),
  "they are the nine tools of Layer 0, 2.2, in order",
  listed,
);

const who = inspect("--method", "tools/call", "--tool-name", "oip_whoami");
check(
  who.status === 0 && member(who.said, "structuredContent", "address") === ada,
  "oip_whoami gives the address the command shows",
  who,
);

const found = inspect(
  "--method",
  "tools/call",
  "--tool-name",
  "oip_find",
  "--tool-arg",
  "want=translate a lease",
);
const first = member(found.said, "structuredContent", "found", 0);
check(
  found.status === 0 && member(first, "mind") === bob,
  "oip_find finds the other mind, verified",
  found,
);
check(
  member(first, "untrusted", "name") === "Bob" && member(first, "name") === undefined,
  "what the other mind says of itself is under `untrusted`, and nowhere else",
  found,
);

const committed = inspect(
  "--method",
  "tools/call",
  "--tool-name",
  "oip_commit",
  "--tool-arg",
  `debtors=${JSON.stringify([bob])}`,
  'creditors=["me"]',
  "promise=A lease translated",
);
const refusal = member(committed.said, "structuredContent", "error");
check(
  committed.status === TOOL_IS_ERROR &&
    member(committed.said, "isError") === true &&
    typeof refusal === "string" &&
    refusal.startsWith("NOT SIGNED."),
  "oip_commit signs nothing for a host that cannot ask the person",
  committed,
);
// The mind's directory says the same: among the records it keeps there is no Commitment.
const records = join(home, ".oip", "records");
const kept = existsSync(records)
  ? readdirSync(records).filter((name) => name.endsWith(".json"))
  : [];
const signed = kept.filter(
  (name) =>
    member(JSON.parse(readFileSync(join(records, name), "utf8")), "record", "type") ===
    "Commitment",
);
check(signed.length === 0, "and the mind's directory holds no Commitment", committed);

finish();
