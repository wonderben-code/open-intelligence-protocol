// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `oip-mcp`: the server as a program a host starts.
 *
 * It speaks MCP on its standard input and output, and so writes nothing
 * else there: what it has to say to a person goes to the standard error,
 * which a host keeps in its log. It takes no passphrase at a terminal,
 * since it has none: the keys are opened by `OIP_PASSPHRASE`, or by the
 * machine's keychain where the mind was made with `oip init --keychain`.
 */

import { homedir } from "node:os";
import { parseArgs } from "node:util";

import type { McpServerFactory } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { systemKeychain } from "@oip/keystore/node";
import { directoryOf, type Machine, UsageError } from "@oip/local";

import { readPolicy } from "./policy.ts";
import { serverFactory, VERSION } from "./server.ts";
import { Work } from "./work.ts";

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  /** The environment's variables. */
  readonly env: Readonly<Record<string, string | undefined>>;
  /** Where help is written, and the version. While the server serves, it is the protocol's alone. */
  readonly stdout: { write(text: string): unknown };
  /** Where the log is written. */
  readonly stderr: { write(text: string): unknown };
  /** Calls `heard` once, when the process is asked to stop. */
  once(signal: "SIGINT" | "SIGTERM", heard: () => void): unknown;
}

/** What serves a factory's servers to a host: over the standard streams, unless a test says otherwise. */
export type Serve = (
  factory: McpServerFactory,
  options: { onerror: (error: Error) => void },
) => { close(): Promise<void> };

const HELP = [
  "oip-mcp: gives an MCP host a mind of the Open Intelligence Protocol.",
  "",
  "A host starts it, and speaks MCP to it over its standard input and output.",
  "",
  "  oip-mcp [--dir <path>]",
  "",
  "  --dir <path>   The mind's directory. Default: OIP_DIR, or ~/.oip",
  "  --help         Show this",
  "  --version      Print the version",
  "",
  "The mind is made first, with `oip init`. Its keys are opened by OIP_PASSPHRASE, or by the",
  "machine's keychain if the mind was made with `oip init --keychain`.",
  "",
  "Before a Commitment or a Receipt is signed the person is asked to confirm it. A file",
  "policy.json in the mind's directory says which need not be asked about:",
  '  { "commit": [["==", ".terms.price.currency", "USD"], ["<=", ".terms.price.amount", "50"]],',
  '    "receipt": [["==", ".outcome", "progress"]] }',
  "",
].join("\n");

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @returns What it exits with, or `undefined` while it serves: it then
 *   ends when the host closes its standard input.
 */
export function main(
  argv: readonly string[],
  host: Host,
  serve: Serve = serveStdio,
): number | undefined {
  const log = (line: string): void => {
    host.stderr.write(`${line}\n`);
  };
  try {
    const { values } = parseArgs({
      args: [...argv],
      options: {
        dir: { type: "string" },
        help: { type: "boolean" },
        version: { type: "boolean" },
      },
      strict: true,
      allowPositionals: false,
    });
    if (values.help === true) {
      host.stdout.write(HELP);
      return 0;
    }
    if (values.version === true) {
      host.stdout.write(`${VERSION}\n`);
      return 0;
    }
    const edges: Machine = {
      env: host.env,
      home: homedir(),
      keychain: () => systemKeychain(),
    };
    const dir = directoryOf(values.dir, edges);
    // A policy that cannot be read is not guessed at: the server does not start.
    const policy = readPolicy(dir);
    const handle = serve(serverFactory(new Work({ edges, dir }, policy), { log }), {
      onerror: (error) => {
        log(`oip-mcp: ${error.name}: ${error.message}`);
      },
    });
    const stop = (): void => {
      void handle.close();
    };
    host.once("SIGINT", stop);
    host.once("SIGTERM", stop);
    log(
      `oip-mcp ${VERSION}: serving the mind of ${dir}. ${
        policy.commit === undefined && policy.receipt === undefined
          ? "Every Commitment and every Receipt is confirmed by the person."
          : "A Commitment or a Receipt is confirmed by the person unless policy.json permits it."
      }`,
    );
    return undefined;
  } catch (error) {
    if (error instanceof UsageError) {
      log(`oip-mcp: ${error.message}`);
      return 2;
    }
    if (error instanceof TypeError && "code" in error) {
      // What `parseArgs` says of arguments it does not know.
      log(`oip-mcp: ${error.message}. \`oip-mcp --help\` shows what it takes`);
      return 2;
    }
    throw error;
  }
}
