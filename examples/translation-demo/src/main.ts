// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The demo as a program: `pnpm demo`.
 *
 * With nothing said, it runs a network of its own, which ends with the
 * telling. With `--network`, it plays on a network that runs already, as
 * `oip demo` runs one, and leaves what the minds published there: an
 * identity log, a profile, a feed and the records of the deal for each, to
 * be looked at afterwards. With `--record`, it keeps the telling as a
 * recording.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { UsageError } from "@oip/local";

import { castOf, svgOf } from "./recording.ts";
import { Stage } from "./stage.ts";
import { NotSo, tell } from "./story.ts";

const HELP = [
  "The translation demo: the scenario of the Open Intelligence Protocol's papers, told as it happens.",
  "",
  "  pnpm demo                       On a network of its own, which ends with the telling",
  "  pnpm demo --network <directory> On a network that runs already: the directory of `oip demo`",
  "  pnpm demo --record <directory>  Keep the telling there, as a terminal session and a picture",
  "",
  "  --help                          Show this",
  "",
  "It exits with 0 if everything it said held, with 1 if the telling stopped at something that",
  "did not, with 2 for arguments it does not take, with 3 if the network could not be used, and",
  "with 130 if it was interrupted.",
  "",
].join("\n");

/** The title of the telling, as a recording gives it. */
const TITLE = "The Open Intelligence Protocol: a translation, from want to Receipt";

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  /** Calls `heard` once, when the process is asked to stop. Without it the program cannot be interrupted cleanly. */
  once?(signal: "SIGINT" | "SIGTERM", heard: () => void): unknown;
}

/** What the program does its work with. A test gives its own. */
export interface Edges {
  /** Tells the scenario on a stage. */
  readonly tell: typeof tell;
}

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @param edges - What it does its work with. Default: the telling itself.
 * @returns What it exits with: 0 for a telling in which everything held, 1
 *   for one that stopped at something that did not, 2 for arguments it
 *   does not take, 3 where the network could not be used, and 130 where
 *   it was interrupted. Whatever it returns, the telling's keys and its
 *   directory are gone.
 */
export async function main(
  argv: readonly string[],
  host: Host,
  edges: Edges = { tell },
): Promise<number> {
  let network: string | undefined;
  let record: string | undefined;
  try {
    const { values, positionals } = parseArgs({
      args: [...argv],
      options: {
        network: { type: "string" },
        record: { type: "string" },
        help: { type: "boolean" },
      },
      strict: true,
      allowPositionals: true,
    });
    if (values.help === true) {
      host.stdout.write(HELP);
      return 0;
    }
    if (positionals.length > 0) {
      throw new UsageError("the demo takes no argument but --network and --record");
    }
    ({ network, record } = values);
  } catch (error) {
    host.stderr.write(
      `demo: ${(error as Error).message}. \`pnpm demo --help\` shows what it takes\n`,
    );
    return 2;
  }
  let stage: Stage;
  try {
    stage = await Stage.open(network);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    host.stderr.write(`demo: ${error.message}\n`);
    return 2;
  }
  const lines: string[] = [];
  // A telling that is interrupted ends as one that finished does: its keys and its directory
  // are removed. What it was doing then fails, and nobody is told of that.
  const interrupted = new Promise<"interrupted">((resolve) => {
    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      host.once?.(signal, () => {
        resolve("interrupted");
      });
    }
  });
  const told = edges
    .tell(stage, (line) => {
      lines.push(line);
      host.stdout.write(`${line}\n`);
    })
    .then(
      () => "told" as const,
      (error: unknown) => ({ error }),
    );
  try {
    const ended = await Promise.race([told, interrupted]);
    if (ended === "interrupted") {
      host.stderr.write("demo: interrupted. The telling's keys and its directory are removed\n");
      return 130;
    }
    if (ended === "told") {
      if (record !== undefined) {
        mkdirSync(record, { recursive: true });
        writeFileSync(join(record, "translation-demo.cast"), castOf(lines, TITLE));
        writeFileSync(join(record, "translation-demo.svg"), svgOf(lines, TITLE));
        host.stdout.write(`\n${String(lines.length)} lines recorded in ${record}\n`);
      }
      return 0;
    }
    const { error } = ended;
    if (error instanceof NotSo) {
      host.stderr.write(`${error.message}\n`);
      return 1;
    }
    // A service that cannot be reached, or that answers as none, is no failed check: the
    // telling could not be made. One line says so, and the exit code is its own.
    if (error instanceof TransportError) {
      host.stderr.write(
        `demo: the network could not be used: ${error.origin} ${error.failure}. Is it still running?\n`,
      );
      return 3;
    }
    if (error instanceof OipError) {
      host.stderr.write(`demo: the network could not be used: it answered ${error.code}\n`);
      return 3;
    }
    if (error instanceof UsageError) {
      host.stderr.write(`demo: ${error.message}\n`);
      return 2;
    }
    throw error;
  } finally {
    await stage.close();
  }
}
