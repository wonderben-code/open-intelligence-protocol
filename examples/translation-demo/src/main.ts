// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The demo as a program: `pnpm demo`.
 *
 * With nothing said, it runs a network of its own, which ends with the
 * telling. With `--network`, it plays on a network that runs already, as
 * `oip demo` runs one, and leaves what the minds published there: an
 * identity log, a profile, a feed and the records of the deal for each, to
 * be looked at afterwards.
 */

import { parseArgs } from "node:util";

import { UsageError } from "@oip/local";

import { Stage } from "./stage.ts";
import { NotSo, tell } from "./story.ts";

const HELP = [
  "The translation demo: the scenario of the Open Intelligence Protocol's papers, told as it happens.",
  "",
  "  pnpm demo                       On a network of its own, which ends with the telling",
  "  pnpm demo --network <directory> On a network that runs already: the directory of `oip demo`",
  "",
  "  --help                          Show this",
  "",
].join("\n");

/** What the program has of the process it runs in: `process` is one. */
export interface Host {
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
}

/**
 * Runs the program.
 *
 * @param argv - Its arguments, without the program's own name.
 * @returns What it exits with: 0 for a telling in which everything held, 1
 *   for one that stopped at something that did not, 2 for arguments it
 *   does not take.
 */
export async function main(argv: readonly string[], host: Host): Promise<number> {
  let network: string | undefined;
  try {
    const { values, positionals } = parseArgs({
      args: [...argv],
      options: { network: { type: "string" }, help: { type: "boolean" } },
      strict: true,
      allowPositionals: true,
    });
    if (values.help === true) {
      host.stdout.write(HELP);
      return 0;
    }
    if (positionals.length > 0) throw new UsageError("the demo takes no argument but --network");
    ({ network } = values);
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
  try {
    await tell(stage, (line) => {
      host.stdout.write(`${line}\n`);
    });
    return 0;
  } catch (error) {
    if (!(error instanceof NotSo)) throw error;
    host.stderr.write(`${error.message}\n`);
    return 1;
  } finally {
    await stage.close();
  }
}
