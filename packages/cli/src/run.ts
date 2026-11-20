// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * One run of `oip`: its arguments are read, a command is found and run, and
 * what it answers is printed. Nothing here reaches outside but through the
 * edges it is given.
 */

import { parseArgs, type ParseArgsOptionsConfig } from "node:util";

import { TransportError } from "@oip/client";
import { OipError } from "@oip/core";
import { KeystoreError } from "@oip/keystore";

import { type Arguments, type Command, type Flag, type Result, UsageError } from "./command.ts";
import { COMMANDS } from "./commands/index.ts";
import type { Edges } from "./edges.ts";
import { directoryOf } from "./home.ts";
import { printable, printableJson } from "./text.ts";

/** What a run ends with: 0 if it did what was asked, 1 if it could not, 2 if it was asked wrongly. */
export type ExitCode = 0 | 1 | 2;

/** The options every command takes. */
export const GLOBAL_FLAGS = {
  dir: {
    type: "string",
    value: "path",
    describes: "The mind's directory. Default: OIP_DIR, or .oip in your home directory",
  },
  json: { type: "boolean", describes: "Print the result as JSON" },
  help: { type: "boolean", describes: "Show this, or a command's own help" },
  version: { type: "boolean", describes: "Print the version" },
} as const satisfies Readonly<Record<string, Flag>>;

/** The version the command says it is. */
export const VERSION = "0.0.0";

const flagLine = (name: string, flag: Flag): [string, string] => [
  `--${name}${flag.type === "string" ? ` <${flag.value ?? "value"}>` : ""}`,
  flag.describes,
];

/** Lines of two columns, the first padded to the widest. */
function columns(rows: readonly (readonly [string, string])[]): string[] {
  const width = Math.max(...rows.map(([first]) => first.length));
  return rows.map(([first, second]) => `  ${first.padEnd(width)}  ${second}`);
}

/** The help of `oip` itself: every command, and the options they share. */
export function overview(): string[] {
  return [
    "oip <command> [options]",
    "",
    "A mind of the Open Intelligence Protocol, from a terminal.",
    "",
    "Commands:",
    ...columns(COMMANDS.map((command) => [command.name, command.summary])),
    "",
    "Options of every command:",
    ...columns(Object.entries(GLOBAL_FLAGS).map(([name, flag]) => flagLine(name, flag))),
    "",
    "Run `oip <command> --help` for a command's own options, and an example.",
  ];
}

/** The help of one command. */
export function helpOf(command: Command): string[] {
  const flags = Object.entries(command.flags);
  return [
    `oip ${command.name}${command.positionals === undefined ? "" : ` ${command.positionals}`}${
      flags.length === 0 ? "" : " [options]"
    }`,
    "",
    command.summary,
    ...(command.notes === undefined ? [] : ["", ...command.notes]),
    ...(flags.length === 0
      ? []
      : ["", "Options:", ...columns(flags.map(([name, flag]) => flagLine(name, flag)))]),
    "",
    "Example:",
    `  ${command.example}`,
  ];
}

/** The command the arguments name, and the arguments that follow its name. */
function find(argv: readonly string[]): { command: Command | undefined; rest: string[] } {
  // The words before the first option, but for the value of `--dir`, are where a name is.
  const words: number[] = [];
  for (let index = 0; index < argv.length && words.length < 2; index++) {
    const word = argv[index] ?? "";
    if (word === "--dir") index++;
    else if (!word.startsWith("-")) words.push(index);
    else if (words.length > 0) break;
  }
  for (const take of [2, 1]) {
    if (words.length < take) continue;
    const taken = words.slice(0, take);
    const name = taken.map((index) => argv[index]).join(" ");
    const command = COMMANDS.find((candidate) => candidate.name === name);
    if (command !== undefined) {
      return { command, rest: argv.filter((_, index) => !taken.includes(index)) };
    }
  }
  return { command: undefined, rest: [...argv] };
}

/** The arguments of a command, read by its own options and those every command takes. */
function read(command: Command | undefined, rest: readonly string[]): Arguments {
  const options: ParseArgsOptionsConfig = {};
  const flags: Readonly<Record<string, Flag>> = { ...GLOBAL_FLAGS, ...command?.flags };
  for (const [name, flag] of Object.entries(flags)) {
    options[name] = { type: flag.type, ...(flag.multiple === true ? { multiple: true } : {}) };
  }
  try {
    const parsed = parseArgs({ args: [...rest], options, allowPositionals: true, strict: true });
    return { flags: parsed.values as Arguments["flags"], positionals: parsed.positionals };
  } catch (error) {
    // What `parseArgs` says of an option it does not know, or one given no value.
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }
}

/** What went wrong, as a code and a sentence. `undefined` for what is nobody's to explain. */
function failureOf(error: unknown): { code: string; message: string; exit: ExitCode } | undefined {
  if (error instanceof UsageError) return { code: "usage", message: error.message, exit: 2 };
  if (error instanceof OipError) return { code: error.code, message: error.message, exit: 1 };
  if (error instanceof TransportError) {
    return { code: error.failure, message: error.message, exit: 1 };
  }
  if (error instanceof KeystoreError) return { code: error.code, message: error.message, exit: 1 };
  return undefined;
}

/**
 * Runs `oip` once.
 *
 * @param argv - The arguments, without the program's own name.
 * @returns What the process should exit with.
 * @throws What no command is expected to throw: a fault of the command's own.
 */
export async function run(argv: readonly string[], edges: Edges): Promise<ExitCode> {
  const json = argv.includes("--json");
  const print = (result: Result): void => {
    // Much of what is printed is a stranger's words: nothing of it reaches the terminal as a control.
    edges.out(
      json
        ? `${printableJson(result.json)}\n`
        : `${result.lines.map((line) => printable(line)).join("\n")}\n`,
    );
  };
  const { command, rest } = find(argv);
  try {
    const given = read(command, rest);
    if (given.flags["version"] === true) {
      print({ lines: [VERSION], json: { version: VERSION } });
      return 0;
    }
    if (command === undefined) {
      const [word] = given.positionals;
      if (word !== undefined) {
        throw new UsageError(`there is no command \`${word}\`: \`oip --help\` lists them`);
      }
      print({ lines: overview(), json: { commands: COMMANDS.map(({ name }) => name) } });
      // Asked for nothing, it has shown what could be asked: that is a use of it, if not the one meant.
      return given.flags["help"] === true ? 0 : 2;
    }
    if (given.flags["help"] === true) {
      print({
        lines: helpOf(command),
        json: {
          command: command.name,
          summary: command.summary,
          options: Object.keys(command.flags),
          example: command.example,
        },
      });
      return 0;
    }
    const dir = given.flags["dir"];
    const context = {
      edges,
      dir: directoryOf(typeof dir === "string" ? dir : undefined, edges),
      say: print,
    };
    const result = await command.run(context, given);
    print(result);
    return result.failed === true ? 1 : 0;
  } catch (error) {
    const failure = failureOf(error);
    if (failure === undefined) throw error;
    if (json) {
      edges.out(`${printableJson({ error: { code: failure.code, message: failure.message } })}\n`);
    } else {
      // A problem's words may be a service's own.
      edges.err(`oip: ${printable(failure.message)}\n`);
      if (failure.exit === 2) {
        edges.err(
          `Run \`oip ${command === undefined ? "" : `${command.name} `}--help\` for how it is used.\n`,
        );
      }
    }
    return failure.exit;
  }
}
