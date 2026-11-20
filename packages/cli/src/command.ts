// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What a command of `oip` is: its name, its options, its help, and what it does. */

import { UsageError } from "@oip/local";

import type { Edges } from "./edges.ts";

// What a command throws when it was not given what it takes: the help says what that is.
export { UsageError };

/** An option of a command. */
export interface Flag {
  /** Whether it takes a value, or is there or not. */
  readonly type: "string" | "boolean";
  /** Whether it may be given more than once. */
  readonly multiple?: boolean;
  /** What its value is called in the help: `--resolver <origin>`. */
  readonly value?: string;
  /** What it is for, in a line. */
  readonly describes: string;
}

/** What a command was given. */
export interface Arguments {
  /** The options, by name: a value, a list of values for one given several times, or `true`. */
  readonly flags: Readonly<Record<string, string | boolean | readonly string[] | undefined>>;
  /** What was given besides options, in order. */
  readonly positionals: readonly string[];
}

/** What a command answers: for a person to read, and for a program. */
export interface Result {
  /** The lines printed, unless `--json` asks for the other. */
  readonly lines: readonly string[];
  /** What `--json` prints, as JSON. Nothing of a private key is in it. */
  readonly json: unknown;
  /**
   * Whether the command did what it was asked and the answer is no: a
   * record that does not verify. The run then ends with 1, as it does for
   * what could not be done.
   */
  readonly failed?: boolean;
}

/** What a command is run with. */
export interface Context {
  /** What the command reaches outside itself. */
  readonly edges: Edges;
  /** The directory of the mind the command works for. */
  readonly dir: string;
  /**
   * Prints a result now, as the one a command returns is printed when it
   * ends: for a command that runs on, and has something to say first.
   */
  readonly say: (result: Result) => void;
}

/** A command of `oip`. */
export interface Command {
  /** Its name, as it is typed: one word, or two as in `keys backup`. */
  readonly name: string;
  /** What it does, in a line. */
  readonly summary: string;
  /** What it takes besides options, as the help shows it: `<address>`. */
  readonly positionals?: string;
  /** Its options, by name. */
  readonly flags: Readonly<Record<string, Flag>>;
  /** More to know, each a line of the help. */
  readonly notes?: readonly string[];
  /** One way to use it, as it would be typed. */
  readonly example: string;
  /** Does it. */
  run(context: Context, given: Arguments): Promise<Result>;
}

/** The value of an option that takes one, if it was given. */
export function one(given: Arguments, name: string): string | undefined {
  const value = given.flags[name];
  return typeof value === "string" ? value : undefined;
}

/** The values of an option that may be given several times. */
export function many(given: Arguments, name: string): readonly string[] {
  const value = given.flags[name];
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? (value as readonly string[]) : [];
}

/** Whether an option that takes no value was given. */
export function has(given: Arguments, name: string): boolean {
  return given.flags[name] === true;
}
