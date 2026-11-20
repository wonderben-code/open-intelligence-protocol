// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The edges of a run in a real process: its environment, its terminal and its machine. */

import { homedir } from "node:os";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";

import { systemKeychain } from "@oip/keystore/node";

import type { Edges } from "./edges.ts";

/** What a process has of a terminal and of signals: `process` is one. */
export interface Process {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdin: NodeJS.ReadableStream & { readonly isTTY?: boolean };
  readonly stdout: { write(text: string): unknown };
  readonly stderr: { write(text: string): unknown };
  once(signal: "SIGINT" | "SIGTERM", heard: () => void): unknown;
}

/** The edges of a process. */
export function systemEdges(of: Process): Edges {
  /** Reads a line from the terminal without showing it: what is typed is a secret. */
  const secret = (question: string): Promise<string> =>
    new Promise((resolve) => {
      of.stderr.write(question);
      const silent = new Writable({
        write(_chunk, _encoding, done) {
          done();
        },
      });
      const terminal = createInterface({ input: of.stdin, output: silent, terminal: true });
      terminal.question("", (typed) => {
        terminal.close();
        of.stderr.write("\n");
        resolve(typed);
      });
    });
  return {
    env: of.env,
    home: homedir(),
    out: (text) => {
      of.stdout.write(text);
    },
    err: (text) => {
      of.stderr.write(text);
    },
    ...(of.stdin.isTTY === true ? { secret } : {}),
    keychain: () => systemKeychain(),
    stopped: () =>
      new Promise((resolve) => {
        of.once("SIGINT", resolve);
        of.once("SIGTERM", resolve);
      }),
  };
}
