// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The parts of the suite that need Node.js: reading the vectors and running the Python checker. */

import { type ChildProcessWithoutNullStreams, spawn, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

import { parseVectors, type Vectors } from "./vectors.ts";

/** Where the specification's test vectors live in this repository. */
export const VECTORS_DIRECTORY = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "spec",
  "test-vectors",
);

/** Reads and checks a `vectors.json`. By default, the one in this repository. */
export function loadVectors(file = join(VECTORS_DIRECTORY, "vectors.json")): Vectors {
  return parseVectors(JSON.parse(readFileSync(file, "utf8")));
}

/** The Python checker's verdict on one case. */
export interface Verdict {
  readonly name: string | null;
  readonly kind: string | null;
  /** Whether the case's claim holds, as `claimHolds` defines it. */
  readonly holds: boolean;
  /** For `status` and `assurance` cases: the value computed. */
  readonly value?: string;
  /** Set when the checker could not process the input at all. `holds` is then false. */
  readonly error?: string;
}

export interface PythonJudgeOptions {
  /** The Python interpreter. Default `python3`. */
  readonly python?: string;
  /** The checker script. Default `spec/test-vectors/oip_vectors.py` in this repository. */
  readonly script?: string;
}

/**
 * Why the Python checker cannot run here, or `undefined` if it can. It needs
 * Python 3 with the `cryptography` package.
 */
export function pythonJudgeUnavailable(options: PythonJudgeOptions = {}): string | undefined {
  const python = options.python ?? "python3";
  const probe = spawnSync(python, ["-c", "import cryptography"], { encoding: "utf8" });
  if (probe.error !== undefined) return `${python} is not installed (${probe.error.message})`;
  if (probe.status !== 0) return `the Python package "cryptography" is not installed`;
  return undefined;
}

/**
 * The independent Python checker, kept open as one process that judges cases
 * one per line (`oip_vectors.py --judge --lines`). Cases are judged in the
 * order given. Call `close()` when done.
 */
export class PythonJudge {
  readonly #child: ChildProcessWithoutNullStreams;
  readonly #waiting: { resolve: (verdict: Verdict) => void; reject: (error: Error) => void }[] = [];
  #failure: Error | undefined;
  #stderr = "";

  constructor(options: PythonJudgeOptions = {}) {
    const script = options.script ?? join(VECTORS_DIRECTORY, "oip_vectors.py");
    this.#child = spawn(options.python ?? "python3", [script, "--judge", "--lines"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.#child.stderr.setEncoding("utf8");
    this.#child.stderr.on("data", (chunk: string) => {
      this.#stderr = (this.#stderr + chunk).slice(-4000);
    });
    // Writing to a checker that has died raises EPIPE here; `close` reports why it died.
    this.#child.stdin.on("error", () => undefined);
    createInterface({ input: this.#child.stdout }).on("line", (line) => {
      const next = this.#waiting.shift();
      if (next === undefined) return;
      try {
        next.resolve(JSON.parse(line) as Verdict);
      } catch {
        next.reject(new Error(`the Python checker printed something that is not JSON: ${line}`));
      }
    });
    this.#child.on("error", (error) => {
      this.#fail(new Error(`could not start the Python checker: ${error.message}`));
    });
    this.#child.on("close", (code) => {
      this.#fail(
        new Error(`the Python checker exited with code ${String(code)}. ${this.#stderr}`.trim()),
      );
    });
  }

  #fail(error: Error): void {
    this.#failure ??= error;
    for (const next of this.#waiting.splice(0)) next.reject(this.#failure);
  }

  /** Asks the checker for its verdict on one case in the vectors' format. */
  judge(vectorCase: unknown): Promise<Verdict> {
    if (this.#failure !== undefined) return Promise.reject(this.#failure);
    // One case per line: JSON.stringify never emits a raw newline.
    const line = JSON.stringify(vectorCase);
    return new Promise((resolve, reject) => {
      this.#waiting.push({ resolve, reject });
      this.#child.stdin.write(`${line}\n`);
    });
  }

  /** Ends the checker's process, once it has answered everything asked. */
  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.#child.exitCode !== null || this.#failure !== undefined) {
        resolve();
        return;
      }
      this.#child.once("close", () => {
        resolve();
      });
      this.#child.stdin.end();
    });
  }
}
