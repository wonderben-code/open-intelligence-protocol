// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Running a script as Node.js itself runs it, outside the test runner.
 *
 * Under the runner a module is not what it is in a program. An import is
 * read through a getter the runner defines, and one that a package's index
 * re-exports is read through two, the first of which gives `undefined` for
 * whatever the second throws. With the call stack all but spent the second
 * finds no room, the import reads as `undefined`, and the function under
 * test fails for a reason no program would meet. Once the engine has
 * compiled the code the getters are gone, so such a test passes when the
 * code is warm and fails, now and then, when it is cold.
 *
 * So what a function does at the end of the stack is asked of a process of
 * its own, where an import is a binding and the code is as cold as it gets.
 */

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * How long such a script may run before it is taken for hung. It takes a
 * second or two alone. Beside every other test on a shared runner it has
 * taken a hundred times that: the limit is there to end what will never end.
 */
const SCRIPT_TIMEOUT_MS = 300_000;

/** What `execFileSync` throws for a process that did not end well, as far as it is read here. */
interface Failed {
  readonly code?: unknown;
  readonly status?: unknown;
  readonly signal?: unknown;
  readonly stderr?: unknown;
}

/**
 * Runs a script in a Node.js process of its own, with the packages read
 * from their sources, and returns what it printed, read as JSON.
 *
 * @param args - Arguments for the script, which it reads from `process.argv`.
 * @param timeoutMs - How long it may run. Default: five minutes.
 * @throws Error if the script fails. Its first line says how the process
 *   ended (with what code, by what signal, or stopped for taking too long)
 *   and the end of what it wrote to standard error: a run that reports one
 *   line of a failure reports what is needed to tell these apart.
 */
export function inNode(
  script: URL,
  args: readonly string[] = [],
  timeoutMs = SCRIPT_TIMEOUT_MS,
): unknown {
  const path = fileURLToPath(script);
  let printed: string;
  try {
    printed = execFileSync(process.execPath, ["--conditions=@oip/source", path, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });
  } catch (error) {
    const { code, status, signal, stderr } = error as Failed;
    const how =
      code === "ETIMEDOUT"
        ? `was stopped after ${String(timeoutMs / 1000)} seconds`
        : typeof signal === "string"
          ? `was ended by ${signal}`
          : `ended with ${String(status)}`;
    const wrote = typeof stderr === "string" ? stderr.trim() : "";
    const last = wrote.split("\n").slice(-8).join(" | ").slice(-1500);
    throw new Error(
      `${path} ${how}. ${last === "" ? "It wrote nothing to its standard error" : `Its standard error ends: ${last}`}`,
      { cause: error },
    );
  }
  return JSON.parse(printed) as unknown;
}

/**
 * How often a function gave each kind of answer, for a script that reports
 * on many calls. `kind` names the answer in a word or two.
 */
export function tally<T>(
  answers: readonly T[],
  kind: (answer: T) => string,
): Record<string, number> {
  const counted: Record<string, number> = {};
  for (const answer of answers) {
    const name = kind(answer);
    counted[name] = (counted[name] ?? 0) + 1;
  }
  return counted;
}
