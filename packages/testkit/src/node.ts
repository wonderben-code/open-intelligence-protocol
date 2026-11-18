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
 * Runs a script in a Node.js process of its own, with the packages read
 * from their sources, and returns what it printed, read as JSON.
 *
 * @throws Error if the script fails, with what it wrote to standard error.
 */
export function inNode(script: URL): unknown {
  const printed = execFileSync(
    process.execPath,
    ["--conditions=@oip/source", fileURLToPath(script)],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      // Some hundred times what such a script takes.
      timeout: 120_000,
    },
  );
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
