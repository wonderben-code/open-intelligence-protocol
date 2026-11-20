// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `keepFramesOneSize` asked about a descent that finds where the call stack
 * ends, many times over: often enough for the engine to have compiled it
 * again, more than once, had it been let. `stack.test.ts` runs this in a
 * process of its own.
 *
 * Usage: node --conditions=@oip/source frames.node.ts [kept]
 */

import { runInThisContext } from "node:vm";

import { keepFramesOneSize } from "../src/index.ts";

let deepest = 0;
let target = -1;
let reached: boolean;

const descend = (depth: number): void => {
  if (target < 0) {
    // Find where the stack ends.
    try {
      descend(depth + 1);
    } catch {
      if (deepest === 0) deepest = depth;
    }
    return;
  }
  if (depth < target) {
    descend(depth + 1);
    return;
  }
  reached = true;
};

if (process.argv[2] === "kept") keepFramesOneSize(descend);

const ends: number[] = [];
let short = 0;
for (let pass = 0; pass < 40; pass++) {
  deepest = 0;
  target = -1;
  descend(0);
  ends.push(deepest);
  // Down again, to a few frames above where the stack was just found to end.
  target = deepest - (pass % 4);
  reached = false;
  try {
    descend(0);
  } catch {
    // The stack ended sooner than it had.
  }
  // The first pass of all is before anything has settled, kept or not.
  if (!reached && pass > 0) short++;
}

/**
 * Whether the engine's own syntax is still read, after the helper is done with it. The text
 * is not the helper's own: the engine keeps what it has compiled, and would not read that
 * again.
 */
let syntax = "refused";
try {
  runInThisContext("(function (asked) { return %NeverOptimizeFunction(asked); })");
  syntax = "read";
} catch {
  // A syntax error: the syntax is not JavaScript, and is read as none.
}

process.stdout.write(
  JSON.stringify({ depths: new Set(ends.slice(1)).size, short, syntax, first: ends[1] }),
);
