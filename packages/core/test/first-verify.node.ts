// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The first call of `verifyEd25519` in a process, made a chosen number of
 * frames above the end of the call stack. `cut-short.test.ts` runs it for a
 * range of depths, each in a process of its own.
 *
 * The library's verification has a `catch` of its own that answers `false`
 * for whatever is thrown while it decodes the key and `R` and multiplies
 * the base point. At one depth that is where the stack runs out: the
 * answer is `false` for a valid signature, and nothing above could tell
 * (ADR-0010). The code is cold, so the frames are at their largest.
 *
 * Usage: node --conditions=@oip/source first-verify.node.ts <frames> [cold]
 */

import { cutShortCount } from "@oip/schema";
import { keepFramesOneSize } from "@oip/testkit";

import { hasOrderL } from "../src/ed25519.ts";
import { ed25519PublicKey, isEd25519PublicKey, signEd25519, verifyEd25519 } from "../src/index.ts";

const frames = Number(process.argv[2]);
const text = new TextEncoder().encode("the first signature this process checks");
const seed = new Uint8Array(32).fill(5);
const key = ed25519PublicKey(seed);
const signature = signEd25519(text, seed);
// The key is remembered as of order L, so that the check asked for is the library's. With
// `cold`, it is not: the check of the key's order is then the first thing to find no room.
if (process.argv[3] !== "cold") isEd25519PublicKey(key);
// Which of the two this run is, as the package has it: a check that says no shows whether
// the key is remembered, and leaves nothing remembered.
const remembered = hasOrderL(key, () => false);

let deepest = 0;
let target = -1;
let answer = "not reached";
let thrown: unknown;

const descend = (depth: number): void => {
  if (target < 0) {
    // First time down: find where the stack ends.
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
  try {
    const before = cutShortCount();
    const valid = verifyEd25519(signature, text, key);
    answer = `${String(valid)}, ${cutShortCount() === before ? "nothing noted" : "noted"}`;
  } catch (error) {
    // Kept as it is: there is no room here to look at it.
    answer = "threw";
    thrown = error;
  }
};

// The frames of the descent stay one size, so that the second descent ends where the first
// said it would (`keepFramesOneSize`).
keepFramesOneSize(descend);
// Where the stack ends, asked until two askings agree: the first of all can be a frame out.
let found = -1;
for (let asked = 0; asked < 8 && found !== deepest; asked++) {
  found = deepest;
  deepest = 0;
  target = -1;
  descend(0);
}
if (found === deepest) {
  target = deepest - frames;
  try {
    descend(0);
  } catch {
    // The stack ended above the depth asked for: the frames were not one size after all.
    answer = "threw outside";
  }
} else {
  answer = "the end of the stack was not found twice at one depth";
}
// Where it was thrown from tells a function that could not be entered from one that failed
// to answer.
const where =
  thrown === undefined
    ? ""
    : String((thrown as { stack?: unknown }).stack)
        .split("\n")
        .slice(1, 4)
        .map((line) => line.trim().replace(/\(.*\/packages\//u, "("))
        .join(" < ");
process.stdout.write(
  JSON.stringify({
    frames,
    remembered,
    answer,
    where,
    afterwards: verifyEd25519(signature, text, key),
  }),
);
