// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `verifyEd25519` asked for a valid signature at each depth near the end of
 * the call stack, in a process that has verified often before.
 *
 * `first-verify.node.ts` asks code the engine has never run, whose frames
 * are at their largest. Code that has run often is compiled again, with
 * frames of other sizes, and the library's verification and the steps
 * taken again after it (ADR-0010) are compiled separately: how much deeper
 * the one reaches than the other is not what it is in cold code. So the
 * question is asked of warm code too.
 *
 * The frames of the descent are of one size, so the depths asked are that
 * far apart, and the place where an answer changes may lie between two of
 * them. Each depth is therefore asked again below a few frames of another
 * size, which moves every depth asked by a part of a frame.
 *
 * Usage: node --conditions=@oip/source warm-verify.node.ts [depths] [shifts] [rounds]
 */

import { cutShortCount } from "@oip/schema";
import { keepFramesOneSize } from "@oip/testkit";

import { ed25519PublicKey, isEd25519PublicKey, signEd25519, verifyEd25519 } from "../src/index.ts";

const depths = Number(process.argv[2] ?? 60);
const shifts = Number(process.argv[3] ?? 16);
const rounds = Number(process.argv[4] ?? 3);
const text = new TextEncoder().encode("a signature this process has checked often");
const seed = new Uint8Array(32).fill(7);
const key = ed25519PublicKey(seed);
const signature = signEd25519(text, seed);
/** The same with one bit of `S` changed: `R` is a point of order L, and the equation fails. */
const failing = signature.slice();
failing[40] = (failing[40] ?? 0) ^ 1;

isEd25519PublicKey(key);
// Enough calls for the engine to have compiled the verification for speed, and what follows
// a signature that fails as well.
for (let n = 0; n < 1500; n++) {
  if (!verifyEd25519(signature, text, key)) throw new Error("a valid signature was refused");
}
for (let n = 0; n < 750; n++) {
  if (verifyEd25519(failing, text, key)) throw new Error("a signature that fails was accepted");
}

let deepest = 0;
let target = -1;
let answer: string;

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
  } catch {
    answer = "threw";
  }
};

/** Runs `run` below `frames` frames that are not the size of the descent's. */
const shifted = (frames: number, run: () => void, a = 0, b = 0, c = 0): void => {
  if (frames === 0) run();
  else shifted(frames - 1, run, a + 1, b + a, c + b);
};

// The frames of the descent, and of what shifts it, stay one size: each descent then ends
// where the one before it said it would (`keepFramesOneSize`). The verification is compiled
// as the engine sees fit, which is what is asked about.
keepFramesOneSize(descend, shifted);

/** Finds where the stack ends below `shift` frames, asked until two askings agree. */
const findEnd = (shift: number): boolean => {
  let found = -1;
  for (let asked = 0; asked < 8; asked++) {
    deepest = 0;
    target = -1;
    shifted(shift, () => {
      descend(0);
    });
    if (deepest === found) return true;
    found = deepest;
  }
  return false;
};

const answers: Record<string, number> = {};
const silent: string[] = [];
for (let round = 0; round < rounds; round++) {
  for (let shift = 0; shift < shifts; shift++) {
    const settled = findEnd(shift);
    for (let frames = 0; frames < depths; frames++) {
      target = deepest - frames;
      answer = "not reached";
      if (settled) {
        try {
          shifted(shift, () => {
            descend(0);
          });
        } catch {
          // The stack ended above the depth asked for: the frames were not one size after all.
          answer = "threw outside";
        }
      } else {
        answer = "the end of the stack was not found twice at one depth";
      }
      answers[answer] = (answers[answer] ?? 0) + 1;
      if (answer === "false, nothing noted") silent.push(`${frames} below ${shift}`);
    }
  }
}
process.stdout.write(
  JSON.stringify({ answers, silent, afterwards: verifyEd25519(signature, text, key) }),
);
