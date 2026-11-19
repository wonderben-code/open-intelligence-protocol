// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the engine throws for a regular expression at the end of the call
 * stack, and whether `noteCutShort` counts each (ADR-0010).
 *
 * An expression is parsed when it is made and compiled when it is first
 * used, and either can find no room. The engine then reports a syntax
 * error in an expression that has none, in words of its own that differ
 * for the two. `cut-short.test.ts` runs this in a process of its own.
 *
 * Usage: node --conditions=@oip/source regex-at-depth.node.ts
 */

import { cutShortCount, noteCutShort } from "../src/index.ts";

/** How many of the frames nearest the end of the stack each thing is asked in. */
const NEAREST = 4000;
const ROUNDS = 4;

// An engine keeps what it has made ready, so each expression is one it has not met.
let made = 0;
const unused = Array.from(
  { length: NEAREST * ROUNDS },
  (_, n) => new RegExp(`^(?:x${n}|[0-9]+[DHMS])+$`, "u"),
);
let used = 0;
const asked: Readonly<Record<string, () => unknown>> = {
  made: () => new RegExp(`^(a|b${made++})+c$`, "u"),
  firstUsed: () => unused[used++]?.test("12D"),
};

const thrown: unknown[] = Array.from({ length: NEAREST }, () => undefined);
let failures = 0;
let left = 0;

/** Goes to the end of the stack, and asks on the way back up, in the frames nearest the end. */
const descend = (ask: () => unknown): void => {
  try {
    descend(ask);
  } catch {
    // The end of the stack.
  }
  if (left > 0) {
    left--;
    try {
      ask();
    } catch (error) {
      // Kept as it is: there is no room here to look at it.
      thrown[failures++] = error;
    }
  }
};

const report: Record<string, Record<string, number>> = {};
for (const [name, ask] of Object.entries(asked)) {
  const kinds: Record<string, number> = {};
  for (let round = 0; round < ROUNDS; round++) {
    left = NEAREST;
    failures = 0;
    descend(ask);
    for (const error of thrown.slice(0, failures)) {
      const before = cutShortCount();
      noteCutShort(error);
      const said = error instanceof Error ? error.message : String(error);
      const kind = `${error instanceof Error ? error.constructor.name : typeof error}: ${said.replace(/\/.*\/[a-z]*:/u, "/…/:")}, ${cutShortCount() === before ? "not counted" : "counted"}`;
      kinds[kind] = (kinds[kind] ?? 0) + 1;
    }
  }
  report[name] = kinds;
}
process.stdout.write(JSON.stringify(report));
