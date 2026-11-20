// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The rule for a check cut short, in a process whose global object cannot
 * hold the count that the copies of this module share (ADR-0010): the
 * module then keeps a count of its own, and judges by it.
 *
 * `frozen` is a process that freezes the count after the module has
 * loaded, as code that hardens everything the global object holds would:
 * a note is still a note, and noting still never throws.
 *
 * Usage: node --conditions=@oip/source own-count.node.ts closed|taken|unsound|frozen
 */

const SLOT = Symbol.for("@oip/schema/cut-short/1");
const how = process.argv[2];

if (how === "closed") Object.preventExtensions(globalThis);
if (how === "taken") Object.defineProperty(globalThis, SLOT, { value: "something else" });
// What looks like a count and is none.
if (how === "unsound") Object.defineProperty(globalThis, SLOT, { value: { noted: Number.NaN } });

const { cutShort, cutShortCount, judging, noteCutShort } = await import("../src/index.ts");

if (how === "frozen") Object.freeze((globalThis as { [SLOT]?: unknown })[SLOT]);

const before = cutShortCount();
const refused = judging(() => {
  noteCutShort(new RangeError("Maximum call stack size exceeded"));
  return { ok: true, value: 1 };
});
process.stdout.write(
  JSON.stringify({
    moved: cutShortCount() - before,
    refused: refused === cutShort(),
    answered: judging(() => ({ ok: true, value: 1 })),
    shared: typeof (globalThis as { [SLOT]?: unknown })[SLOT],
  }),
);
