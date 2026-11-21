// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A count that other code froze after this package loaded (ADR-0010).
 *
 * A program may freeze everything its global object holds. The count is
 * among it, and a note can then no longer be added there. It must still be
 * a note, and noting must still never throw.
 *
 * This file is alone because what it does cannot be undone: it freezes the
 * count of the process it runs in. The runner gives each test file a
 * process of its own.
 */

import { describe, expect, it } from "vitest";

import { cutShort, cutShortCount, finding, judging, noteCutShort } from "../src/index.ts";

const COUNT = Symbol.for("@oip/schema/cut-short/1");
const overflow = (): RangeError => new RangeError("Maximum call stack size exceeded");

describe("a count that other code has frozen", () => {
  it("still counts: a note is kept by the copy that made it, and noting does not throw", () => {
    const shared = (globalThis as { [COUNT]?: { noted: number } })[COUNT];
    if (shared === undefined) throw new Error("the count is not where the package keeps it");
    noteCutShort(overflow());
    const kept = shared.noted;
    expect(kept).toBeGreaterThan(0);
    Object.freeze(shared);

    const before = cutShortCount();
    expect(() => {
      noteCutShort(overflow());
    }).not.toThrow();
    // The count the process shares stays where it was, and the reading moves all the same.
    expect(shared.noted).toBe(kept);
    expect(cutShortCount()).toBe(before + 1);
    // What is no failure for want of room is still not counted.
    noteCutShort(new Error("anything else"));
    expect(cutShortCount()).toBe(before + 1);
  });

  it("is still compared by a judge, which refuses for a check that was cut short", () => {
    expect(
      judging(() => {
        noteCutShort(overflow());
        return { ok: true, value: 1 };
      }),
    ).toBe(cutShort());
    expect(
      finding(() => {
        noteCutShort(overflow());
        return 1;
      }),
    ).toBeUndefined();
    expect(
      judging(() => {
        throw overflow();
      }),
    ).toBe(cutShort());
    expect(
      finding(() => {
        throw overflow();
      }),
    ).toBeUndefined();
    // And answers where none was.
    expect(judging(() => ({ ok: true, value: 1 }))).toStrictEqual({ ok: true, value: 1 });
    expect(finding(() => 1)).toBe(1);
    expect(() =>
      judging(() => {
        throw new TypeError("a mistake in the calling program");
      }),
    ).toThrow(TypeError);
  });
});
