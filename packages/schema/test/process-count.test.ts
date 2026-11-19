// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where a process keeps its count of checks cut short (ADR-0010): on an
 * object every copy of this package finds, left there by the first.
 *
 * The object is the global one. Here it is an object of the test's own, so
 * that each state it can be in is made without touching the runner's.
 * `own-count.node.ts` makes the same states of the global object itself, in
 * a process of its own.
 */

import { describe, expect, it } from "vitest";

import { countOfTheProcess } from "../src/process-count.ts";

const COUNT = Symbol.for("@oip/schema/cut-short/1");

/** What an object holds where the count is kept. */
const held = (shared: object): unknown => (shared as Record<symbol, unknown>)[COUNT];

describe("the count a process keeps", () => {
  it("is left by the first copy for the others, where nothing shows it", () => {
    const shared: object = {};
    const first = countOfTheProcess(shared);
    expect(first).toStrictEqual({ noted: 0 });
    expect(held(shared)).toBe(first);
    // Not among the properties a program lists, and not to be put aside for another.
    expect(Object.keys(shared)).toStrictEqual([]);
    expect(Object.getOwnPropertyDescriptor(shared, COUNT)).toMatchObject({
      enumerable: false,
      writable: false,
      configurable: false,
    });
    first.noted = 7;
    const second = countOfTheProcess(shared);
    expect(second).toBe(first);
    expect(second.noted).toBe(7);
  });

  it("is the global object's, when no other is named", () => {
    // The package has loaded, so the count is there already.
    expect(countOfTheProcess()).toBe(held(globalThis));
    expect(Number.isSafeInteger(countOfTheProcess().noted)).toBe(true);
  });

  it("is the caller's alone where the object takes no new property", () => {
    for (const shared of [Object.freeze({}), Object.preventExtensions({})]) {
      const one = countOfTheProcess(shared);
      const other = countOfTheProcess(shared);
      expect(one).toStrictEqual({ noted: 0 });
      expect(other).not.toBe(one);
      expect(Object.getOwnPropertySymbols(shared)).toStrictEqual([]);
    }
  });

  it("is the caller's alone where the place is taken by something that is no count", () => {
    for (const taken of [
      "something else",
      null,
      7,
      {},
      { noted: "7" },
      // A number that is none would never again compare equal to itself.
      { noted: Number.NaN },
      { noted: 0.5 },
      { noted: Number.POSITIVE_INFINITY },
    ]) {
      const shared: object = Object.defineProperty({}, COUNT, { value: taken });
      const own = countOfTheProcess(shared);
      expect(own, JSON.stringify(taken)).toStrictEqual({ noted: 0 });
      expect(own).not.toBe(taken);
      expect(held(shared)).toBe(taken);
    }
  });

  it("takes the place of what is no count, where it can be put aside", () => {
    const shared: object = { [COUNT]: { noted: Number.NaN } };
    const own = countOfTheProcess(shared);
    expect(own).toStrictEqual({ noted: 0 });
    expect(held(shared)).toBe(own);
  });

  it("is the caller's alone where the object cannot so much as be read", () => {
    const shared = new Proxy(
      {},
      {
        get: () => {
          throw new Error("no");
        },
      },
    );
    expect(countOfTheProcess(shared)).toStrictEqual({ noted: 0 });
  });
});
