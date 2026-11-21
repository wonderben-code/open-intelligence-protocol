// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { MAX_DEPTH, validateJson, validateWithoutProof } from "../src/index.ts";

/** An object nested `depth` deep, the object itself being depth 1. */
const nested = (depth: number): unknown => (depth === 1 ? {} : { in: nested(depth - 1) });

/** A list of two with no first element. */
const holed: unknown[] = [];
holed[1] = 1;

describe(`${clause("core 3.1", "L1 7.1")} a value apart from its proofs`, () => {
  it("is the plain copy of the value without its `proof`", () => {
    const value = { type: "Update", seq: 1, homes: ["https://a.example"], proof: [{ a: 1 }] };
    const content = validateWithoutProof(value);
    expect(content).toStrictEqual({
      ok: true,
      value: { type: "Update", seq: 1, homes: ["https://a.example"] },
    });
    // A copy, and never the value it was given.
    expect(content.ok && content.value).not.toBe(value);
    expect(validateWithoutProof({ proof: 5 })).toStrictEqual({ ok: true, value: {} });
    expect(validateWithoutProof({})).toStrictEqual({ ok: true, value: {} });
  });

  it.each<[string, unknown]>([
    ["a number that is no integer", [{ n: 1.5 }]],
    ["a number out of range", [{ n: 2 ** 60 }]],
    ["a lone surrogate", [{ text: "\ud800" }]],
    ["nesting deeper than a record's", [nested(MAX_DEPTH)]],
    ["a value that is no data", [new Date(0), () => 0, undefined]],
    ["a list with a hole", holed],
  ])("does not look at what `proof` holds: %s", (_, proof) => {
    const value = { seq: 1, proof };
    expect(validateJson(value).ok).toBe(false);
    expect(validateWithoutProof(value)).toStrictEqual({ ok: true, value: { seq: 1 } });
  });

  it("does not read `proof` at all: an accessor there is never called", () => {
    let called = 0;
    const value = Object.defineProperty({ seq: 1 }, "proof", {
      get: () => ++called,
      enumerable: true,
    });
    expect(validateWithoutProof(value)).toStrictEqual({ ok: true, value: { seq: 1 } });
    expect(called).toBe(0);
  });

  it("leaves out the value's own `proof`, and no member of that name inside it", () => {
    expect(validateWithoutProof({ ext: { proof: [1] }, proof: [2] })).toStrictEqual({
      ok: true,
      value: { ext: { proof: [1] } },
    });
    expect(validateWithoutProof({ ext: { proof: [1.5] } }).ok).toBe(false);
    expect(validateWithoutProof([{ proof: [1.5] }]).ok).toBe(false);
  });

  it("refuses everything else that `validateJson` refuses", () => {
    let called = 0;
    const accessor = Object.defineProperty({}, "seq", { get: () => ++called, enumerable: true });
    const hidden = Object.defineProperty({}, "seq", { value: 1, enumerable: false });
    const marked = { [Symbol("s")]: 1 };
    class Event {
      seq = 1;
    }
    for (const value of [
      { n: 1.5 },
      { text: "\ud800" },
      { "\ud800": 1 },
      nested(MAX_DEPTH + 1),
      accessor,
      hidden,
      marked,
      new Event(),
      new Date(0),
      5.5,
      undefined,
      () => 0,
    ]) {
      expect(validateWithoutProof(value).ok).toBe(false);
    }
    expect(called).toBe(0);
    // What is no object has no `proof` to leave out, and is checked whole.
    for (const value of [5, "text", null, true, [1, [2]], nested(MAX_DEPTH)]) {
      expect(validateWithoutProof(value)).toStrictEqual(validateJson(value));
    }
  });

  it("reads no more values than it is allowed", () => {
    const wide = { list: Array.from({ length: 50 }, () => 0) };
    expect(validateWithoutProof(wide, { maxValues: 10 }).ok).toBe(false);
    expect(validateWithoutProof(wide, { maxValues: 100 }).ok).toBe(true);
  });
});
