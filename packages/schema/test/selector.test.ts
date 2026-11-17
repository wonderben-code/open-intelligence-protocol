// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { parseSelector } from "../src/index.ts";

describe(`${clause("L1 11.3")} selectors`, () => {
  it("parses the value itself, names, indexes and quoted names", () => {
    expect(parseSelector(".")).toEqual([]);
    expect(parseSelector(".terms.price.amount")).toEqual(["terms", "price", "amount"]);
    expect(parseSelector(".parties[0].mind")).toEqual(["parties", 0, "mind"]);
    expect(parseSelector("[12][0]")).toEqual([12, 0]);
    expect(parseSelector('.ext["com.example.escrow"].v')).toEqual([
      "ext",
      "com.example.escrow",
      "v",
    ]);
    expect(parseSelector('["a \\"quoted\\" name"]')).toEqual(['a "quoted" name']);
    expect(parseSelector('["\\u00e9"]')).toEqual(["é"]);
    expect(parseSelector('[""]')).toEqual([""]);
    expect(parseSelector(".a_1.B2")).toEqual(["a_1", "B2"]);
  });

  it("rejects everything else", () => {
    for (const bad of [
      "",
      "terms",
      "..",
      ".a..b",
      ".a.",
      ".a-b",
      ".a b",
      "[01]",
      "[-1]",
      "[1.5]",
      "[a]",
      "['a']",
      '["unterminated]',
      '["bad \\x escape"]',
      '["a"',
      ".a[",
      "$.a",
      ". a",
      ".é",
      '["line\nbreak"]',
      null,
      undefined,
      0,
      ["."],
    ]) {
      expect(parseSelector(bad), JSON.stringify(bad)).toBeUndefined();
    }
  });

  it("round-trips any path written in its canonical form", () => {
    const step = fc.oneof(fc.string(), fc.nat());
    fc.assert(
      fc.property(fc.array(step, { minLength: 1, maxLength: 6 }), (path) => {
        const written = path
          .map((part) => (typeof part === "number" ? `[${part}]` : `[${JSON.stringify(part)}]`))
          .join("");
        expect(parseSelector(written)).toEqual(path);
      }),
    );
  });

  it("never throws", () => {
    fc.assert(
      fc.property(fc.string(), (value) => {
        const parsed = parseSelector(value);
        expect(parsed === undefined || Array.isArray(parsed)).toBe(true);
      }),
      { numRuns: 5000 },
    );
  });
});
