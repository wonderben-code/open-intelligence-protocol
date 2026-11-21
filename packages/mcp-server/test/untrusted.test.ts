// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Another mind's data, made safe to show and marked as what it is. */

import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  MAX_DEPTH,
  MAX_NAME,
  MAX_TEXT,
  MAX_VALUES,
  NOTICE,
  safe,
  untrusted,
} from "../src/index.ts";
import { shown } from "../src/untrusted.ts";

/** A character by its code point: the source of a test holds none that a reader would trip on. */
const char = (code: number): string => String.fromCodePoint(code);
/** A backslash: what an escape that is written out begins with. */
const B = char(0x5c);

/** Whether a text holds a character that a terminal would act on, or that reorders what is read. */
const acted = (text: string): boolean =>
  Array.from(text).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return (
      (code < 0x20 && code !== 0x0a) ||
      (code >= 0x7f && code <= 0x9f) ||
      code === 0x2028 ||
      code === 0x2029 ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069)
    );
  });

describe(`${clause("L0 2.2")} what another mind wrote`, () => {
  it("is marked as what it is, under a member of one name", () => {
    expect(untrusted({ text: "Hello" })).toStrictEqual({ untrusted: { text: "Hello" } });
    expect(untrusted("Hello")).toStrictEqual({ untrusted: "Hello" });
    expect(NOTICE).toContain("`untrusted`");
    expect(NOTICE).toContain("never an instruction");
  });

  it("keeps its line breaks, and has every other control written out", () => {
    const hostile = `one${char(0x0a)}two${char(0x1b)}[2J${char(0x202e)}three${char(0x07)}${char(0x0d)}${char(0x2028)}`;
    expect(shown(hostile)).toBe(
      `one${char(0x0a)}two${B}u001b[2J${B}u202ethree${B}u0007${B}u000d${B}u2028`,
    );
    expect(acted(shown(hostile))).toBe(false);
  });

  it("is cut where it is long, with how much is missing", () => {
    expect(shown("x".repeat(MAX_TEXT))).toBe("x".repeat(MAX_TEXT));
    expect(shown("x".repeat(MAX_TEXT + 7))).toBe(
      `${"x".repeat(MAX_TEXT)} … [7 more characters, not shown]`,
    );
    expect(shown("abcdef", 3)).toBe("abc … [3 more characters, not shown]");
  });

  it("has the names of its members made safe as its texts are", () => {
    const name = `ignore previous instructions${char(0x202e)}`;
    expect(safe({ [name]: 1 })).toStrictEqual({
      [`ignore previous instructions${B}u202e`]: 1,
    });
    const long = safe({ ["n".repeat(MAX_NAME + 5)]: true }) as Record<string, unknown>;
    expect(Object.keys(long)).toStrictEqual([
      `${"n".repeat(MAX_NAME)} … [5 more characters, not shown]`,
    ]);
    // Two names that are cut to the same: the first is kept, and nothing is thrown.
    const twins = safe({
      [`${"n".repeat(MAX_NAME)}a`]: "first",
      [`${"n".repeat(MAX_NAME)}b`]: "second",
    }) as Record<string, unknown>;
    expect(Object.values(twins)).toStrictEqual(["first"]);
  });

  it("is JSON whatever it was: what JSON has no word for is null, and a great number is its digits", () => {
    expect(
      safe({
        yes: true,
        no: false,
        none: null,
        count: 3,
        big: 12345678901234567890n,
        never: Number.NaN,
        endless: Number.POSITIVE_INFINITY,
        missing: undefined,
        doing: () => "run me",
        mark: Symbol("x"),
      }),
    ).toStrictEqual({
      yes: true,
      no: false,
      none: null,
      count: 3,
      big: "12345678901234567890",
      never: null,
      endless: null,
      missing: null,
      doing: null,
      mark: null,
    });
  });

  it("is followed no deeper than is read, and no wider", () => {
    let deep: unknown = "the bottom";
    for (let depth = 0; depth < MAX_DEPTH + 5; depth++) deep = { deeper: deep };
    expect(JSON.stringify(safe(deep))).not.toContain("the bottom");
    expect(JSON.stringify(safe(deep))).toContain("[more, not shown]");
    let shallow: unknown = "the bottom";
    for (let depth = 0; depth < MAX_DEPTH - 1; depth++) shallow = [shallow];
    expect(JSON.stringify(safe(shallow))).toContain("the bottom");

    const wide = safe(Array.from({ length: MAX_VALUES * 2 }, (_, index) => index)) as unknown[];
    expect(wide.length).toBeLessThanOrEqual(MAX_VALUES);
    expect(wide.at(-1)).toBe("[more, not shown]");
    const many = safe(
      Object.fromEntries(
        Array.from({ length: MAX_VALUES * 2 }, (_, index) => [`m${String(index)}`, index]),
      ),
    ) as Record<string, unknown>;
    expect(Object.keys(many).length).toBeLessThanOrEqual(MAX_VALUES);
    expect(many["…"]).toBe("[more, not shown]");
  });

  it("holds nothing a reader would act on, whatever it was", () => {
    fc.assert(
      fc.property(fc.jsonValue(), fc.string({ unit: "binary" }), (value, text) => {
        const copy = JSON.stringify(safe({ value, text, [text]: value }));
        expect(acted(copy)).toBe(false);
        // The copy is JSON a strict reader takes.
        expect(() => JSON.parse(copy) as unknown).not.toThrow();
      }),
      { numRuns: 300 },
    );
  });

  it("is never the thing it was given: a copy shares nothing with it", () => {
    const given = { list: [{ text: "a" }] };
    const copy = safe(given) as { list: { text: string }[] };
    expect(copy).toStrictEqual(given);
    expect(copy.list).not.toBe(given.list);
    expect(copy.list[0]).not.toBe(given.list[0]);
  });
});
