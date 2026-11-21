// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { compareDecimals, isAmount, isDecimal, MAX_DECIMAL_LENGTH } from "../src/index.ts";
import { cases, show, strings } from "./vectors.ts";

/** Not decimals, however they look (core 1.3). */
const NOT_DECIMALS: unknown[] = [
  "1,000",
  "1,000,000",
  "1e2",
  "1E2",
  " 400 ",
  " 400",
  "400 ",
  "-Infinity",
  "Infinity",
  "NaN",
  "４００",
  "٤٠٠",
  "+1",
  ".5",
  "1.",
  "01",
  "00",
  "-01",
  "--1",
  "-",
  "",
  "1.2.3",
  "1_000",
  "0x10",
  "1/2",
  "",
  "5 USD",
  "1\n",
  "\n1",
  "- 1",
  "1 .5",
  "一",
  1,
  0,
  1.5,
  1n,
  null,
  undefined,
  true,
  ["1"],
  { value: "1" },
  new String("1"),
];

describe(`${clause("core 1.3")} decimal quantities`, () => {
  it("recognises decimals", () => {
    for (const decimal of [
      "0",
      "1",
      "10",
      "400",
      "0.5",
      "1.50",
      "500.01",
      "-1",
      "-0.25",
      "-0",
      "0.0",
      "-0.000",
      "123456789012345678901234567890.123456789",
      "0.000000000000000000001",
    ]) {
      expect(isDecimal(decimal), decimal).toBe(true);
    }
    for (const bad of NOT_DECIMALS) expect(isDecimal(bad), show(bad)).toBe(false);
  });

  it("recognises amounts, which are never negative", () => {
    for (const amount of ["0", "1", "400", "0.5", "500.01", "0.0"]) {
      expect(isAmount(amount), amount).toBe(true);
    }
    for (const negative of ["-1", "-0.25", "-0", "-0.0", "-400"]) {
      expect(isDecimal(negative), negative).toBe(true);
      expect(isAmount(negative), negative).toBe(false);
    }
    for (const bad of NOT_DECIMALS) expect(isAmount(bad), show(bad)).toBe(false);
  });

  it("allows at most 64 characters", () => {
    expect(MAX_DECIMAL_LENGTH).toBe(64);
    const longest = `${"9".repeat(32)}.${"9".repeat(31)}`;
    expect(longest).toHaveLength(64);
    expect(isDecimal(longest)).toBe(true);
    expect(isAmount(longest)).toBe(true);
    expect(isDecimal(`-${longest.slice(1)}`)).toBe(true);
    expect(isDecimal(`${longest}9`)).toBe(false);
    expect(isAmount(`${longest}9`)).toBe(false);
    expect(isDecimal(`-${longest}`)).toBe(false);
    expect(isDecimal("1".repeat(64))).toBe(true);
    expect(isDecimal("1".repeat(65))).toBe(false);
    expect(compareDecimals("1".repeat(65), "1")).toBeUndefined();
    expect(compareDecimals("1", `0.${"0".repeat(63)}`)).toBeUndefined();
    expect(compareDecimals("1".repeat(64), "1")).toBe(1);
  });

  it("compares numerically", () => {
    const less: [string, string][] = [
      ["0", "1"],
      ["9", "10"],
      ["99", "100"],
      ["1.9", "1.10".replace("1.10", "1.91")],
      ["1.09", "1.1"],
      ["0.5", "0.50001"],
      ["120", "500"],
      ["500", "500.01"],
      ["499.99", "500"],
      ["-1", "0"],
      ["-1", "1"],
      ["-10", "-9"],
      ["-0.5", "-0.25"],
      ["-500.01", "-500"],
      ["0.000000000000000000001", "0.00000000000000000001"],
      ["12345678901234567890", "12345678901234567891"],
      ["9007199254740992", "9007199254740993"],
      ["0.1", "0.3"],
      ["2", "10"],
    ];
    for (const [a, b] of less) {
      expect(compareDecimals(a, b), `${a} < ${b}`).toBe(-1);
      expect(compareDecimals(b, a), `${b} > ${a}`).toBe(1);
    }
  });

  it("treats two spellings of one number as equal", () => {
    for (const [a, b] of [
      ["1.5", "1.50"],
      ["1", "1.0"],
      ["1", "1.000000000000000000000000000000"],
      ["0", "-0"],
      ["0", "0.0"],
      ["-0", "0.00"],
      ["-0.0", "0"],
      ["-1.50", "-1.5"],
      ["500", "500.00"],
      ["100", "100"],
    ] as const) {
      expect(compareDecimals(a, b), `${a} = ${b}`).toBe(0);
      expect(compareDecimals(b, a), `${b} = ${a}`).toBe(0);
    }
  });

  it("is exact where binary floating point is not", () => {
    // As floats, 0.1 + 0.2 is not 0.3, and these pairs are equal.
    expect(compareDecimals("0.30000000000000004", "0.3")).toBe(1);
    expect(compareDecimals("9007199254740993", "9007199254740992")).toBe(1);
    expect(compareDecimals("0.1000000000000000055511151231257827", "0.1")).toBe(1);
    expect(compareDecimals("1.0000000000000000000000000000001", "1")).toBe(1);
    expect(
      compareDecimals("123456789012345678901234567890.1", "123456789012345678901234567890.10"),
    ).toBe(0);
    expect(
      compareDecimals(
        "179769313486231570000000000000000000000000000000000000000000000",
        "179769313486231570000000000000000000000000000000000000000000001",
      ),
    ).toBe(-1);
  });

  it("has no answer when either value is not a decimal", () => {
    for (const bad of NOT_DECIMALS) {
      expect(compareDecimals(bad, "1"), show(bad)).toBeUndefined();
      expect(compareDecimals("1", bad), show(bad)).toBeUndefined();
      expect(compareDecimals(bad, bad), show(bad)).toBeUndefined();
    }
  });

  it("agrees with exact rational arithmetic on any two decimals", () => {
    const decimal = fc
      .tuple(
        fc.boolean(),
        fc.stringMatching(/^(0|[1-9][0-9]{0,20})$/),
        fc.option(fc.stringMatching(/^[0-9]{1,20}$/), { nil: undefined }),
      )
      .map(([negative, whole, fraction]) => ({
        text: `${negative ? "-" : ""}${whole}${fraction === undefined ? "" : `.${fraction}`}`,
        // The value times 10^20, as an integer.
        scaled: BigInt(whole + (fraction ?? "").padEnd(20, "0")) * (negative ? -1n : 1n),
      }));
    fc.assert(
      fc.property(decimal, decimal, (a, b) => {
        const expected = a.scaled < b.scaled ? -1 : a.scaled > b.scaled ? 1 : 0;
        expect(compareDecimals(a.text, b.text), `${a.text} ? ${b.text}`).toBe(expected);
        expect(compareDecimals(a.text, a.text)).toBe(0);
      }),
      { numRuns: 5000 },
    );
  });

  it("orders decimals as a total order", () => {
    const decimal = fc.stringMatching(/^-?(0|[1-9][0-9]{0,5})(\.[0-9]{1,5})?$/);
    fc.assert(
      fc.property(decimal, decimal, decimal, (a, b, c) => {
        const ab = compareDecimals(a, b) ?? 0;
        const bc = compareDecimals(b, c) ?? 0;
        expect(compareDecimals(b, a)).toBe(ab === 0 ? 0 : -ab);
        if (ab <= 0 && bc <= 0) expect(compareDecimals(a, c)).toBeLessThanOrEqual(0);
      }),
      { numRuns: 2000 },
    );
  });

  it("reads every amount in the vectors as an amount", () => {
    const amounts: string[] = [];
    JSON.stringify(cases, (name, value: unknown) => {
      if ((name === "amount" || name === "max") && typeof value === "string") amounts.push(value);
      return value;
    });
    expect(amounts.length).toBeGreaterThan(5);
    for (const amount of amounts) expect(isAmount(amount), amount).toBe(true);
    expect(strings(cases).length).toBeGreaterThan(0);
  });
});
