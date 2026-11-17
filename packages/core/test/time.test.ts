// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause, withAmbientTrapped } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  CLOCK_SKEW,
  formatTimestamp,
  isDuration,
  isTimestamp,
  MAX_DURATION_LENGTH,
  parseDuration,
  parseTimestamp,
} from "../src/index.ts";
import { cases, show, strings } from "./vectors.ts";

const SECOND = 1_000_000_000n;

/** The instant by the platform's calendar, which is exact to the millisecond. */
function byPlatform(year: number, month: number, day: number, hour = 0, minute = 0, second = 0) {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  return BigInt(date.getTime()) * 1_000_000n;
}

const two = (value: number) => String(value).padStart(2, "0");

describe(`${clause("core 1.4")} timestamps`, () => {
  it("reads a timestamp as nanoseconds since 1970", () => {
    expect(parseTimestamp("1970-01-01T00:00:00Z")).toBe(0n);
    expect(parseTimestamp("1970-01-01T00:00:01Z")).toBe(SECOND);
    expect(parseTimestamp("1970-01-02T00:00:00Z")).toBe(86400n * SECOND);
    expect(parseTimestamp("1969-12-31T23:59:59Z")).toBe(-SECOND);
    expect(parseTimestamp("2000-01-01T00:00:00Z")).toBe(946684800n * SECOND);
    expect(parseTimestamp("2026-10-30T09:00:00Z")).toBe(byPlatform(2026, 10, 30, 9));
    expect(parseTimestamp("2026-11-17T23:59:59Z")).toBe(byPlatform(2026, 11, 17, 23, 59, 59));
    expect(parseTimestamp("2001-09-09T01:46:40Z")).toBe(1_000_000_000n * SECOND);
    expect(parseTimestamp("9999-12-31T23:59:59.999999999Z")).toBe(253402300800n * SECOND - 1n);
    expect(parseTimestamp("0000-01-01T00:00:00Z")).toBe(-62167219200n * SECOND);
  });

  it("keeps every digit of the fraction", () => {
    const base = parseTimestamp("2026-10-30T09:00:00Z") ?? 0n;
    expect(parseTimestamp("2026-10-30T09:00:00.5Z")).toBe(base + 500_000_000n);
    expect(parseTimestamp("2026-10-30T09:00:00.000000001Z")).toBe(base + 1n);
    expect(parseTimestamp("2026-10-30T09:00:00.123456789Z")).toBe(base + 123_456_789n);
    expect(parseTimestamp("2026-10-30T09:00:00.999999999Z")).toBe(base + 999_999_999n);
    expect(parseTimestamp("2026-10-30T09:00:00.001Z")).toBe(base + 1_000_000n);
    expect(parseTimestamp("2026-10-30T09:00:00.0Z")).toBe(base);
    expect(parseTimestamp("2026-10-30T09:00:00.000000000Z")).toBe(base);
  });

  it("compares as instants at full precision, never as strings", () => {
    const instant = (text: string) => parseTimestamp(text) ?? 0n;
    // The same instant, written two ways.
    expect(instant("2026-10-30T09:00:00.1Z")).toBe(instant("2026-10-30T09:00:00.100Z"));
    expect(instant("2026-10-30T09:00:00Z")).toBe(instant("2026-10-30T09:00:00.000Z"));
    // One nanosecond is a difference. A clock of millisecond precision would lose it.
    expect(instant("2026-10-30T09:00:00.000000001Z") > instant("2026-10-30T09:00:00Z")).toBe(true);
    expect(instant("2026-10-30T09:00:00.0000009Z") < instant("2026-10-30T09:00:00.000001Z")).toBe(
      true,
    );
    // As strings these compare the other way round: "." sorts before "Z".
    expect("2026-10-30T09:00:00.5Z" < "2026-10-30T09:00:00Z").toBe(true);
    expect(instant("2026-10-30T09:00:00.5Z") > instant("2026-10-30T09:00:00Z")).toBe(true);
    expect("2026-10-30T09:00:00.9Z" > "2026-10-30T09:00:00.10Z").toBe(true);
    expect(instant("2026-10-30T09:00:00.9Z") > instant("2026-10-30T09:00:00.10Z")).toBe(true);
  });

  it("accepts only real dates and times", () => {
    for (const real of [
      "2024-02-29T00:00:00Z",
      "2000-02-29T00:00:00Z",
      "2400-02-29T00:00:00Z",
      "0000-02-29T00:00:00Z",
      "0004-02-29T00:00:00Z",
      "2026-01-31T00:00:00Z",
      "2026-04-30T00:00:00Z",
      "2026-12-31T23:59:59Z",
      "2026-02-28T23:59:59.999999999Z",
    ]) {
      expect(isTimestamp(real), real).toBe(true);
      expect(typeof parseTimestamp(real), real).toBe("bigint");
    }
    for (const unreal of [
      "2026-13-01T00:00:00Z",
      "2026-00-01T00:00:00Z",
      "2026-01-00T00:00:00Z",
      "2026-01-32T00:00:00Z",
      "2026-04-31T00:00:00Z",
      "2026-06-31T00:00:00Z",
      "2026-09-31T00:00:00Z",
      "2026-11-31T00:00:00Z",
      "2026-02-29T00:00:00Z",
      "2026-02-30T00:00:00Z",
      "2023-02-29T00:00:00Z",
      "1900-02-29T00:00:00Z",
      "2100-02-29T00:00:00Z",
      "0100-02-29T00:00:00Z",
      "2026-01-01T24:00:00Z",
      "2026-01-01T23:60:00Z",
      "2026-01-01T23:59:60Z",
      "2026-01-01T23:59:61Z",
      "2026-12-31T23:59:60Z",
    ]) {
      expect(isTimestamp(unreal), unreal).toBe(false);
      expect(parseTimestamp(unreal), unreal).toBeUndefined();
    }
  });

  it("accepts only the one form: UTC, upper-case T and Z, up to nine fraction digits", () => {
    for (const bad of [
      "2026-10-30T09:00:00",
      "2026-10-30T09:00:00+00:00",
      "2026-10-30T09:00:00-00:00",
      "2026-10-30T09:00:00+01:00",
      "2026-10-30t09:00:00Z",
      "2026-10-30T09:00:00z",
      "2026-10-30 09:00:00Z",
      "2026-10-30T09:00Z",
      "2026-10-30T09Z",
      "2026-10-30",
      "2026-10-30T09:00:00.Z",
      "2026-10-30T09:00:00.1234567890Z",
      "2026-10-30T09:00:00,5Z",
      "20261030T090000Z",
      "2026-1-30T09:00:00Z",
      "26-10-30T09:00:00Z",
      "02026-10-30T09:00:00Z",
      "+2026-10-30T09:00:00Z",
      "-0001-10-30T09:00:00Z",
      " 2026-10-30T09:00:00Z",
      "2026-10-30T09:00:00Z ",
      "2026-10-30T09:00:00Z\n",
      "２０２６-10-30T09:00:00Z",
      "",
      "now",
      1793354400,
      null,
      undefined,
      new Date(0),
      ["2026-10-30T09:00:00Z"],
    ]) {
      expect(isTimestamp(bad), show(bad)).toBe(false);
      expect(parseTimestamp(bad), show(bad)).toBeUndefined();
    }
  });

  it("agrees with the platform's calendar on every date", () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 0, max: 9999 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 31 }),
        fc.integer({ min: 0, max: 23 }),
        fc.integer({ min: 0, max: 59 }),
        fc.integer({ min: 0, max: 59 }),
        fc.option(fc.stringMatching(/^[0-9]{1,9}$/), { nil: undefined }),
        (year, month, day, hour, minute, second, fraction) => {
          const text =
            `${String(year).padStart(4, "0")}-${two(month)}-${two(day)}T` +
            `${two(hour)}:${two(minute)}:${two(second)}${fraction === undefined ? "" : `.${fraction}`}Z`;
          // The platform rolls a day that does not exist into the next month.
          const check = new Date(0);
          check.setUTCFullYear(year, month - 1, day);
          const real = check.getUTCMonth() === month - 1;
          const parsed = parseTimestamp(text);
          expect(parsed !== undefined, text).toBe(real);
          if (parsed !== undefined) {
            const nanoseconds = BigInt((fraction ?? "").padEnd(9, "0"));
            expect(parsed, text).toBe(
              byPlatform(year, month, day, hour, minute, second) + nanoseconds,
            );
          }
        },
      ),
      { numRuns: 5000 },
    );
  });

  it("orders timestamps as time passes", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: -62167219200n * SECOND, max: 253402300800n * SECOND - 1n }),
        fc.bigInt({ min: 1n, max: 10n ** 12n }),
        (instant, step) => {
          fc.pre(instant + step <= 253402300800n * SECOND - 1n);
          const earlier = parseTimestamp(formatTimestamp(instant));
          const later = parseTimestamp(formatTimestamp(instant + step));
          expect(earlier).toBe(instant);
          expect(later).toBe(instant + step);
        },
      ),
      { numRuns: 2000 },
    );
  });

  it("reads every timestamp in the vectors", () => {
    const found = strings(cases).filter((text) => /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/.test(text));
    expect(found.length).toBeGreaterThan(100);
    for (const text of found) {
      const instant = parseTimestamp(text);
      expect(instant, text).toBe(BigInt(Date.parse(text)) * 1_000_000n);
    }
  });

  it("never reads the clock", () => {
    const answers = withAmbientTrapped(() => [
      parseTimestamp("2026-10-30T09:00:00.5Z"),
      formatTimestamp(0n),
      parseDuration("P1D"),
    ]);
    expect(answers).toEqual([
      byPlatform(2026, 10, 30, 9) + 500_000_000n,
      "1970-01-01T00:00:00Z",
      86400n * SECOND,
    ]);
  });
});

describe("writing a timestamp", () => {
  it("writes an instant with the shortest fraction that keeps its precision", () => {
    expect(formatTimestamp(0n)).toBe("1970-01-01T00:00:00Z");
    expect(formatTimestamp(1n)).toBe("1970-01-01T00:00:00.000000001Z");
    expect(formatTimestamp(500_000_000n)).toBe("1970-01-01T00:00:00.5Z");
    expect(formatTimestamp(120_000_000n)).toBe("1970-01-01T00:00:00.12Z");
    expect(formatTimestamp(1_001_000_000n)).toBe("1970-01-01T00:00:01.001Z");
    expect(formatTimestamp(-1n)).toBe("1969-12-31T23:59:59.999999999Z");
    expect(formatTimestamp(-SECOND)).toBe("1969-12-31T23:59:59Z");
    expect(formatTimestamp(-1_500_000_000n)).toBe("1969-12-31T23:59:58.5Z");
    expect(formatTimestamp(byPlatform(2026, 10, 30, 9, 5, 7))).toBe("2026-10-30T09:05:07Z");
    expect(formatTimestamp(byPlatform(2024, 2, 29, 23, 59, 59))).toBe("2024-02-29T23:59:59Z");
    expect(formatTimestamp(byPlatform(2025, 3, 1))).toBe("2025-03-01T00:00:00Z");
    expect(formatTimestamp(byPlatform(2024, 12, 31, 12))).toBe("2024-12-31T12:00:00Z");
    expect(formatTimestamp(byPlatform(999, 1, 1))).toBe("0999-01-01T00:00:00Z");
    expect(formatTimestamp(-62167219200n * SECOND)).toBe("0000-01-01T00:00:00Z");
    expect(formatTimestamp(253402300800n * SECOND - 1n)).toBe("9999-12-31T23:59:59.999999999Z");
  });

  it("writes only what a timestamp can name", () => {
    for (const bad of [-62167219200n * SECOND - 1n, 253402300800n * SECOND, 10n ** 40n]) {
      expect(() => formatTimestamp(bad)).toThrow(
        new RangeError("a timestamp names an instant in the years 0000 to 9999"),
      );
    }
    // A value that is not an instant at all is a wrong argument, not one out of range.
    for (const bad of [0, "0", null, 1.5, undefined, new Date(0)]) {
      expect(() => formatTimestamp(bad as unknown as bigint)).toThrow(
        new TypeError("an instant is a bigint of nanoseconds"),
      );
    }
  });

  it("writes what it reads, and reads what it writes", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: -62167219200n * SECOND, max: 253402300800n * SECOND - 1n }),
        (instant) => {
          const text = formatTimestamp(instant);
          expect(isTimestamp(text), text).toBe(true);
          expect(parseTimestamp(text)).toBe(instant);
          expect(text.endsWith("0Z") && text.includes(".")).toBe(false);
        },
      ),
      { numRuns: 5000 },
    );
    // Every day of four centuries, which is one full cycle of the calendar.
    for (let day = 0n; day < 146097n; day += 1n) {
      const instant = day * 86400n * SECOND;
      const text = formatTimestamp(instant);
      if (parseTimestamp(text) !== instant) throw new Error(`day ${day}: ${text}`);
    }
  });
});

describe(`${clause("core 9.1")} clock skew`, () => {
  it("is 300 seconds", () => {
    expect(CLOCK_SKEW).toBe(300_000_000_000n);
    const created = parseTimestamp("2026-10-30T09:05:00Z") ?? 0n;
    const now = parseTimestamp("2026-10-30T09:00:00Z") ?? 0n;
    expect(created - now).toBe(CLOCK_SKEW);
  });
});

describe(`${clause("core 1.5")} durations`, () => {
  it("reads days, hours, minutes and seconds", () => {
    expect(parseDuration("P30D")).toBe(30n * 86400n * SECOND);
    expect(parseDuration("PT15M")).toBe(900n * SECOND);
    expect(parseDuration("PT1H")).toBe(3600n * SECOND);
    expect(parseDuration("PT1S")).toBe(SECOND);
    expect(parseDuration("P1DT2H3M4S")).toBe((86400n + 7200n + 180n + 4n) * SECOND);
    expect(parseDuration("PT2H4S")).toBe(7204n * SECOND);
    expect(parseDuration("P1DT4S")).toBe(86404n * SECOND);
    expect(parseDuration("PT3M4S")).toBe(184n * SECOND);
    expect(parseDuration("P0D")).toBe(0n);
    expect(parseDuration("PT0S")).toBe(0n);
    expect(parseDuration("PT90M")).toBe(parseDuration("PT1H30M"));
    expect(parseDuration("PT36H")).toBe(parseDuration("P1DT12H"));
    expect(parseDuration("P007D")).toBe(7n * 86400n * SECOND);
  });

  it("is exact however large the numbers", () => {
    expect(parseDuration("P1000000000000000000000000000000D")).toBe(10n ** 30n * 86400n * SECOND);
    expect(parseDuration(`PT${"9".repeat(50)}S`)).toBe(BigInt("9".repeat(50)) * SECOND);
    expect(parseDuration("P9007199254740993D")).toBe(9007199254740993n * 86400n * SECOND);
  });

  it("is at most 64 characters", () => {
    expect(MAX_DURATION_LENGTH).toBe(64);
    const longest = `P${"9".repeat(62)}D`;
    expect(longest).toHaveLength(64);
    expect(isDuration(longest)).toBe(true);
    expect(parseDuration(longest)).toBe(BigInt("9".repeat(62)) * 86400n * SECOND);
    const tooLong = `P${"9".repeat(63)}D`;
    expect(isDuration(tooLong)).toBe(false);
    expect(parseDuration(tooLong)).toBeUndefined();
    // A million digits are refused at once, not multiplied out.
    const started = performance.now();
    expect(parseDuration(`P${"9".repeat(1_000_000)}D`)).toBeUndefined();
    expect(performance.now() - started).toBeLessThan(50);
  });

  it("rejects everything else", () => {
    for (const bad of [
      "P",
      "PT",
      "P1DT",
      "T1H",
      "1D",
      "P1Y",
      "P1M",
      "P1W",
      "P1Y2M3D",
      "P1H",
      "P1S",
      "PT1D",
      "P1D1H",
      "PT1M1H",
      "PT1S1M",
      "PT1H1H",
      "P1D2D",
      "P1.5D",
      "PT1.5S",
      "PT0.5H",
      "P-1D",
      "-P1D",
      "+P1D",
      "p1d",
      "P1d",
      "pt1h",
      "P 1D",
      "P1D ",
      " P1D",
      "P1D\n",
      "PD",
      "PTS",
      "PT1",
      "P1",
      "P１D",
      "",
      "30 days",
      3600,
      null,
      undefined,
      ["P1D"],
    ]) {
      expect(isDuration(bad), show(bad)).toBe(false);
      expect(parseDuration(bad), show(bad)).toBeUndefined();
    }
    for (const good of ["P30D", "PT15M", "P1DT2H3M4S"]) expect(isDuration(good)).toBe(true);
  });

  it("adds up its parts", () => {
    const part = fc.option(fc.nat(100000), { nil: undefined });
    fc.assert(
      fc.property(part, part, part, part, (days, hours, minutes, seconds) => {
        fc.pre([days, hours, minutes, seconds].some((value) => value !== undefined));
        const time =
          (hours === undefined ? "" : `${hours}H`) +
          (minutes === undefined ? "" : `${minutes}M`) +
          (seconds === undefined ? "" : `${seconds}S`);
        const text = `P${days === undefined ? "" : `${days}D`}${time === "" ? "" : `T${time}`}`;
        const expected =
          BigInt((days ?? 0) * 86400 + (hours ?? 0) * 3600 + (minutes ?? 0) * 60 + (seconds ?? 0)) *
          SECOND;
        expect(parseDuration(text), text).toBe(expected);
      }),
      { numRuns: 1000 },
    );
  });
});
