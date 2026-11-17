// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { patterns } from "../src/index.ts";

// Ajv compiles patterns with the `u` flag, so the tests do too.
const re = Object.fromEntries(
  Object.entries(patterns).map(([name, source]) => [name, new RegExp(source, "u")]),
) as Record<keyof typeof patterns, RegExp>;

describe("patterns", () => {
  it("avoid lookaround and back-references, so that linear-time engines accept them", () => {
    for (const [name, source] of Object.entries(patterns)) {
      expect(source, name).not.toMatch(/\(\?[=!<]|\\[1-9]/);
      expect(source.startsWith("^"), name).toBe(true);
    }
  });
});

describe("timestamps", () => {
  // The pattern exactly as core 1.4 writes it.
  const SPEC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$/;

  // An independent check that the fields name a real date and time.
  function isReal(value: string): boolean {
    const [year, month, day, hour, minute, second] = (value.match(/[0-9]+/g) ?? []).map(Number) as [
      number,
      number,
      number,
      number,
      number,
      number,
    ];
    if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) return false;
    const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1] ?? 0;
    return day <= days;
  }

  const two = (max: number) => fc.integer({ min: 0, max }).map((n) => String(n).padStart(2, "0"));
  const timestampLike = fc
    .tuple(
      fc.integer({ min: 0, max: 9999 }).map((n) => String(n).padStart(4, "0")),
      two(14),
      two(33),
      two(25),
      two(61),
      two(61),
      fc.option(fc.stringMatching(/^[0-9]{1,9}$/), { nil: undefined }),
    )
    .map(
      ([y, mo, d, h, mi, s, f]) =>
        `${y}-${mo}-${d}T${h}:${mi}:${s}${f === undefined ? "" : `.${f}`}Z`,
    );

  it(`${clause("core 1.4")} accepts exactly the strings that match the specification's pattern and name a real date and time`, () => {
    fc.assert(
      fc.property(timestampLike, (value) => {
        expect(SPEC.test(value)).toBe(true);
        expect(re.timestamp.test(value)).toBe(isReal(value));
      }),
      { numRuns: 5000 },
    );
  });

  it(`${clause("core 1.4")} never accepts a string the specification's pattern rejects`, () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.string(),
          timestampLike.map((value) => value.replace("Z", "")),
          timestampLike.map((value) => ` ${value}`),
        ),
        (value) => {
          if (!SPEC.test(value)) expect(re.timestamp.test(value)).toBe(false);
        },
      ),
      { numRuns: 2000 },
    );
  });

  it(`${clause("core 1.4")} knows the leap years`, () => {
    for (const [value, expected] of [
      ["2024-02-29T00:00:00Z", true],
      ["2026-02-29T00:00:00Z", false],
      ["2000-02-29T00:00:00Z", true],
      ["1900-02-29T00:00:00Z", false],
      ["2100-02-29T00:00:00Z", false],
      ["2400-02-29T00:00:00Z", true],
      ["2026-04-31T00:00:00Z", false],
      ["2026-12-31T23:59:59.999999999Z", true],
      ["2026-10-30T09:00:00.Z", false],
      ["２０２６-10-30T09:00:00Z", false],
    ] as const) {
      expect(re.timestamp.test(value), value).toBe(expected);
    }
  });
});

describe("durations", () => {
  // The pattern exactly as core 1.5 writes it, with its lookaheads.
  const SPEC = /^P(?!$)([0-9]+D)?(T(?=[0-9])([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$/;

  const part = (unit: string) =>
    fc.option(
      fc.integer({ min: 0, max: 99999 }).map((n) => `${n}${unit}`),
      { nil: "" },
    );
  const durationLike = fc
    .tuple(
      fc.constantFrom("P", "", "p"),
      part("D"),
      fc.constantFrom("T", "", "T"),
      part("H"),
      part("M"),
      part("S"),
      fc.constantFrom("", "", "", "X", "1"),
    )
    .map((parts) => parts.join(""));

  it(`${clause("core 1.5")} accepts exactly the strings the specification's pattern accepts`, () => {
    fc.assert(
      fc.property(fc.oneof(durationLike, fc.string()), (value) => {
        expect(re.duration.test(value)).toBe(SPEC.test(value));
      }),
      { numRuns: 5000 },
    );
    for (const value of [
      "P30D",
      "PT15M",
      "P1DT2H3M4S",
      "PT0S",
      "P",
      "PT",
      "P1D T1H",
      "PT1S1M",
      "P1H",
    ]) {
      expect(re.duration.test(value), value).toBe(SPEC.test(value));
    }
  });
});

describe("decimals", () => {
  it(`${clause("core 1.3")} accepts decimal strings and nothing that only looks like one`, () => {
    for (const value of ["0", "400", "-12.50", "0.001", "500.01"]) {
      expect(re.decimal.test(value), value).toBe(true);
    }
    for (const value of [
      "1,000",
      "1e2",
      " 400 ",
      "-Infinity",
      "４００",
      "01",
      ".5",
      "5.",
      "+5",
      "",
      "NaN",
      "0x10",
      "1_000",
    ]) {
      expect(re.decimal.test(value), value).toBe(false);
      expect(re.amount.test(value), value).toBe(false);
    }
  });

  it(`${clause("core 1.3")} never accepts a negative amount`, () => {
    expect(re.amount.test("0")).toBe(true);
    expect(re.amount.test("120.00")).toBe(true);
    expect(re.amount.test("-0")).toBe(false);
    expect(re.amount.test("-1")).toBe(false);
  });

  it("accepts scores from 0 to 1 only", () => {
    for (const value of ["0", "1", "0.5", "1.0", "0.999", "1.000"])
      expect(re.unitDecimal.test(value), value).toBe(true);
    for (const value of ["1.1", "2", "-0.1", "1.01", ".5", "01"])
      expect(re.unitDecimal.test(value), value).toBe(false);
  });
});

describe("identifiers and references", () => {
  const CID = "bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna";

  it(`${clause("core 3.2")} accepts only the canonical spelling of a content ID`, () => {
    expect(re.contentId.test(CID)).toBe(true);
    expect(re.contentId.test(CID.toUpperCase())).toBe(false);
    expect(re.contentId.test(`${CID.slice(0, -1)}b`)).toBe(false);
    expect(re.contentId.test(`${CID}a`)).toBe(false);
    expect(re.contentId.test(CID.slice(0, -1))).toBe(false);
    expect(re.contentId.test(`bciqq${CID.slice(5)}`)).toBe(false);
    expect(re.contentId.test(`bafy${CID.slice(4)}`)).toBe(false);
    expect(re.contentId.test(`${CID.slice(0, 20)}1${CID.slice(21)}`)).toBe(false);
  });

  it(`${clause("core 6.1")} follows the reference grammar`, () => {
    const address = `did:oip:${CID}`;
    const key = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    expect(re.mindAddress.test(address)).toBe(true);
    expect(re.mindAddress.test(`did:OIP:${CID}`)).toBe(false);
    expect(re.versionId.test(`0-${CID}`)).toBe(true);
    expect(re.versionId.test(`12-${CID}`)).toBe(true);
    expect(re.versionId.test(`012-${CID}`)).toBe(false);
    expect(re.versionedMind.test(`${address}?versionId=3-${CID}`)).toBe(true);
    expect(re.keyRef.test(`${address}?versionId=3-${CID}#${key}`)).toBe(true);
    expect(re.keyRef.test(`${address}?versionId=3-${CID}#z0OIl`)).toBe(false);
    expect(re.controlKeyRef.test(`did:key:${key}#${key}`)).toBe(true);
    expect(re.recordRef.test(`${address}/${CID}`)).toBe(true);
    expect(re.recordRef.test(`${address}#${CID}`)).toBe(false);
    expect(re.recordRef.test(`${address}/${CID}/`)).toBe(false);
  });

  it(`${clause("core 4.2")} checks the prefix and length of a Multikey`, () => {
    const ed = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const x = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
    expect(re.ed25519Multikey.test(ed)).toBe(true);
    expect(re.x25519Multikey.test(x)).toBe(true);
    expect(re.ed25519Multikey.test(x)).toBe(false);
    expect(re.x25519Multikey.test(ed)).toBe(false);
    expect(re.ed25519Multikey.test(ed.slice(0, -1))).toBe(false);
    expect(re.ed25519Multikey.test(`${ed}a`)).toBe(false);
    expect(re.ed25519Multikey.test(ed.replace("z", "u"))).toBe(false);
  });

  it(`${clause("L1 11.2")} follows the command syntax`, () => {
    for (const value of ["/oip/send", "/x402/pay", "/a", "/a.b/c_d/e-f"])
      expect(re.command.test(value), value).toBe(true);
    for (const value of ["", "/", "oip/send", "/oip/", "/oip//send", "/oip/sign/*", "/a b"])
      expect(re.command.test(value), value).toBe(false);
    expect(re.oipCommandSpace.test("/oip")).toBe(true);
    expect(re.oipCommandSpace.test("/oip/anything")).toBe(true);
    expect(re.oipCommandSpace.test("/oipx")).toBe(false);
  });
});
