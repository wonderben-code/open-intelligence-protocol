// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { systemClock, systemRandomness } from "../src/index.ts";

describe("the clock of the machine", () => {
  it("gives the time now, in nanoseconds since the Unix epoch", () => {
    const before = BigInt(Date.now()) * 1_000_000n;
    const now = systemClock.now();
    const after = BigInt(Date.now()) * 1_000_000n;
    expect(typeof now).toBe("bigint");
    expect(now >= before && now <= after).toBe(true);
  });
});

describe("the platform's randomness", () => {
  it("gives as many bytes as were asked for, and other bytes each time", () => {
    expect(systemRandomness.bytes(0)).toStrictEqual(new Uint8Array(0));
    const one = systemRandomness.bytes(32);
    const other = systemRandomness.bytes(32);
    expect(one).toHaveLength(32);
    expect(one).not.toStrictEqual(other);
    expect(systemRandomness.bytes(65_536)).toHaveLength(65_536);
  });

  it("takes a whole number of bytes that the platform gives in one call", () => {
    for (const length of [-1, 1.5, 65_537, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => systemRandomness.bytes(length)).toThrow(TypeError);
    }
  });
});
