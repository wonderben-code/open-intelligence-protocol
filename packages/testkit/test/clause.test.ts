// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  citedClauses,
  clause,
  specClauses,
  specRevision,
  withAmbientTrapped,
} from "../src/index.ts";

describe("clause", () => {
  it("formats one or more citations for a test name", () => {
    expect(clause("core 4.4")).toBe("[core 4.4]");
    expect(clause("L1 6.4", "L2 8.3", "L0 2.2")).toBe("[L1 6.4] [L2 8.3] [L0 2.2]");
  });

  it("accepts a section that has no numbered paragraphs", () => {
    expect(clause("core 11")).toBe("[core 11]");
    expect(clause("L1 19")).toBe("[L1 19]");
  });

  it("throws on an ID that is not a clause, naming the revision", () => {
    expect(() => clause("core 99.9")).toThrow(specRevision);
    expect(() => clause("L3 1.1")).toThrow(/not a clause/);
    expect(() => clause("core 4.4 ")).toThrow(/not a clause/);
  });

  it("reads citations back out of a test name", () => {
    const name = `${clause("L1 11.1", "core 8.3")} rejects it`;
    expect(citedClauses(name)).toEqual(["L1 11.1", "core 8.3"]);
    expect(citedClauses("no citation here [not one]")).toEqual([]);
  });
});

describe("the clause list", () => {
  it("covers all four specification documents", () => {
    const documents = new Set([...specClauses.values()].map((entry) => entry.document));
    expect([...documents].sort()).toEqual(["L0", "L1", "L2", "core"]);
  });

  it("knows the level of a clause from its key words", () => {
    expect(specClauses.get("core 4.4")?.level).toBe("MUST");
    expect(specClauses.get("core 5.7")?.level).toBe("SHOULD");
    expect(specClauses.get("core 2.1")?.level).toBe("none");
  });
});

describe("withAmbientTrapped", () => {
  it("returns what pure code returns, and restores the clock afterwards", () => {
    const before = Date.now;
    expect(withAmbientTrapped(() => 1 + 1)).toBe(2);
    expect(withAmbientTrapped(() => new Date(0).toISOString())).toBe("1970-01-01T00:00:00.000Z");
    expect(Date.now).toBe(before);
    expect(typeof Date.now()).toBe("number");
    expect(Math.random()).toBeLessThan(1);
  });

  const impure: [name: string, run: () => unknown][] = [
    ["Date.now()", () => Date.now()],
    ["new Date()", () => new Date()],
    ["Date()", () => (Date as unknown as () => string)()],
    ["Math.random()", () => Math.random()],
    ["performance.now()", () => performance.now()],
    ["crypto.randomUUID()", () => crypto.randomUUID()],
    ["crypto.getRandomValues()", () => crypto.getRandomValues(new Uint8Array(4))],
    ["Date.now()", () => globalThis.Date.now()],
    ["new Date()", () => Reflect.construct(Date, []) as Date],
  ];

  it.each(impure)("throws when the code reaches %s", (name, run) => {
    expect(() => withAmbientTrapped(run)).toThrow(`pure code reached ambient state: ${name}`);
  });

  it("reports a trap the code reached even if the code caught the exception", () => {
    const swallowing = () => {
      try {
        return Date.now();
      } catch {
        return 0;
      }
    };
    expect(() => withAmbientTrapped(swallowing)).toThrow(/Date\.now\(\)/);
    expect(typeof Date.now()).toBe("number");
  });
});
