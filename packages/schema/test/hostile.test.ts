// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Input chosen to break the validator rather than to be rejected by it. Each
 * case here once made validation throw, hang, exhaust memory or answer with
 * megabytes; none may do so again.
 */

import { type JsonObject, positiveVectorRecords, withAmbientTrapped } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  MAX_ISSUES,
  parseSelector,
  type RecordType,
  validateExtensionRecord,
  validateProof,
  validateRecord,
  validateRecordOfType,
} from "../src/index.ts";
import { sample, sampleProof, samples } from "./fixtures.ts";

const KEY = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/** Rejected, with a bounded answer, in bounded time. */
function expectBoundedRejection(run: () => { ok: boolean; issues?: readonly unknown[] }): void {
  const started = performance.now();
  const result = run();
  expect(result.ok).toBe(false);
  expect(result.issues?.length).toBeGreaterThan(0);
  expect(result.issues?.length).toBeLessThanOrEqual(MAX_ISSUES);
  expect(JSON.stringify(result.issues).length).toBeLessThan(32_768);
  expect(performance.now() - started).toBeLessThan(5000);
}

describe("many violations in one record", () => {
  it("are reported up to a limit, however many there are", () => {
    const critical = Array.from({ length: 200_000 }, () => "a");
    expectBoundedRejection(() => validateRecord(sample("Offer", { critical })));
    expectBoundedRejection(() =>
      validateExtensionRecord({ oip: "1", type: "com.example.X", critical }),
    );
    const bad = sample("Update", { keys: [{ key: KEY }, { key: KEY }] });
    const events = Array.from({ length: 20_000 }, () => bad);
    expectBoundedRejection(() => validateRecord(sample("LogPage", { events })));
  });

  it("do not multiply the size of the input in the answer", () => {
    const badSelectors = Array.from({ length: 64 }, () => ["==", "not a selector", 1]);
    const powers = Array.from({ length: 64 }, () => ({ command: "/x/y", policy: badSelectors }));
    const roles = { ["r".repeat(100_000)]: { powers } };
    expectBoundedRejection(() => validateRecord(sample("Collective", { roles })));
    const policy = Array.from({ length: 64 }, () => ["and", badSelectors]);
    expectBoundedRejection(() => validateRecord(sample("Delegation", { policy })));
  });

  it("are answered from a deep call stack too", () => {
    const critical = Array.from({ length: 50_000 }, () => "a");
    const record = sample("Offer", { critical });
    const fromDepth = (depth: number): boolean =>
      depth === 0 ? validateRecord(record).ok : fromDepth(depth - 1);
    expect(fromDepth(3000)).toBe(false);
  });
});

describe("a type name that is not a record type", () => {
  const anything = "a string, not a record";

  it.each([
    "constructor",
    "toString",
    "valueOf",
    "__proto__",
    "hasOwnProperty",
    "Merge",
    "Proof",
    "ExtensionRecord",
    "Policy",
    "",
  ])("%j never reaches a validator through validateRecordOfType", (name) => {
    for (const value of [anything, samples.Intent, { oip: "1", type: "Genesis" }, {}]) {
      const result = validateRecordOfType(name as RecordType, value);
      expect(result.ok).toBe(false);
    }
  });

  it("is rejected whatever it is", () => {
    for (const name of [undefined, null, 7, {}, ["Intent"], Symbol("Intent")]) {
      expect(validateRecordOfType(name as RecordType, samples.Intent).ok).toBe(false);
    }
  });
});

describe("values that are not JSON", () => {
  const rejected = (member: unknown) =>
    expectBoundedRejection(() => validateRecord(sample("Intent", { futureMember: member })));

  it("an array with millions of holes is rejected without reading them", () => {
    rejected(new Array(2 ** 27));
    rejected([new Array(2 ** 30)]);
    const holed: unknown[] = [1, 2, 3];
    holed.length = 5;
    rejected(holed);
  });

  it("a structure that shares its parts is rejected without being walked exponentially", () => {
    let shared: unknown = "leaf";
    for (let i = 0; i < 60; i++) shared = [shared, shared];
    rejected(shared);
    let wide: unknown = "leaf";
    for (let i = 0; i < 60; i++) wide = { a: wide, b: wide };
    rejected(wide);
  });

  it("undefined, bigint, symbols and functions are rejected wherever they are", () => {
    for (const value of [undefined, 10n, Symbol("x"), () => 1]) {
      rejected(value);
      rejected([value]);
      rejected({ deep: { deeper: [value] } });
    }
  });

  it("objects that are not plain are rejected", () => {
    class Custom {
      member = 1;
    }
    for (const value of [new Date(0), new Map(), new Set(), new Custom(), /x/, new Uint8Array(4)]) {
      rejected(value);
      rejected([value]);
    }
    rejected({ [Symbol("hidden")]: 1 });
  });

  it("a member the limits cannot see is rejected, not passed on to the schema", () => {
    let deep: unknown = ["==", ".a", 1];
    for (let i = 0; i < 100_000; i++) deep = ["not", deep];
    const hidden = sample("Delegation");
    Object.defineProperty(hidden, "policy", { value: [deep], enumerable: false });
    expectBoundedRejection(() => validateRecord(hidden));

    const inherited = Object.create(sample("Delegation", { policy: [deep] })) as JsonObject;
    expectBoundedRejection(() => validateRecord(inherited));
    expectBoundedRejection(() => validateRecordOfType("Delegation", inherited));
  });

  it("an accessor is rejected without being called", () => {
    let calls = 0;
    const record = sample("Intent");
    Object.defineProperty(record, "want", {
      enumerable: true,
      get() {
        calls++;
        return "text";
      },
    });
    expectBoundedRejection(() => validateRecord(record));
    const nested = sample("Intent", { futureMember: {} });
    Object.defineProperty(nested["futureMember"], "x", { enumerable: true, get: () => 1.5 });
    expectBoundedRejection(() => validateRecord(nested));
    expect(calls).toBe(0);
  });

  it("an object that throws when read gives a rejection, never an exception", () => {
    const trap = () => {
      throw new Error("no");
    };
    const hostile = new Proxy(sample("Intent"), { get: trap, ownKeys: trap, getPrototypeOf: trap });
    expect(validateRecord(hostile).ok).toBe(false);
    expect(validateRecordOfType("Intent", hostile).ok).toBe(false);
    expect(validateExtensionRecord(hostile).ok).toBe(false);
    expect(validateProof(hostile).ok).toBe(false);
    const inner = new Proxy({}, { ownKeys: trap, getOwnPropertyDescriptor: trap });
    expect(validateRecord(sample("Intent", { futureMember: inner })).ok).toBe(false);
    expect(validateProof(sampleProof({ authority: [inner] })).ok).toBe(false);
  });
});

describe("selectors of hostile size", () => {
  it("parse in one pass, whatever their length", () => {
    const name = "n".repeat(8 * 1024 * 1024);
    expect(parseSelector(`["${name}"]`)).toEqual([name]);
    expect(parseSelector(`["${"\\\\".repeat(1024 * 1024)}"]`)?.[0]).toHaveLength(1024 * 1024);
    expect(parseSelector(`["${name}`)).toBeUndefined();
    expect(parseSelector(`.${"a".repeat(1024 * 1024)}`)?.[0]).toHaveLength(1024 * 1024);
    expect(parseSelector(".a".repeat(200_000))).toHaveLength(200_000);
  });

  it("give an index beyond any array one fixed value, never Infinity", () => {
    expect(parseSelector(`[1${"0".repeat(1024 * 1024)}]`)).toEqual([Number.MAX_SAFE_INTEGER]);
    expect(parseSelector("[9007199254740993]")).toEqual([Number.MAX_SAFE_INTEGER]);
    expect(parseSelector("[999999999999999]")).toEqual([999999999999999]);
  });

  it("are rejected in a policy with a short message", () => {
    const selector = `["${"n".repeat(1024 * 1024)}`;
    expectBoundedRejection(() =>
      validateRecord(sample("Delegation", { policy: [["==", selector, 1]] })),
    );
  });
});

describe("purity", () => {
  it("reads no clock and no randomness, whatever it validates", () => {
    const inputs: unknown[] = [
      ...positiveVectorRecords().map((entry) => entry.record),
      ...Object.values(samples),
      sample("Delegation", { delegate: samples.Delegation["author"] }),
      sample("Offer", { critical: ["missing"] }),
      sample("Intent", { futureMember: 1.5 }),
      { oip: "1", type: "com.example.Escrow" },
      "not a record",
    ];
    const verdicts = withAmbientTrapped(() =>
      inputs.map((input) => [
        validateRecord(input).ok,
        validateExtensionRecord(input).ok,
        validateProof(input).ok,
        parseSelector(input) !== undefined,
      ]),
    );
    expect(verdicts).toHaveLength(inputs.length);
    expect(verdicts.filter(([record]) => record === true).length).toBeGreaterThan(70);
  });
});
