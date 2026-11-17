// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause, type JsonObject } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  IMPLEMENTATION_LIMIT,
  MAX_DEPTH,
  MAX_SAFE_INTEGER,
  RECORD_TYPES,
  validateProof,
  validateRecord,
} from "../src/index.ts";
import { codePointLength, deepEqual } from "../src/runtime.ts";
import { sample, sampleProof, samples } from "./fixtures.ts";

function nest(depth: number): unknown {
  let value: unknown = "leaf";
  for (let i = 0; i < depth; i++) value = i % 2 === 0 ? [value] : { inner: value };
  return value;
}

describe("limits on every value", () => {
  it(`${clause("core 1.2")} rejects a number with a fraction or outside the safe range, wherever it is`, () => {
    for (const bad of [
      1.5,
      MAX_SAFE_INTEGER + 1,
      -MAX_SAFE_INTEGER - 1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      1e300,
    ]) {
      const result = validateRecord(sample("Intent", { futureMember: { deep: [0, bad] } }));
      expect(result.ok, String(bad)).toBe(false);
      if (!result.ok) expect(result.issues[0].clause).toBe("core 1.2");
    }
    for (const good of [0, -0, 1, -1, MAX_SAFE_INTEGER, -MAX_SAFE_INTEGER, 1.0, 1e2]) {
      expect(validateRecord(sample("Intent", { futureMember: [good] })).ok, String(good)).toBe(
        true,
      );
    }
  });

  it(`${clause("core 1.1")} rejects an unpaired surrogate in a string or in a member name`, () => {
    for (const bad of ["\ud800", "a\udc00", "\udc00\ud800", "ok \ud83d"]) {
      for (const record of [
        sample("Intent", { want: bad }),
        sample("Intent", { futureMember: [{ deep: bad }] }),
        sample("Intent", { [bad]: 1 }),
        sample("Intent", { futureMember: { [bad]: 1 } }),
      ]) {
        const result = validateRecord(record);
        expect(result.ok).toBe(false);
        if (!result.ok) expect(result.issues[0].clause).toBe("core 1.1");
      }
    }
    expect(validateRecord(sample("Intent", { want: "paired \ud83d\ude00 and 𝛑" })).ok).toBe(true);
  });

  it("accepts nesting up to the implementation limit and rejects anything deeper", () => {
    // The record is level 1 and the member's value starts at level 2.
    expect(validateRecord(sample("Intent", { futureMember: nest(MAX_DEPTH - 1) })).ok).toBe(true);
    const result = validateRecord(sample("Intent", { futureMember: nest(MAX_DEPTH) }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues[0].clause).toBe(IMPLEMENTATION_LIMIT);
  });

  it("rejects hostile nesting without exhausting the stack", () => {
    expect(validateRecord(sample("Intent", { futureMember: nest(200_000) })).ok).toBe(false);
    expect(validateRecord(sample("Delegation", { policy: nest(200_000) })).ok).toBe(false);
    expect(validateProof(sampleProof({ authority: nest(200_000) })).ok).toBe(false);
  });

  it("rejects a value that refers to itself", () => {
    const record = sample("Intent");
    record["self"] = record;
    expect(validateRecord(record).ok).toBe(false);
  });
});

describe("validateRecord", () => {
  it("never throws, whatever it is given", () => {
    fc.assert(
      fc.property(
        fc.anything({ withBigInt: true, withDate: true, withMap: true, withSet: true }),
        (value) => {
          expect(typeof validateRecord(value).ok).toBe("boolean");
          expect(typeof validateProof(value).ok).toBe("boolean");
        },
      ),
      { numRuns: 2000 },
    );
  });

  it("never throws on a record of a known type with arbitrary members", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...RECORD_TYPES),
        fc.dictionary(fc.string(), fc.jsonValue(), { maxKeys: 12 }),
        (type, members) => {
          const result = validateRecord({ ...members, oip: "1", type });
          expect(typeof result.ok).toBe("boolean");
          if (!result.ok) {
            expect(result.issues.length).toBeGreaterThan(0);
            for (const issue of result.issues) {
              expect(issue.message).not.toBe("");
              expect(issue.clause).not.toBe("");
            }
          }
        },
      ),
      { numRuns: 3000 },
    );
  });

  it("still accepts a sample after any one member is replaced only if the value is still well formed", () => {
    // Replacing a required, typed member with an arbitrary JSON value of another type must fail.
    fc.assert(
      fc.property(
        fc.constantFrom(...RECORD_TYPES),
        fc.constantFrom(null, true, 12, [], {}),
        (type, junk) => {
          const record = sample(type);
          for (const member of ["oip", "type"]) {
            expect(validateRecord({ ...record, [member]: junk }).ok).toBe(false);
          }
        },
      ),
    );
  });

  it("cites the clause that defines the record type when the schema rejects", () => {
    const result = validateRecord(sample("Checkpoint", { size: "two" }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.issues[0]).toMatchObject({ path: "/size", clause: "L1 10.5" });
    }
  });

  it("treats a member called __proto__ as any other member, and never changes a prototype", () => {
    // JSON.parse makes `__proto__` an own member; it does not set the prototype.
    const hidden = JSON.parse('{"__proto__": {"oip": "1", "type": "Session"}}') as JsonObject;
    expect(validateRecord(hidden).ok).toBe(false);
    const extra = JSON.parse(
      JSON.stringify(samples.Session).replace(/}$/, ',"__proto__": {"polluted": true}}'),
    ) as JsonObject;
    expect(Object.keys(extra)).toContain("__proto__");
    expect(validateRecord(extra).ok).toBe(true);
    expect(({} as JsonObject)["polluted"]).toBeUndefined();
  });
});

describe("string lengths", () => {
  it(`${clause("core 1.8")} counts lengths in code points, not UTF-16 code units`, () => {
    expect(codePointLength("")).toBe(0);
    expect(codePointLength("abc")).toBe(3);
    expect(codePointLength("é")).toBe(1);
    expect(codePointLength("𝛑")).toBe(1);
    expect("𝛑".length).toBe(2);
    expect(codePointLength("a𝛑b𝛑")).toBe(4);
    // Unpaired surrogates count one each.
    expect(codePointLength("\ud800")).toBe(1);
    expect(codePointLength("\ud800a")).toBe(2);
    expect(codePointLength("\udc00\ud800")).toBe(2);
    fc.assert(
      fc.property(fc.string({ unit: "grapheme" }), (value) => {
        // Array.from walks a string by code point.
        expect(codePointLength(value)).toBe(Array.from(value).length);
      }),
    );
  });

  it(`${clause("core 1.8", "L1 12.1")} applies the nonce limits in code points`, () => {
    // Eight astral characters are 16 code units but 8 characters.
    expect(validateRecord(sample("Packet", { nonce: "𝛑".repeat(8) })).ok).toBe(true);
    expect(validateRecord(sample("Packet", { nonce: "𝛑".repeat(7) })).ok).toBe(false);
    expect(validateRecord(sample("Packet", { nonce: "𝛑".repeat(64) })).ok).toBe(true);
    expect(validateRecord(sample("Packet", { nonce: "𝛑".repeat(65) })).ok).toBe(false);
  });
});

describe("deepEqual", () => {
  it("compares JSON values member for member, whatever the member order", () => {
    expect(deepEqual({ a: 1, b: [1, { c: null }] }, { b: [1, { c: null }], a: 1 })).toBe(true);
    expect(deepEqual({ a: 1 }, { a: 1, b: undefined })).toBe(false);
    expect(deepEqual({ a: 1 }, { b: 1 })).toBe(false);
    expect(deepEqual([1, 2], [2, 1])).toBe(false);
    expect(deepEqual([1, 2], [1, 2, 3])).toBe(false);
    expect(deepEqual([], {})).toBe(false);
    expect(deepEqual(null, {})).toBe(false);
    expect(deepEqual({}, null)).toBe(false);
    expect(deepEqual("1", 1)).toBe(false);
    expect(deepEqual(0, 0)).toBe(true);
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(deepEqual(value, structuredClone(value))).toBe(true);
      }),
    );
    fc.assert(
      fc.property(fc.jsonValue(), fc.jsonValue(), (a, b) => {
        expect(deepEqual(a, b)).toBe(deepEqual(b, a));
      }),
    );
  });
});
