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

  it(`${clause("core 1.9")} accepts nesting up to 64 deep and rejects anything deeper`, () => {
    // The record is level 1 and the member's value starts at level 2.
    expect(validateRecord(sample("Intent", { futureMember: nest(MAX_DEPTH - 1) })).ok).toBe(true);
    const result = validateRecord(sample("Intent", { futureMember: nest(MAX_DEPTH) }));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.issues[0].clause).toBe("core 1.9");
    expect(MAX_DEPTH).toBe(64);
    expect(IMPLEMENTATION_LIMIT).toBe("implementation limit");
  });

  it(`${clause("core 1.9")} lets a container carry records that are each as deep as the limit`, () => {
    const depthOfIssue = (record: JsonObject) => {
      const result = validateRecord(record);
      return result.ok ? "ok" : result.issues.map((issue) => `${issue.clause} ${issue.path}`);
    };
    // An identity event with an unknown member, the whole event nesting `depth` deep.
    const event = (depth: number) => sample("Genesis", { futureMember: nest(depth - 1) });
    for (const depth of [61, 62, 63, MAX_DEPTH]) {
      expect(depthOfIssue(event(depth)), `alone, ${depth}`).toBe("ok");
      expect(depthOfIssue(sample("Bundle", { log: [event(depth)] })), `Bundle, ${depth}`).toBe(
        "ok",
      );
      expect(depthOfIssue(sample("LogPage", { events: [event(depth)] })), `LogPage, ${depth}`).toBe(
        "ok",
      );
      expect(
        depthOfIssue(sample("DuplicityEvidence", { pairs: [[event(depth), event(depth)]] })),
        `DuplicityEvidence, ${depth}`,
      ).toBe("ok");
    }
    // One level more is too deep, alone or carried, and the issue says which record.
    const tooDeep = event(MAX_DEPTH + 1);
    expect(depthOfIssue(tooDeep)).toEqual(["core 1.9 "]);
    expect(depthOfIssue(sample("LogPage", { events: [event(10), tooDeep] }))).toEqual([
      "core 1.9 /events/1",
    ]);
    expect(depthOfIssue(sample("Bundle", { log: [tooDeep] }))).toEqual(["core 1.9 /log/0"]);
    // In DuplicityEvidence a record stands one level further down, past what any container allows.
    expect(depthOfIssue(sample("DuplicityEvidence", { pairs: [[event(10), tooDeep]] }))).toEqual([
      "core 1.9 ",
    ]);
    const deepEntry = sample("Entry", { futureMember: nest(MAX_DEPTH - 1) });
    expect(depthOfIssue(sample("FeedPage", { entries: [deepEntry] }))).toBe("ok");
    expect(
      depthOfIssue(sample("FeedPage", { entries: [sample("Entry", { x: nest(MAX_DEPTH) })] })),
    ).toEqual(["core 1.9 /entries/0"]);
    // Far deeper than any container allows is rejected before anything else is looked at.
    expect(depthOfIssue(sample("LogPage", { events: [event(MAX_DEPTH + 5)] }))).toEqual([
      "core 1.9 ",
    ]);
  });

  it(`${clause("core 1.9")} applies the limit to a container without the records it carries`, () => {
    const verdict = (record: JsonObject) => {
      const result = validateRecord(record);
      return result.ok ? "ok" : result.issues.map((issue) => `${issue.clause} ${issue.path}`);
    };
    // The container's own unknown member may be as deep as any record's, and no deeper.
    expect(verdict(sample("LogPage", { futureMember: nest(MAX_DEPTH - 1) }))).toBe("ok");
    expect(verdict(sample("LogPage", { futureMember: nest(MAX_DEPTH) }))).toEqual(["core 1.9 "]);
    expect(verdict(sample("Bundle", { futureMember: nest(MAX_DEPTH) }))).toEqual(["core 1.9 "]);
    // A record that only carries another is not a container: the limit is on the whole.
    const packet = sample("Packet", { futureMember: nest(MAX_DEPTH - 1) });
    expect(verdict(packet)).toBe("ok");
    expect(verdict(sample("Forwarded", { packet }))).toEqual(["core 1.9 "]);
  });

  it(`${clause("core 1.9")} counts a proof from its place in a record`, () => {
    // A proof stands at depth 3: the record, its proof array, the proof.
    const deepest = sampleProof({ authority: [nest(MAX_DEPTH - 4)] });
    expect(validateProof(deepest).ok).toBe(true);
    expect(validateRecord(sample("Intent", { proof: [deepest] })).ok).toBe(true);
    const tooDeep = sampleProof({ authority: [nest(MAX_DEPTH - 3)] });
    const result = validateProof(tooDeep);
    expect(!result.ok && result.issues[0].clause).toBe("core 1.9");
    expect(validateRecord(sample("Intent", { proof: [tooDeep] })).ok).toBe(false);
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
