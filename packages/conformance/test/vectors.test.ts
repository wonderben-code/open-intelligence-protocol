// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The golden vectors, run against the reference implementation. A check or a
 * case the implementation cannot answer yet is listed as `todo`, so the
 * output shows how far the build has come. `pnpm spec:coverage` fails if a
 * kind of case is still pending after the milestone that owes it.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { parseJson } from "@oip/core";
import { describe, expect, it } from "vitest";

import {
  CASE_KINDS,
  loadVectors,
  POSITIVE_CHECKS,
  referenceAdapter,
  runCase,
  SECTIONS,
  VECTORS_DIRECTORY,
} from "../src/index.ts";

const vectors = loadVectors();

describe("vectors: positive", () => {
  for (const check of POSITIVE_CHECKS) {
    const name = `${check.name} (${check.milestone})`;
    const mismatches = check.run(referenceAdapter, vectors);
    if (mismatches === undefined) {
      it.todo(name);
    } else {
      it(name, () => {
        expect(mismatches).toEqual([]);
      });
    }
  }
});

for (const section of SECTIONS) {
  for (const kind of CASE_KINDS) {
    const cases = vectors[section].filter((entry) => entry.kind === kind);
    if (cases.length === 0) continue;
    describe(`vectors: ${section}: ${kind}`, () => {
      for (const vectorCase of cases) {
        // Pending: the adapter has no method for this kind of case, or says
        // that it does not judge this one yet.
        const result = runCase(referenceAdapter, vectors, section, vectorCase);
        if (result.outcome === "pending") {
          it.todo(vectorCase.name);
          continue;
        }
        it(vectorCase.name, () => {
          expect(result.detail).toBeUndefined();
          expect(result.outcome).toBe("pass");
        });
      }
    });
  }
}

describe("the vectors file", () => {
  it("is for the specification revision this implementation builds", () => {
    expect(vectors.spec_revision).toBe("2026-11-17");
  });

  it("has the cases its README counts", () => {
    expect(vectors.valid).toHaveLength(48);
    expect(vectors.negative).toHaveLength(181);
    expect(vectors.controls).toHaveLength(125);
  });

  it("holds nothing a strict reader of JSON refuses, apart from its depth", () => {
    // No float, no unpaired surrogate and no noncharacter anywhere in the file: the
    // cases about such things hold them as escapes inside a string. Only its depth
    // is beyond a record's, because it carries records that nest as deep as one may.
    const text = readFileSync(join(VECTORS_DIRECTORY, "vectors.json"), "utf8");
    expect(text.isWellFormed()).toBe(true);
    const noncharacter = (code: number) =>
      (code >= 0xfdd0 && code <= 0xfdef) || (code & 0xfffe) === 0xfffe;
    let strings = 0;
    let numbers = 0;
    const walk = (value: unknown): void => {
      if (typeof value === "string") {
        strings++;
        expect(value.isWellFormed(), value.slice(0, 40)).toBe(true);
        for (const character of value) {
          expect(noncharacter(character.codePointAt(0) ?? 0), value.slice(0, 40)).toBe(false);
        }
      } else if (typeof value === "number") {
        numbers++;
        expect(Number.isSafeInteger(value), String(value)).toBe(true);
      } else if (typeof value === "object" && value !== null) {
        for (const [name, member] of Object.entries(value)) {
          if (!Array.isArray(value)) walk(name);
          walk(member);
        }
      }
    };
    walk(JSON.parse(text));
    expect(strings).toBeGreaterThan(10_000);
    expect(numbers).toBeGreaterThan(100);
    // The reader of the reference implementation agrees: depth is its one objection.
    const parsed = parseJson(text);
    expect(!parsed.ok && parsed.issues.map((issue) => issue.clause)).toEqual(["core 1.9"]);
  });

  it("pairs every control with a negative case of the same name and kind", () => {
    for (const control of vectors.controls) {
      const negative = vectors.negative.find((entry) => entry.name === control.name);
      expect(negative?.kind, control.name).toBe(control.kind);
    }
  });
});
