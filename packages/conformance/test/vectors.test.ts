// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The golden vectors, run against the reference implementation. A check or a
 * case the implementation cannot answer yet is listed as `todo`, so the
 * output shows how far the build has come. `pnpm spec:coverage` fails if a
 * kind of case is still pending after the milestone that owes it.
 */

import { describe, expect, it } from "vitest";

import {
  CASE_KINDS,
  loadVectors,
  METHOD_FOR_KIND,
  POSITIVE_CHECKS,
  referenceAdapter,
  runCase,
  SECTIONS,
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
        if (referenceAdapter[METHOD_FOR_KIND[kind]] === undefined) {
          it.todo(vectorCase.name);
          continue;
        }
        it(vectorCase.name, () => {
          const result = runCase(referenceAdapter, vectors, section, vectorCase);
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
    expect(vectors.valid).toHaveLength(15);
    expect(vectors.negative).toHaveLength(72);
    expect(vectors.controls).toHaveLength(22);
  });

  it("pairs every control with a negative case of the same name and kind", () => {
    for (const control of vectors.controls) {
      const negative = vectors.negative.find((entry) => entry.name === control.name);
      expect(negative?.kind, control.name).toBe(control.kind);
    }
  });
});
