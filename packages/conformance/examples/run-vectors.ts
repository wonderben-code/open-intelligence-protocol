// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { type ConformanceAdapter, loadVectors, runVectors, tally } from "@oip/conformance";

/**
 * Runs the golden vectors against an implementation that so far only knows
 * whether a record is well formed, and reports how it did.
 */
export function report(recordIsWellFormed: (record: unknown) => boolean): string[] {
  const adapter: ConformanceAdapter = { name: "my implementation", recordIsWellFormed };
  const results = runVectors(adapter, loadVectors());
  const { pass, fail, pending } = tally(results);
  return [
    `${adapter.name}: ${pass} passed, ${fail} failed, ${pending} pending`,
    ...results
      .filter((result) => result.outcome === "fail")
      .map((result) => `FAIL ${result.section} ${result.name}: ${result.detail ?? ""}`),
  ];
}
