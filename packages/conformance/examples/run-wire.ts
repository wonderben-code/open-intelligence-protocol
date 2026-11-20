// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { runWire, type WireOptions, type WireProfile } from "@oip/conformance";

/**
 * Runs a profile against an implementation over the wire, and reports how
 * it did: a line with the sum, and a line for each check that failed.
 */
export async function report(profile: WireProfile, options: WireOptions): Promise<string[]> {
  const { checks, summary, conforms } = await runWire(profile, options);
  return [
    `the ${profile} at ${options.origin ?? options.target}: ${summary.pass} passed, ${summary.fail} failed, ` +
      `${summary.skipped} skipped, ${summary["not-applicable"]} not applicable: ` +
      (conforms ? "it conforms" : "not shown to conform"),
    ...checks
      .filter((check) => check.outcome === "fail")
      .map((check) => `FAIL ${check.id} [${check.clauses.join(", ")}]: ${check.detail ?? ""}`),
  ];
}
