// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Validation sits in front of every verification, so its cost is part of
 * the budget "verify a record with two proofs: 2 ms median" (BUILD.md 3.8).
 * M1 measures that budget; this benchmark shows what validation takes of it.
 */

import { positiveVectorRecords } from "@oip/testkit";
import { describe, test } from "vitest";

import { validateProof, validateRecord } from "../src/index.ts";

const records = positiveVectorRecords();
const pick = (name: string) => {
  const found = records.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`the vectors have no record called ${name}`);
  return found.record;
};

const commitment = pick("commitment_accepted");
const packet = pick("packet");
const genesis = pick("amina_log[0]");
const proofs = commitment["proof"] as unknown[];

// In Vitest 5 a benchmark runs inside a test, through the test's `bench`.
const cases: [name: string, run: () => void][] = [
  ["validateRecord: a Commitment with two proofs", () => validateRecord(commitment)],
  ["validateRecord: a Packet that opens a session", () => validateRecord(packet)],
  ["validateRecord: a Genesis", () => validateRecord(genesis)],
  [
    "validateRecord: every record of the positive vectors",
    () => {
      for (const { record } of records) validateRecord(record);
    },
  ],
  [
    "validateProof: the two proofs of a Commitment, one with an inline Delegation",
    () => {
      for (const proof of proofs) validateProof(proof);
    },
  ],
];

describe("validation", () => {
  test.for(cases)("%s", async ([name, run], { bench }) => {
    await bench(name, run).run();
  });
});
