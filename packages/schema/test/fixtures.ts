// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The shared samples of `@oip/testkit`, typed by record type. */

import { copy, type JsonObject, readVectors, sampleProofRecord, sampleRecords } from "@oip/testkit";

import type { RecordType } from "../src/index.ts";

export { AMINA, CID, LEXIS_AGENT, OTHER_CID, T0 } from "@oip/testkit";

/** A well-formed record of each type. */
export const samples = sampleRecords as Readonly<Record<RecordType, JsonObject>>;

/** A fresh copy of the sample of `type`, with `changes` applied on top. */
export function sample(type: RecordType, changes: JsonObject = {}): JsonObject {
  return { ...copy(samples[type]), ...changes };
}

/** A copy of `record` without the member `name`. */
export function without(record: JsonObject, name: string): JsonObject {
  const { [name]: _removed, ...rest } = record;
  return rest;
}

/** A well-formed proof, from the vectors. */
export function sampleProof(changes: JsonObject = {}): JsonObject {
  return { ...copy(sampleProofRecord), ...changes };
}

/** A proof whose `authority` carries an inline Delegation, from the vectors. */
export function delegatedProof(): JsonObject {
  const accepted = readVectors().cases["commitment_accepted"] as JsonObject;
  const proofs = accepted["proof"] as JsonObject[];
  const found = proofs.find((candidate) => candidate["authority"] !== undefined);
  if (found === undefined) throw new Error("the vectors have no delegated proof");
  return copy(found);
}
