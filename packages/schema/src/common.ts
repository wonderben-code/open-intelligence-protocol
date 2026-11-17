// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The members every record shares (core Section 7). */

import { Type } from "typebox";

import { define } from "./naming.ts";
import { Critical, Ext, JsonObject, Timestamp } from "./primitives.ts";

/**
 * core 5.1: a proof set, as it stands in a record before verification. Each
 * proof is judged on its own against the `Proof` schema when it is verified:
 * a malformed proof never counts, but it does not make the record malformed
 * (core 5.5), so that nobody can invalidate a record by adding a bad proof.
 */
export const ProofSet = define(
  "proofSet",
  Type.Array(JsonObject, { minItems: 1, maxItems: 256 }),
);

/** Members of every record. */
export const everyRecord = {
  oip: Type.Literal("1"),
  ext: Type.Optional(Ext),
  critical: Type.Optional(Critical),
};

/** Members of every signed record. */
export const signedRecord = {
  ...everyRecord,
  created: Timestamp,
  proof: ProofSet,
};

/**
 * Members of every unsigned record that carries `created`. `proof` is
 * forbidden: `Never` accepts no value, so the member cannot be present.
 */
export const unsignedRecord = {
  ...everyRecord,
  created: Timestamp,
  proof: Type.Optional(Type.Never()),
};

/** Members of the containers and of `Sealed`, which carry neither `created` nor `proof` (core 11). */
export const containerRecord = {
  ...everyRecord,
  proof: Type.Optional(Type.Never()),
};
