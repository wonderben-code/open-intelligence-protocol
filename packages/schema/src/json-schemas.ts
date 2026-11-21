// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The schemas as plain JSON Schema documents, as exported to `spec/schemas/`. */

import { Defs, schemaId } from "./naming.ts";
import { recordSchemas, RESERVED_RECORD_TYPES, sharedSchemas } from "./registry.ts";

/** The JSON Schema dialect of every exported schema. */
export const SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";

/** A JSON Schema document. */
export type JsonSchema = Readonly<Record<string, unknown>>;

function document(schema: object): JsonSchema {
  // A round trip through JSON drops everything that is not part of the schema document.
  const { $id, title, description, ...rest } = JSON.parse(JSON.stringify(schema)) as Record<
    string,
    unknown
  >;
  return { $schema: SCHEMA_DIALECT, $id, title, description, ...rest };
}

const recordNames = Object.keys(recordSchemas);

/** Dispatches on `type` to the schema of that record type. */
const anyRecord: JsonSchema = {
  $schema: SCHEMA_DIALECT,
  $id: schemaId("Record"),
  title: "Record",
  description: `Any record this revision defines (core Section 11). ${RESERVED_RECORD_TYPES.join(", ")} is reserved and matches nothing.`,
  type: "object",
  properties: { oip: { const: "1" }, type: { enum: recordNames } },
  required: ["oip", "type"],
  allOf: recordNames.map((name) => ({
    if: { properties: { type: { const: name } } },
    then: { $ref: schemaId(name) },
  })),
};

/**
 * Every exported schema, by name: one per record type, `Proof`, `Policy`, the
 * shared definitions `Defs`, and `Record`, which dispatches on `type`. Schemas refer to each other by `$id`
 * (`urn:oip:schema:<name>`), so load them all into one registry.
 */
export const jsonSchemas: Readonly<Record<string, JsonSchema>> = Object.freeze({
  ...Object.fromEntries(
    Object.entries({ ...recordSchemas, ...sharedSchemas, Defs }).map(([name, schema]) => [
      name,
      document(schema),
    ]),
  ),
  Record: anyRecord,
});
