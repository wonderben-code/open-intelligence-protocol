// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the gateway puts on the wire, held against the A2A project's own
 * JSON Schema (`a2a/a2a.schema.json`: see the README beside it).
 *
 * The bundle names each definition by its title, as "Send Message
 * Response", and refers from one to another by the name of a file, as
 * `lf.a2a.v1.Task.jsonschema.json`. Each definition is given that name as
 * its ID here, so that a validator finds it.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { Ajv2020 } from "ajv/dist/2020.js";

const bundle = JSON.parse(
  readFileSync(join(repoRoot, "packages", "bridge-a2a", "test", "a2a", "a2a.schema.json"), "utf8"),
) as { definitions: Record<string, Record<string, unknown>> };

/** The three definitions that are Google's, and not A2A's own. */
const GOOGLE = new Set(["Struct", "Timestamp", "Value"]);

// A2A's timestamps are checked by the tests that make them: the validator knows no formats.
const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: true });
for (const [title, schema] of Object.entries(bundle.definitions)) {
  const name = title.replace(/ /gu, "");
  const { $schema: _, ...rest } = schema;
  ajv.addSchema({
    ...rest,
    $id: `${GOOGLE.has(name) ? "google.protobuf" : "lf.a2a.v1"}.${name}.jsonschema.json`,
  });
}

/**
 * What is wrong with a value as a thing of A2A, by the title of its
 * definition in the bundle. Nothing, where it is one.
 */
export function wrongAs(title: string, value: unknown): string[] {
  const validate = ajv.getSchema(`lf.a2a.v1.${title.replace(/ /gu, "")}.jsonschema.json`);
  if (validate === undefined) throw new Error(`the bundle has no definition "${title}"`);
  if (validate(value) === true) return [];
  return (validate.errors ?? []).map(
    (error) => `${error.instancePath === "" ? "/" : error.instancePath} ${error.message ?? ""}`,
  );
}
