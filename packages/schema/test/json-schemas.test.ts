// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { positiveVectorRecords, readVectors, repoRoot } from "@oip/testkit";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import { jsonSchemas, RECORD_TYPES, SCHEMA_DIALECT, validateRecord } from "../src/index.ts";
import { samples } from "./fixtures.ts";

const schemaDir = join(repoRoot, "spec", "schemas");
const onDisk = Object.fromEntries(
  readdirSync(schemaDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => [file.replace(/\.json$/, ""), JSON.parse(readFileSync(join(schemaDir, file), "utf8")) as Record<string, unknown>]),
);

/** A second validator, built at run time from the files an implementer would download. */
function independentValidator() {
  const ajv = new Ajv2020({ strict: false, allErrors: false });
  for (const schema of Object.values(onDisk)) ajv.addSchema(schema);
  const validate = ajv.getSchema("urn:oip:schema:Record");
  if (validate === undefined) throw new Error("spec/schemas has no Record schema");
  return (value: unknown) => validate(value);
}

describe("the exported JSON Schemas", () => {
  it("are the files in spec/schemas", () => {
    expect(Object.keys(onDisk).sort()).toEqual(Object.keys(jsonSchemas).sort());
    for (const [name, schema] of Object.entries(jsonSchemas)) {
      expect(onDisk[name], name).toEqual(JSON.parse(JSON.stringify(schema)));
    }
  });

  it("each declare the 2020-12 dialect, an $id, a title and a description", () => {
    for (const [name, schema] of Object.entries(jsonSchemas)) {
      expect(schema["$schema"], name).toBe(SCHEMA_DIALECT);
      expect(schema["$id"], name).toBe(`urn:oip:schema:${name}`);
      expect(schema["title"], name).toBe(name);
      expect(String(schema["description"]).length, name).toBeGreaterThan(20);
    }
  });

  it("refer only to schemas that exist", () => {
    const ids = new Set<string>();
    const refs = new Set<string>();
    const walk = (value: unknown): void => {
      if (Array.isArray(value)) return value.forEach(walk);
      if (typeof value !== "object" || value === null) return;
      for (const [key, inner] of Object.entries(value)) {
        if (key === "$id" && typeof inner === "string") ids.add(inner);
        if (key === "$ref" && typeof inner === "string") refs.add(inner);
        walk(inner);
      }
    };
    walk(jsonSchemas);
    for (const ref of refs) {
      if (ref.startsWith("#")) continue;
      expect(ids.has(ref), ref).toBe(true);
    }
  });

  it("use only keywords of the 2020-12 vocabularies, so that any conforming validator can load them", () => {
    // Ajv's strict mode rejects unknown keywords and ambiguous constructs.
    const ajv = new Ajv2020({ strict: true, strictTypes: false, strictRequired: false });
    for (const schema of Object.values(onDisk)) ajv.addSchema(schema);
    for (const name of Object.keys(onDisk)) {
      expect(() => ajv.getSchema(`urn:oip:schema:${name}`), name).not.toThrow();
    }
  });

  it("give the same verdict as the compiled validators wherever no code rule is involved", () => {
    const independent = independentValidator();
    const records = [
      ...positiveVectorRecords().map((entry) => entry.record),
      ...RECORD_TYPES.map((type) => samples[type]),
    ];
    for (const record of records) {
      expect(independent(record), String(record["type"])).toBe(true);
      expect(validateRecord(record).ok).toBe(true);
    }
    // Structural damage that a schema alone catches: both must reject.
    for (const record of records) {
      for (const member of Object.keys(record)) {
        if (member === "oip" || member === "type") continue;
        const damaged = { ...record, [member]: { not: "what this member holds" } };
        const compiled = validateRecord(damaged).ok;
        if (independent(damaged) !== compiled) {
          expect.fail(`verdicts differ for ${String(record["type"])} with ${member} replaced`);
        }
      }
    }
  });

  it("reject the two malformed records of the negative vectors' `record` cases as far as a schema can", () => {
    const independent = independentValidator();
    const cases = readVectors().negative.filter((entry) => entry.kind === "record");
    expect(cases.map((entry) => entry.name).sort()).toEqual(["delegation-to-self", "packet-short-nonce"]);
    for (const entry of cases) {
      expect(validateRecord(entry["record"]).ok, entry.name).toBe(false);
    }
    // The short nonce is a schema matter. A delegation to oneself is a code rule (Layer 1, 11.1).
    const short = cases.find((entry) => entry.name === "packet-short-nonce");
    expect(independent(short?.["record"])).toBe(false);
  });
});
