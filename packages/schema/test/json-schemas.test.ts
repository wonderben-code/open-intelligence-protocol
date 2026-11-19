// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { positiveVectorRecords, readVectors, repoRoot } from "@oip/testkit";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import {
  jsonSchemas,
  RECORD_TYPES,
  SCHEMA_DIALECT,
  validateExtensionRecord,
  validateRecord,
} from "../src/index.ts";
import { samples } from "./fixtures.ts";

const schemaDir = join(repoRoot, "spec", "schemas");
const onDisk = Object.fromEntries(
  readdirSync(schemaDir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => [
      file.replace(/\.json$/, ""),
      JSON.parse(readFileSync(join(schemaDir, file), "utf8")) as Record<string, unknown>,
    ]),
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

  it("state on their own the bounds that the code rules would also catch", () => {
    // A threshold of zero is rejected by the majority rule in code as well, so
    // only a validator that has the schemas alone shows that they say it too.
    const independent = independentValidator();
    const genesis = samples.Genesis;
    const key = (genesis["controller"] as { keys: string[] }).keys[0];
    const next = ["bciqa" + "a".repeat(50) + "a"];
    const member = "did:oip:bciqa" + "b".repeat(50) + "a";
    expect(independent({ ...genesis, controller: { keys: [key], next, nextThreshold: 1 } })).toBe(
      true,
    );
    for (const nextThreshold of [0, -1, 17, 1.5, "1"]) {
      expect(independent({ ...genesis, controller: { keys: [key], next, nextThreshold } })).toBe(
        false,
      );
    }
    const collective = (threshold: unknown) => ({
      ...genesis,
      kind: "collective",
      controller: { members: [member], threshold },
    });
    expect(independent(collective(1))).toBe(true);
    for (const threshold of [0, -1, 257, 1.5, "1"]) {
      expect(independent(collective(threshold))).toBe(false);
    }
  });

  it("judge the `record` cases of the vectors as the vectors say, as far as a schema can", () => {
    const independent = independentValidator();
    const vectors = readVectors();
    const ofKind = (section: "valid" | "negative" | "controls") =>
      vectors[section].filter((entry) => entry.kind === "record");
    // Whichever validator is the right one for the record's type.
    const wellFormed = (record: unknown) =>
      validateRecord(record).ok || validateExtensionRecord(record).ok;
    const negative = ofKind("negative");
    expect(negative.map((entry) => entry.name).sort()).toEqual([
      "bundle-carries-a-location-nested-65-deep",
      "container-carries-a-record-nested-65-deep",
      "container-nested-65-deep-without-its-records",
      "delegation-to-self",
      "duplicity-evidence-carries-a-record-nested-65-deep",
      "duration-of-65-characters",
      "extension-name-not-a-namespace",
      "extension-type-without-created",
      "feed-page-carries-a-record-nested-65-deep",
      "packet-short-nonce",
      "proof-entry-not-an-object",
      "record-nested-65-deep",
      "unknown-type-without-critical-extension",
    ]);
    for (const entry of negative) expect(wellFormed(entry["record"]), entry.name).toBe(false);
    const accepted = [...ofKind("valid"), ...ofKind("controls")];
    expect(accepted).toHaveLength(18);
    for (const entry of accepted) expect(wellFormed(entry["record"]), entry.name).toBe(true);
    // What a schema alone can see: a short nonce, an entry of proof that is no object, a
    // name in ext that is no namespace, a duration that is too long. A delegation to
    // oneself is a code rule (Layer 1, 11.1), and so is depth.
    for (const name of [
      "packet-short-nonce",
      "proof-entry-not-an-object",
      "extension-name-not-a-namespace",
      "duration-of-65-characters",
    ]) {
      const found = negative.find((entry) => entry.name === name);
      expect(independent(found?.["record"]), name).toBe(false);
    }
  });
});
