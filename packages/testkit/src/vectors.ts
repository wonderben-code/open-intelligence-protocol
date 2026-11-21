// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The test vectors, as far as tests below `@oip/conformance` need to know them. */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repository root, for tests that read the specifications or the vectors. */
export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** A JSON object whose members are not yet known. */
export type JsonObject = Record<string, unknown>;

/** One must-accept case, negative case or control of the test vectors. */
export interface VectorCase extends JsonObject {
  readonly name: string;
  readonly kind: string;
  readonly reason?: string;
}

/** The test vectors, as far as tests below `@oip/conformance` need to know them. */
export interface RawVectors {
  readonly spec_revision: string;
  readonly cases: Readonly<Record<string, unknown>>;
  readonly valid: readonly VectorCase[];
  readonly negative: readonly VectorCase[];
  readonly controls: readonly VectorCase[];
}

let cachedVectors: RawVectors | undefined;

/** Reads `spec/test-vectors/vectors.json`. `@oip/conformance` has the typed loader and the runners. */
export function readVectors(): RawVectors {
  cachedVectors ??= JSON.parse(
    readFileSync(join(repoRoot, "spec", "test-vectors", "vectors.json"), "utf8"),
  ) as RawVectors;
  return cachedVectors;
}

function isRecord(value: unknown): value is JsonObject {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    (value as JsonObject)["oip"] === "1" &&
    typeof (value as JsonObject)["type"] === "string"
  );
}

/**
 * Every record in the positive part of the vectors (`cases`), with a name
 * that says where it came from: single records, and each event of each log.
 */
export function positiveVectorRecords(): { name: string; record: JsonObject }[] {
  const found: { name: string; record: JsonObject }[] = [];
  for (const [name, value] of Object.entries(readVectors().cases)) {
    if (isRecord(value)) {
      found.push({ name, record: value });
    } else if (Array.isArray(value)) {
      value.forEach((item: unknown, i) => {
        if (isRecord(item)) found.push({ name: `${name}[${i}]`, record: item });
      });
    }
  }
  return found;
}

/** A deep copy of a JSON value, for tests that change a record. */
export function copy<T>(value: T): T {
  return structuredClone(value);
}
