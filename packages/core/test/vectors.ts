// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The golden vectors, as the tests of this package read them. */

import { type JsonObject, positiveVectorRecords, readVectors, type VectorCase } from "@oip/testkit";

import { hexToBytes } from "../src/index.ts";

export interface TestKey {
  readonly seed_hex: string;
  readonly multikey: string;
  readonly type?: string;
}

const vectors = readVectors() as unknown as {
  readonly keys: Readonly<Record<string, TestKey>>;
  readonly cases: Readonly<Record<string, unknown>>;
  readonly valid: readonly VectorCase[];
  readonly negative: readonly VectorCase[];
  readonly controls: readonly VectorCase[];
};

export const cases = vectors.cases;
export const keys = vectors.keys;

/** A named record of the positive vectors. */
export function named(name: string): JsonObject {
  const value = cases[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`the vectors have no record named ${name}`);
  }
  return value as JsonObject;
}

/** A named identity log of the positive vectors. */
export function log(name: string): JsonObject[] {
  const value = cases[name];
  if (!Array.isArray(value)) throw new Error(`the vectors have no log named ${name}`);
  return value as JsonObject[];
}

/** The item at a position, which must exist. */
export function at<T>(items: readonly T[] | undefined, index = 0): T {
  const item = items?.[index];
  if (item === undefined) throw new Error(`nothing at position ${index}`);
  return item;
}

/** The proofs of a record. */
export function proofsOf(record: JsonObject): JsonObject[] {
  const proofs = record["proof"];
  if (!Array.isArray(proofs)) throw new Error("the record has no proofs");
  return proofs as JsonObject[];
}

/** A value as a test message shows it. */
export function show(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? typeof value;
  } catch {
    return typeof value;
  }
}

/** A negative case, by name. */
export function negative(name: string): VectorCase {
  const found = vectors.negative.find((item) => item.name === name);
  if (found === undefined) throw new Error(`the vectors have no negative case named ${name}`);
  return found;
}

/** The private key (the seed) of the test key with this Multikey. */
export function privateKeyOf(multikey: string): Uint8Array {
  const key = Object.values(keys).find((candidate) => candidate.multikey === multikey);
  if (key === undefined) throw new Error(`the vectors have no test key ${multikey}`);
  return hexToBytes(key.seed_hex);
}

/** Every record of the positive vectors that carries proofs. */
export const signedRecords = positiveVectorRecords().filter(({ record }) =>
  Array.isArray(record["proof"]),
);

/** The identity logs of the positive vectors, by the name of the mind they belong to. */
export const logs: readonly [log: string, mind: string][] = [
  ["amina_log", "amina"],
  ["lexis_ltd_log", "lexis_ltd"],
  ["lexis_agent_log", "lexis_agent"],
  ["lexis_fork_log", "lexis_fork"],
  ["lexis_fork2_log", "lexis_fork2"],
  ["researcher_log", "researcher"],
  ["collective_log", "collective"],
  ["multi_log", "multi"],
  ["assistant_log", "assistant"],
  ["gateway_log", "gateway"],
  ["bridged_log", "bridged"],
];

/** Every string anywhere in a value. */
export function strings(value: unknown, found: string[] = []): string[] {
  if (typeof value === "string") found.push(value);
  else if (Array.isArray(value)) for (const item of value) strings(item, found);
  else if (typeof value === "object" && value !== null) {
    for (const [name, member] of Object.entries(value)) {
      found.push(name);
      strings(member, found);
    }
  }
  return found;
}

export { positiveVectorRecords, vectors };
