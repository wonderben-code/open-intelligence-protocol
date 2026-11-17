// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The golden test vectors (`spec/test-vectors/vectors.json`), typed. */

/** A JSON object whose members are not yet known. */
export type JsonObject = Readonly<Record<string, unknown>>;

/** An identity log: its events in order, the genesis first. */
export type Log = readonly JsonObject[];

/** Evidence of time (core 9.4): a proof digest or an event's content ID, to the earliest time shown. */
export type Seen = Readonly<Record<string, string>>;

/** What every must-accept case, negative case and control has in common. */
export interface CaseBase {
  readonly name: string;
  /** Why the case must be accepted or rejected. Controls have none: they are their negative case, corrected. */
  readonly reason?: string;
  /** Logs that replace the baseline logs of the same minds. */
  readonly extraLogs?: readonly Log[];
  /** Further, conflicting branches of a mind's log. */
  readonly branches?: readonly Log[];
  /** Records the verifier holds besides the baseline records. */
  readonly extraRecords?: readonly JsonObject[];
  /**
   * The verifier's evidence. Without it, the verifier is taken to have
   * obtained each proof and each identity event at its own `created` time.
   */
  readonly seen?: Seen;
}

/** The identity log in `log` verifies (must-accept, control) or does not (negative). */
export interface LogCase extends CaseBase {
  readonly kind: "log";
  readonly log: Log;
}

/** `record` counts for `mind` (must-accept, control) or does not (negative). */
export interface CountsForCase extends CaseBase {
  readonly kind: "countsFor";
  readonly record: JsonObject;
  readonly mind: string;
}

/** The packet in `record` does not count as sent on `mind`'s behalf (negative). */
export interface SentForCase extends CaseBase {
  readonly kind: "sentFor";
  readonly record: JsonObject;
  readonly mind: string;
}

/** The status of `of`, given `records` at time `at`, is `expect`. */
export interface StatusCase extends CaseBase {
  readonly kind: "status";
  readonly of: JsonObject;
  readonly records: readonly JsonObject[];
  readonly at: string;
  readonly expect: string;
}

/** The assurance level (Layer 0, 1.3) of the profile in `record` is `expect`. */
export interface AssuranceCase extends CaseBase {
  readonly kind: "assurance";
  readonly record: JsonObject;
  readonly expect: string;
}

/** `record` is malformed (negative). */
export interface RecordCase extends CaseBase {
  readonly kind: "record";
  readonly record: unknown;
}

export type VectorCase =
  LogCase | CountsForCase | SentForCase | StatusCase | AssuranceCase | RecordCase;

/** The kinds of case, in the order the vectors' README lists them. */
export const CASE_KINDS = ["log", "countsFor", "sentFor", "status", "assurance", "record"] as const;
export type CaseKind = (typeof CASE_KINDS)[number];

/** The three lists of cases. */
export const SECTIONS = ["valid", "negative", "controls"] as const;
export type Section = (typeof SECTIONS)[number];

/** A status the positive part of the vectors expects, by the names of records in `cases`. */
export interface ExpectedStatus {
  readonly of: string;
  readonly records: readonly string[];
  readonly at: string;
  readonly expect: string;
}

/** A test key. Every key in the vectors derives from a public seed and must never be used for anything real. */
export interface TestKey {
  readonly seed_hex: string;
  readonly multikey: string;
  readonly type?: string;
}

/** `vectors.json`. */
export interface Vectors {
  readonly spec_revision: string;
  readonly status: string;
  /**
   * The verifier's view that every case starts from: the names, in `cases`,
   * of the identity logs and the records it holds.
   */
  readonly baseline: { readonly logs: readonly string[]; readonly records: readonly string[] };
  readonly keys: Readonly<Record<string, TestKey>>;
  /** The positive part: records, logs, addresses, DID documents and expected values, by name. */
  readonly cases: Readonly<Record<string, unknown>>;
  /** Cases that look suspicious and must be accepted. */
  readonly valid: readonly VectorCase[];
  /** Cases every implementation must reject, each with its reason. */
  readonly negative: readonly VectorCase[];
  /** Negative cases changed only in the respect their reason names, which must be accepted. */
  readonly controls: readonly VectorCase[];
}

function fail(message: string): never {
  throw new Error(`vectors.json: ${message}`);
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkCase(section: Section, value: unknown, index: number): void {
  const where = `${section}[${index}]`;
  if (!isObject(value)) fail(`${where} is not an object`);
  const { name, kind } = value;
  if (typeof name !== "string" || name === "") fail(`${where} has no name`);
  if (!(CASE_KINDS as readonly unknown[]).includes(kind)) {
    fail(`${where} (${name}) has the unknown kind ${JSON.stringify(kind)}`);
  }
  const needs: Record<CaseKind, readonly string[]> = {
    log: ["log"],
    countsFor: ["record", "mind"],
    sentFor: ["record", "mind"],
    status: ["of", "records", "at", "expect"],
    assurance: ["record", "expect"],
    record: ["record"],
  };
  for (const member of needs[kind as CaseKind]) {
    if (!(member in value)) fail(`${where} (${name}) has no ${member}`);
  }
}

/**
 * Checks that a parsed `vectors.json` has the shape this suite relies on, and
 * returns it typed. It throws, naming what is wrong, rather than let a
 * malformed file make cases pass by being skipped.
 */
export function parseVectors(value: unknown): Vectors {
  if (!isObject(value)) fail("not an object");
  if (typeof value["spec_revision"] !== "string") fail("no spec_revision");
  if (!isObject(value["cases"])) fail("no cases");
  if (!isObject(value["keys"])) fail("no keys");
  const baseline = value["baseline"];
  if (
    !isObject(baseline) ||
    !Array.isArray(baseline["logs"]) ||
    !Array.isArray(baseline["records"])
  ) {
    fail("no baseline of logs and records");
  }
  for (const name of [...(baseline["logs"] as unknown[]), ...(baseline["records"] as unknown[])]) {
    if (typeof name !== "string" || !(name in value["cases"])) {
      fail(`the baseline names ${JSON.stringify(name)}, which is not in cases`);
    }
  }
  const names = new Set<string>();
  for (const section of SECTIONS) {
    const list = value[section];
    if (!Array.isArray(list)) fail(`no ${section}`);
    list.forEach((item: unknown, index) => {
      checkCase(section, item, index);
      const key = `${section}/${(item as VectorCase).name}`;
      if (names.has(key)) fail(`${key} appears twice`);
      names.add(key);
    });
  }
  return value as unknown as Vectors;
}

/** The record called `name` in the positive part of the vectors. */
export function namedRecord(vectors: Vectors, name: string): JsonObject {
  const value = vectors.cases[name];
  if (!isObject(value)) fail(`cases.${name} is not a record`);
  return value;
}

/** The identity log called `name` in the positive part of the vectors. */
export function namedLog(vectors: Vectors, name: string): Log {
  const value = vectors.cases[name];
  if (!Array.isArray(value) || !value.every(isObject)) fail(`cases.${name} is not a log`);
  return value;
}

/** Every record in the positive part of the vectors: single records and each event of each log. */
export function positiveRecords(vectors: Vectors): { name: string; record: JsonObject }[] {
  const found: { name: string; record: JsonObject }[] = [];
  const isRecord = (value: unknown): value is JsonObject =>
    isObject(value) && value["oip"] === "1" && typeof value["type"] === "string";
  for (const [name, value] of Object.entries(vectors.cases)) {
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
