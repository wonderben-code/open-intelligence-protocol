// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The golden vectors as a verifier's view: the logs it holds and its evidence of time. */

import { contentId, type Instant, parseTimestamp, proofDigest } from "@oip/core";
import { type JsonObject, readVectors, type VectorCase } from "@oip/testkit";

import { type EvidenceView, type JudgedRecord, judgeRecord, LogBook } from "../src/index.ts";

const vectors = readVectors() as unknown as {
  readonly baseline: { readonly logs: readonly string[]; readonly records: readonly string[] };
  readonly keys: Readonly<Record<string, { readonly seed_hex: string; readonly multikey: string }>>;
  readonly cases: Readonly<Record<string, unknown>>;
  readonly valid: readonly VectorCase[];
  readonly negative: readonly VectorCase[];
  readonly controls: readonly VectorCase[];
};

export const { cases, keys, valid, negative, controls } = vectors;

/** A named identity log of the positive vectors. */
export function log(name: string): JsonObject[] {
  const value = cases[name];
  if (!Array.isArray(value)) throw new Error(`the vectors have no log named ${name}`);
  return value as JsonObject[];
}

/** A named record of the positive vectors. */
export function named(name: string): JsonObject {
  const value = cases[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`the vectors have no record named ${name}`);
  }
  return value as JsonObject;
}

/** A named address of the positive vectors. */
export function mind(name: string): string {
  const value = cases[name];
  if (typeof value !== "string") throw new Error(`the vectors have no mind named ${name}`);
  return value;
}

/** The instant a timestamp names. */
export function instant(timestamp: string): Instant {
  const parsed = parseTimestamp(timestamp);
  if (parsed === undefined) throw new Error(`${timestamp} is not a timestamp`);
  return parsed;
}

/**
 * The vectors take the verifier to hold every log in full. A log held "as of
 * the end of time" lacks no later event.
 */
export const ALWAYS: Instant = instant("9999-12-31T23:59:59Z");

const EVENT_TYPES: readonly unknown[] = ["Genesis", "Update", "Fork", "Retire"];

/**
 * The convention of the vectors, which is not a rule of the protocol: unless
 * `seen` names it, each proof and each identity event was obtained at its own
 * `created`, as by a witness that followed everything from the start.
 */
export function assumedEvidence(
  items: unknown,
  seen: Readonly<Record<string, string>> = {},
): EvidenceView {
  const times = new Map<string, Instant>();
  const note = (name: () => string, created: unknown): void => {
    const time = parseTimestamp(created);
    if (time === undefined) return;
    try {
      times.set(name(), time);
    } catch {
      // What has no digest or content ID has no evidence either.
    }
  };
  const walk = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(walk);
    } else if (typeof value === "object" && value !== null) {
      const object = value as JsonObject;
      if (EVENT_TYPES.includes(object["type"])) note(() => contentId(object), object["created"]);
      if (Array.isArray(object["proof"])) {
        for (const proof of object["proof"] as unknown[]) {
          if (typeof proof === "object" && proof !== null) {
            note(() => proofDigest(proof), (proof as JsonObject)["created"]);
          }
        }
      }
      Object.values(object).forEach(walk);
    }
  };
  walk(items);
  for (const [name, time] of Object.entries(seen)) times.set(name, instant(time));
  return { proofSeen: (digest) => times.get(digest), eventSeen: (id) => times.get(id) };
}

/** What a case adds to the baseline. */
export interface CaseExtras {
  readonly log?: unknown;
  readonly record?: unknown;
  readonly extraLogs?: readonly unknown[];
  readonly branches?: readonly unknown[];
  readonly extraRecords?: readonly unknown[];
  readonly seen?: Readonly<Record<string, string>>;
}

export interface World {
  readonly book: LogBook;
  /** The records the verifier holds: the baseline's, and the case's. */
  readonly records: readonly JudgedRecord[];
}

/** The verifier's view for a case: the baseline of the vectors and what the case adds. */
export function worldFor(extras: CaseExtras = {}): World {
  const baseLogs = vectors.baseline.logs.map(log);
  const held = [...vectors.baseline.records.map(named), ...(extras.extraRecords ?? [])];
  const evidence = assumedEvidence(
    [baseLogs, held, extras.log, extras.record, extras.extraLogs, extras.branches],
    extras.seen,
  );
  const book = new LogBook(evidence);
  for (const events of [...baseLogs, ...(extras.extraLogs ?? [])]) book.hold(events, ALWAYS);
  for (const events of extras.branches ?? []) book.hold(events, ALWAYS);
  const records = held.flatMap((record) => {
    const judged = judgeRecord(record);
    return judged.ok ? [judged.value] : [];
  });
  return { book, records };
}
