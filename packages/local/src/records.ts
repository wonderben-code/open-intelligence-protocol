// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a mind's directory keeps between the runs of a program: the records
 * the mind holds, and the packets it has received.
 *
 * A client holds records while it is open. A command is one short run, so
 * what the mind held at the end of one is written down, and held again at
 * the start of the next. A mailbox gives each packet once: a packet that
 * was read is kept here, or it would be gone when the program ends.
 *
 * Each is a file named by its content ID. What is read back is validated
 * again before it is used, as anything from outside is.
 */

import { mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalize, contentId, type Instant, type JsonObject, parseJsonBytes } from "@oip/core";

import { MAX_FILE_BYTES } from "./files.ts";

/** The name of the file of a content ID, or `undefined` for what is none: nothing else names a file here. */
const fileOf = (id: string): string | undefined =>
  /^bciq[a-z2-7]{52}$/u.test(id) ? `${id}.json` : undefined;

/** A directory of JSON objects, each in a file named by a content ID. */
export class Kept {
  /** The directory. */
  readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  /** The content IDs of what is kept, in order. */
  ids(): string[] {
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      // Nothing was ever kept.
      return [];
    }
    return names
      .filter((name) => fileOf(name.slice(0, -".json".length)) === name)
      .map((name) => name.slice(0, -".json".length))
      .sort();
  }

  /** What is kept under a content ID, or `undefined` if nothing is, or what is there is no JSON object. */
  get(id: string): JsonObject | undefined {
    const name = fileOf(id);
    if (name === undefined) return undefined;
    let bytes: Uint8Array;
    try {
      bytes = readFileSync(join(this.dir, name));
    } catch {
      return undefined;
    }
    const parsed = parseJsonBytes(bytes, { maxLength: MAX_FILE_BYTES });
    if (!parsed.ok) return undefined;
    return isObject(parsed.value) ? parsed.value : undefined;
  }

  /** Everything kept, each with the content ID it is kept under. */
  all(): { id: string; value: JsonObject }[] {
    return this.ids().flatMap((id) => {
      const value = this.get(id);
      return value === undefined ? [] : [{ id, value }];
    });
  }

  /**
   * Keeps a JSON object under a content ID. The file is the user's alone,
   * and is written whole or not at all. One that says the same already is
   * left as it is.
   */
  put(id: string, value: object): void {
    const name = fileOf(id);
    if (name === undefined) throw new TypeError(`${id} is no content ID`);
    const text = canonicalize(value);
    const file = join(this.dir, name);
    try {
      if (readFileSync(file, "utf8") === text) return;
    } catch {
      // Not kept yet.
    }
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const partial = `${file}.partial`;
    writeFileSync(partial, text, { mode: 0o600 });
    renameSync(partial, file);
  }
}

/** A record as it is kept: with when each of its proofs was first obtained (core 9.4, item 1). */
export interface KeptRecord {
  /** The record, as it was kept. It is validated again when the mind holds it. */
  readonly record: JsonObject;
  /** By the proof's digest, the time, in nanoseconds of the Unix epoch. */
  readonly seen: Readonly<Record<string, Instant>>;
}

/**
 * The records a mind holds, as its directory keeps them between runs.
 *
 * With each is kept when this mind first obtained each of its proofs. That
 * is evidence the proof existed then, and for most proofs the only evidence
 * there is: without it, a record held again by the next command would be
 * judged as if it had only then arrived.
 */
export class KeptRecords {
  readonly #kept: Kept;

  constructor(dir: string) {
    this.#kept = new Kept(dir);
  }

  /** Every record kept. A file that holds no such thing is passed over. */
  all(): KeptRecord[] {
    return this.#kept.all().flatMap(({ value }) => {
      const { record, seen } = value;
      if (!isObject(record) || !isObject(seen)) return [];
      const times: Record<string, Instant> = {};
      for (const [digest, time] of Object.entries(seen)) {
        // What is no time says nothing, and the proof is then first seen when it is held again.
        if (typeof time === "string" && /^[0-9]{1,30}$/u.test(time)) times[digest] = BigInt(time);
      }
      return [{ record, seen: times }];
    });
  }

  /** The record kept under a content ID, if one is. */
  get(id: string): JsonObject | undefined {
    const record = this.#kept.get(id)?.["record"];
    return isObject(record) ? record : undefined;
  }

  /**
   * Keeps a record that came from outside a mind that is open, unless it is
   * kept already: what is kept of when its proofs first came is left as it is.
   */
  add(record: object, seen: Readonly<Record<string, Instant>>): void {
    if (this.get(contentId(record)) === undefined) this.keep(record, seen);
  }

  /** Keeps a record under its content ID, with when its proofs were first obtained. */
  keep(record: object, seen: Readonly<Record<string, Instant>>): void {
    const times = Object.fromEntries(
      Object.entries(seen).map(([digest, time]) => [digest, String(time)]),
    );
    this.#kept.put(contentId(record), { record, seen: times });
  }
}

const isObject = (value: unknown): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);
