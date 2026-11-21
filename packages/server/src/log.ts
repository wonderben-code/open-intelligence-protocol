// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A service's log: one line of JSON for each thing that happened.
 *
 * CLAUDE.md: never log a private key or any other secret. A filter that
 * removes what someone thought to name is no answer to that, so the rule
 * here is about what can be logged at all:
 *
 * - A line is an event's name and fields that are plain values: text,
 *   numbers, booleans. There is no way to log a record, a request, a header
 *   or any other object.
 * - An error is logged as its class, its code if it has one, and where it
 *   was thrown. Its message is logged only if the error is one of ours,
 *   whose messages are built from constants. What another library puts in
 *   a message is not known, and some put in the value they choked on.
 */

import { formatTimestamp, OipError } from "@oip/core";

import { ConfigError } from "./config.ts";
import type { Clock } from "./edges.ts";
import { FetchRefused } from "./fetcher.ts";
import { HttpFailure, Unavailable } from "./http.ts";
import { StorageError } from "./storage.ts";

/** How much an event matters. */
export type Level = "debug" | "info" | "warn" | "error";

const LEVELS: readonly Level[] = ["debug", "info", "warn", "error"];

/** A value a field may have. */
export type FieldValue = string | number | boolean | bigint;

/** The fields of an event. One that is `undefined` is left out. */
export type Fields = Readonly<Record<string, FieldValue | undefined>>;

/** How a log is set up. */
export interface LogOptions {
  /** The service's name, on every line. */
  readonly service: string;
  readonly clock: Clock;
  /** Where a line goes. The standard output, by default. */
  readonly sink?: (line: string) => void;
  /** The least level that is written. `info` by default. */
  readonly level?: Level;
}

/** The longest text of one field. What is longer is cut, and says so. */
const LONGEST = 256;

/** How many places of a stack are logged. */
const DEEPEST = 8;

/** The names a line has of its own, which no field takes. */
const OWN = new Set(["time", "level", "service", "event"]);

const FIELD_NAME = /^[a-z][A-Za-z0-9]*$/u;

/** Our own errors: their messages are built from constants, and say nothing of a secret. */
const OURS = [OipError, StorageError, HttpFailure, Unavailable, FetchRefused, ConfigError] as const;

function plain(value: unknown): string | number | boolean | undefined {
  if (typeof value === "string") {
    return value.length > LONGEST
      ? `${value.slice(0, LONGEST)}… (${value.length} characters)`
      : value;
  }
  if (typeof value === "number") return Number.isFinite(value) ? value : String(value);
  if (typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  return undefined;
}

/** Where an error was thrown: the places of its stack, without its first line, which holds the message. */
function placesOf(error: Error): string | undefined {
  let stack: unknown;
  try {
    // The engine keeps a stack behind an accessor. An error may have one of its own, too.
    stack = error.stack;
  } catch {
    return undefined;
  }
  if (typeof stack !== "string") return undefined;
  const places = stack
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("at "))
    .slice(0, DEEPEST)
    .map((line) => line.slice(3));
  return places.length === 0 ? undefined : places.join(" < ");
}

/** A log. A service makes one and gives it to whatever logs. */
export class Log {
  readonly #service: string;
  readonly #clock: Clock;
  readonly #sink: (line: string) => void;
  readonly #least: number;

  constructor(options: LogOptions) {
    this.#service = options.service;
    this.#clock = options.clock;
    this.#sink =
      options.sink ??
      ((line) => {
        process.stdout.write(`${line}\n`);
      });
    this.#least = LEVELS.indexOf(options.level ?? "info");
  }

  /**
   * Writes an event.
   *
   * @param name - What happened, in a word or two: `request`, `bundle merged`.
   * @param fields - What is worth knowing of it. Each is a plain value;
   *   anything else is written as `(not a plain value)`, and a field whose
   *   name is none is left out.
   */
  event(level: Level, name: string, fields: Fields = {}): void {
    if (LEVELS.indexOf(level) < this.#least) return;
    const line: Record<string, string | number | boolean> = {
      time: formatTimestamp(this.#clock.now()),
      level,
      service: this.#service,
      event: name,
    };
    for (const [key, value] of Object.entries(fields)) {
      if (value === undefined || OWN.has(key) || !FIELD_NAME.test(key)) continue;
      line[key] = plain(value) ?? "(not a plain value)";
    }
    // JSON leaves three characters as they are that some readers take for the end of a line.
    this.#sink(
      JSON.stringify(line).replace(
        /[\u0085\u2028\u2029]/gu,
        (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
      ),
    );
  }

  /**
   * Writes a failure: an event at level `error`, with what may be said of
   * what was thrown.
   */
  failure(name: string, thrown: unknown, fields: Fields = {}): void {
    const said: Record<string, FieldValue | undefined> = { ...fields };
    if (thrown instanceof Error) {
      said["error"] = thrown.constructor.name;
      const code = (thrown as { code?: unknown }).code;
      if (typeof code === "string" || typeof code === "number") said["code"] = code;
      // The result code of SQLite, which says which failure of the database it was.
      const errcode = (thrown as { errcode?: unknown }).errcode;
      if (typeof errcode === "number") said["errcode"] = errcode;
      said["message"] = OURS.some((ours) => thrown instanceof ours)
        ? thrown.message
        : "(withheld: not an error of ours)";
      said["at"] = placesOf(thrown);
    } else {
      said["error"] = `(${thrown === null ? "null" : typeof thrown} thrown)`;
    }
    this.event("error", name, said);
  }
}
