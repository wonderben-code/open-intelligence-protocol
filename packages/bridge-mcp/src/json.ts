// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * JSON as MCP has it, in records (Layer 0, 2.1).
 *
 * A tool's input schema, a call's arguments and a tool's result are JSON
 * that an MCP server or a requester chose. A record cannot hold all such
 * JSON: it has no number with a fraction, no number outside the safe
 * integers, no string with a noncharacter, and no nesting beyond 64 deep
 * (core 1.1, 1.2 and 1.9). What a record can hold is carried as it is.
 * What it cannot is carried as its JSON text, a string.
 */

import { canonicalBytes, type JsonValue, parseJson, sha256Digest, utf8 } from "@oip/core";
import { jsonText } from "@oip/local";

// The JSON text of a value, as a string that a record can hold: with the gateway for A2A agents, which needs it too.
export { jsonText };

/**
 * How deep in its record a carried value may sit. A body is the fifth
 * level of a packet whose content has parts, and an input schema is the
 * sixth of a profile. One number serves both, with a level to spare.
 */
const LEVELS_ABOVE = 6;
/** How deep the JSON text of a requester may nest: as deep as a record. */
const MAX_TEXT_NESTING = 64;

/** Thrown for a value that JSON cannot say: a number that is not finite, or what is no JSON at all. */
export class Unsayable extends Error {
  override readonly name = "Unsayable";
}

/** Whether a value has a number in it that JSON has no way to write: an infinity, or what is no number. */
function hasNoNumber(value: unknown, depth = 0): boolean {
  if (typeof value === "number") return !Number.isFinite(value);
  // What nests deeper than this is no value a record holds, and is not walked.
  if (typeof value !== "object" || value === null || depth > 4 * MAX_TEXT_NESTING) return false;
  return Object.values(value).some((member) => hasNoNumber(member, depth + 1));
}

/**
 * A value as a record holds it where the gateway puts one, or `undefined`
 * if no record holds it.
 *
 * The value is written as text and read back by the parser for records.
 * What that parser read is what is given: the value as it will be signed,
 * and never the value as it was handed in, which may say something the
 * text did not.
 */
export function held(value: unknown): JsonValue | undefined {
  // `undefined` for what is no JSON at all: a function, or nothing.
  let text: unknown;
  try {
    text = JSON.stringify(value);
  } catch {
    // What cannot be written at all, a cycle or a nesting too deep to walk, no record holds.
    return undefined;
  }
  if (typeof text !== "string") return undefined;
  const wrapped = parseJson("[".repeat(LEVELS_ABOVE) + text + "]".repeat(LEVELS_ABOVE));
  if (!wrapped.ok) return undefined;
  let inner: JsonValue = wrapped.value;
  for (let level = 0; level < LEVELS_ABOVE; level += 1) inner = (inner as JsonValue[])[0] ?? null;
  return inner;
}

/** Whether a record can hold a value where the gateway puts one. */
export function holds(value: unknown): boolean {
  return held(value) !== undefined;
}

/**
 * A value as a record carries it: as it is, or as its JSON text.
 *
 * @throws Unsayable for a value JSON cannot say. `JSON.stringify` writes
 *   an infinity as `null`: what would be carried is not what was given.
 */
export function carriedJson(value: unknown): JsonValue {
  if (hasNoNumber(value)) {
    throw new Unsayable("the value holds a number that is not finite, which JSON cannot write");
  }
  const whole = held(value);
  if (whole !== undefined) return whole;
  try {
    return jsonText(value);
  } catch (error) {
    throw new Unsayable("the value has no JSON text", { cause: error });
  }
}

/**
 * Reads JSON text that a stranger wrote: a request's body, where it came
 * as text.
 *
 * The text is of a packet, so its length is bounded. Its nesting is
 * bounded here, before it is parsed. An object that names a member twice
 * is refused: a reader that takes the last and one that takes the first
 * would call different tools. So is a number that is not finite.
 *
 * @returns The value, or `undefined` for text that is no JSON, nests more
 *   than 64 deep, names a member twice in one object, or holds a number
 *   that JSON has and a program has not.
 */
export function readJsonText(text: string): { readonly value: unknown } | undefined {
  /** For each object or array that is open: the names an object has so far, or `undefined` for an array. */
  const open: (Set<string> | undefined)[] = [];
  /** Whether the next string, in the object that is open, is a member's name. */
  let name = false;
  for (let at = 0; at < text.length; at += 1) {
    const unit = text.charCodeAt(at);
    if (unit === 0x22) {
      // A string: to the quote that ends it. A backslash takes the unit after it with it.
      const from = at;
      for (at += 1; at < text.length && text.charCodeAt(at) !== 0x22; at += 1) {
        if (text.charCodeAt(at) === 0x5c) at += 1;
      }
      const names = open.at(-1);
      if (names !== undefined && name) {
        let read: unknown;
        try {
          read = JSON.parse(text.slice(from, at + 1));
        } catch {
          return undefined;
        }
        if (typeof read !== "string" || names.has(read)) return undefined;
        names.add(read);
        name = false;
      }
    } else if (unit === 0x7b || unit === 0x5b) {
      if (open.length >= MAX_TEXT_NESTING) return undefined;
      open.push(unit === 0x7b ? new Set() : undefined);
      name = unit === 0x7b;
    } else if (unit === 0x7d || unit === 0x5d) {
      open.pop();
      name = false;
    } else if (unit === 0x2c) {
      // After a comma an object has its next member's name, and an array its next value.
      name = open.at(-1) !== undefined;
    }
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  // `1e999` is JSON, and no number a program has: what would be passed on is not what was written.
  return hasNoNumber(value) ? undefined : { value };
}

/**
 * The digest of a body the gateway returned, as a Receipt gives it in
 * evidence (Layer 0, 2.1): of its canonical form, or of its bytes where it
 * is text.
 */
export function digestOf(body: JsonValue): string {
  return sha256Digest(typeof body === "string" ? utf8(body) : canonicalBytes(body));
}

/**
 * The size of a body in the record that carries it, in bytes of the
 * record's canonical form (core 1.4, 1.6). A text is a JSON string there:
 * each quotation mark and each backslash of it is two bytes, and JSON text
 * is full of both.
 */
export function sizeOf(body: JsonValue): number {
  return typeof body === "string" ? utf8(JSON.stringify(body)).length : canonicalBytes(body).length;
}
