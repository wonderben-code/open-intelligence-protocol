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

/**
 * Whether a record can hold a value where the gateway puts one.
 *
 * The value is written as text and read back by the parser for records:
 * what that parser takes, a record holds.
 */
export function holds(value: unknown): boolean {
  // `undefined` for what is no JSON at all: a function, or nothing.
  let text: unknown;
  try {
    text = JSON.stringify(value);
  } catch {
    // What cannot be written at all, a cycle or a nesting too deep to walk, no record holds.
    return false;
  }
  if (typeof text !== "string") return false;
  return parseJson("[".repeat(LEVELS_ABOVE) + text + "]".repeat(LEVELS_ABOVE)).ok;
}

/** A value as a record carries it: as it is, or as its JSON text. */
export function carriedJson(value: unknown): JsonValue {
  return holds(value) ? (value as JsonValue) : jsonText(value);
}

/**
 * Reads JSON text that a stranger wrote: a request's body, where it came
 * as text.
 *
 * The text is of a packet, so its length is bounded. Its nesting is
 * bounded here, before it is parsed.
 *
 * @returns The value, or `undefined` for text that is no JSON, or nests more than 64 deep.
 */
export function readJsonText(text: string): { readonly value: unknown } | undefined {
  let depth = 0;
  let inString = false;
  for (let at = 0; at < text.length; at += 1) {
    const unit = text.charCodeAt(at);
    if (inString) {
      // A backslash takes the unit after it with it, a quote among them.
      if (unit === 0x5c) at += 1;
      else if (unit === 0x22) inString = false;
    } else if (unit === 0x22) {
      inString = true;
    } else if (unit === 0x5b || unit === 0x7b) {
      depth += 1;
      if (depth > MAX_TEXT_NESTING) return undefined;
    } else if (unit === 0x5d || unit === 0x7d) {
      depth -= 1;
    }
  }
  try {
    return { value: JSON.parse(text) as unknown };
  } catch {
    return undefined;
  }
}

/**
 * The digest of a body the gateway returned, as a Receipt gives it in
 * evidence (Layer 0, 2.1): of its canonical form, or of its bytes where it
 * is text.
 */
export function digestOf(body: JsonValue): string {
  return sha256Digest(typeof body === "string" ? utf8(body) : canonicalBytes(body));
}

/** The size of a body in a packet, in bytes, near enough to keep a packet within its limit. */
export function sizeOf(body: JsonValue): number {
  return utf8(typeof body === "string" ? body : JSON.stringify(body)).length;
}
