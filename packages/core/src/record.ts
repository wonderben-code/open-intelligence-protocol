// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Reading a record from untrusted text: the JSON profile, the schema and
 * rules of its type, and the size limit (core 1.6). It is the first two
 * steps of "validate, verify, then use".
 */

import {
  containerParts,
  type ExtensionRecord,
  IMPLEMENTATION_LIMIT,
  isRecordType,
  type Issue,
  type OipRecord,
  type Validation,
  validateParsedExtensionRecord,
  validateParsedRecord,
  judging,
  noteCutShort,
} from "@oip/schema";

import type { JsonObject } from "./content-id.ts";
import { canonicalSizeUpTo } from "./jcs.ts";
import { parseForRecord, type ParseOptions } from "./json.ts";
import { no, ok } from "./result.ts";

/** core 1.6: the longest canonical form of a record, 1 MiB, in bytes. */
export const MAX_RECORD_BYTES = 1_048_576;

/** core 1.6: every implementation accepts records of at least this size, 256 KiB. */
export const MIN_ACCEPTED_RECORD_BYTES = 262_144;

/**
 * The longest `ciphertext` of a `Sealed` record, in characters. core 1.6
 * lets a `Sealed` record exceed the limit "by its encoding overhead" and
 * gives no number. This implementation reads that as: the ciphertext may be
 * as long as a packet of 1 MiB makes it, with the cipher's tag of 16 bytes,
 * in base64url, and the record apart from its ciphertext obeys the ordinary
 * limit.
 */
export const MAX_SEALED_CIPHERTEXT_LENGTH = Math.ceil(((MAX_RECORD_BYTES + 16) * 4) / 3);

/** Whether the canonical form of a value known to be within the JSON profile exceeds the limit. */
function exceeds(value: object): boolean {
  return canonicalSizeUpTo(value as JsonObject, MAX_RECORD_BYTES) > MAX_RECORD_BYTES;
}

function tooLarge(path: string, what: string): Issue {
  return {
    path,
    message: `${what} is more than ${MAX_RECORD_BYTES} bytes in canonical form. Carry larger content by reference`,
    clause: "core 1.6",
  };
}

/**
 * Checks a validated record against the size limit of core 1.6: its
 * canonical form, proofs included, is at most 1 MiB.
 *
 *   - For the containers (`Bundle`, `LogPage`, `FeedPage`,
 *     `DuplicityEvidence`) the limit applies to each record they carry, and
 *     to the container without them.
 *   - A `Sealed` record may exceed it by its encoding overhead: see
 *     `MAX_SEALED_CIPHERTEXT_LENGTH`.
 *
 * The answer is the issues found: none if the record is within the limit.
 */
export function checkSize(record: OipRecord | ExtensionRecord): Issue[] {
  const parts = isRecordType(record.type) ? containerParts(record as OipRecord) : undefined;
  if (parts !== undefined) {
    const issues = parts.carried.flatMap(([path, carried]) => {
      return exceeds(carried) ? [tooLarge(path, "the record")] : [];
    });
    return exceeds(parts.rest)
      ? [tooLarge("", "the container, without the records it carries,"), ...issues]
      : issues;
  }
  if (record.type === "Sealed") {
    const { ciphertext, ...rest } = record as Extract<OipRecord, { type: "Sealed" }>;
    const issues: Issue[] = [];
    if (ciphertext.length > MAX_SEALED_CIPHERTEXT_LENGTH) {
      issues.push({
        path: "/ciphertext",
        message: `the ciphertext is ${ciphertext.length} characters; a sealed packet of 1 MiB needs at most ${MAX_SEALED_CIPHERTEXT_LENGTH}`,
        clause: "core 1.6",
      });
    }
    if (exceeds(rest)) issues.push(tooLarge("", "the record, without its ciphertext,"));
    return issues;
  }
  return exceeds(record) ? [tooLarge("", "the record")] : [];
}

/**
 * Reads a record from JSON text, or from its UTF-8 bytes. The text is parsed
 * under the JSON profile (core Section 1), the value is validated against the
 * schema and the rules of its type, and its size is checked (core 1.6).
 *
 * A record that passes is well formed. It is not yet verified: its proofs
 * are checked with `verifyProofs`, and whose they are by the packages above
 * this one. It never throws.
 */
export function parseRecord(
  input: string | Uint8Array,
  options?: ParseOptions,
): Validation<OipRecord> {
  return judging(() => recordOf(input, options));
}

/** The record, as `parseRecord` answers when no check is cut short. */
function recordOf(input: string | Uint8Array, options?: ParseOptions): Validation<OipRecord> {
  const parsed = parseForRecord(input, options);
  // What the parser has just built is validated as it is: nothing else holds it.
  return parsed.ok
    ? withinSize(validateParsedRecord(parsed.value.value, parsed.value.deepest))
    : parsed;
}

/**
 * Reads a record of a type this revision does not define, as an extension
 * may define one (core 7), from JSON text or its UTF-8 bytes. The text is
 * parsed under the JSON profile, the members every record shares are checked
 * (among them that `critical` lists an extension), and so is the size.
 *
 * Such a record can be stored and forwarded. Whether it may be acted on
 * depends on its `critical` list: see `unsupportedCritical`. `parseRecord`
 * refuses these records and says so; this is what reads them. It never
 * throws.
 */
export function parseExtensionRecord(
  input: string | Uint8Array,
  options?: ParseOptions,
): Validation<ExtensionRecord> {
  return judging(() => extensionRecordOf(input, options));
}

/** The record, as `parseExtensionRecord` answers when no check is cut short. */
function extensionRecordOf(
  input: string | Uint8Array,
  options?: ParseOptions,
): Validation<ExtensionRecord> {
  const parsed = parseForRecord(input, options);
  return parsed.ok
    ? withinSize(validateParsedExtensionRecord(parsed.value.value, parsed.value.deepest))
    : parsed;
}

/** A validated record, if it is also within the size limit. */
function withinSize<T extends OipRecord | ExtensionRecord>(
  validated: Validation<T>,
): Validation<T> {
  if (!validated.ok) return validated;
  try {
    const [first, ...rest] = checkSize(validated.value);
    return first === undefined ? ok(validated.value) : { ok: false, issues: [first, ...rest] };
  } catch (error) {
    noteCutShort(error);
    // Its size could not be measured: the stack is spent, or the process is in
    // a state in which nothing can be serialised. A reader answers all the same.
    return no("the record's size could not be measured", IMPLEMENTATION_LIMIT);
  }
}
