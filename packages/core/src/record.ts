// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Reading a record from untrusted text: the JSON profile, the schema and
 * rules of its type, and the size limit (core 1.6). It is the first two
 * steps of "validate, verify, then use".
 */

import {
  CONTAINER_RECORD_TYPES,
  type Issue,
  type OipRecord,
  type Validation,
  validateRecord,
} from "@oip/schema";

import type { JsonObject } from "./content-id.ts";
import { canonicalBytesOf } from "./jcs.ts";
import { type ParseOptions, parseJson, parseJsonBytes } from "./json.ts";
import { ok } from "./result.ts";

/** core 1.6: the longest canonical form of a record, 1 MiB, in bytes. */
export const MAX_RECORD_BYTES = 1_048_576;

/** core 1.6: every implementation accepts records of at least this size, 256 KiB. */
export const MIN_ACCEPTED_RECORD_BYTES = 262_144;

/**
 * The longest canonical form of a `Sealed` record this implementation
 * accepts. core 1.6 lets a `Sealed` record exceed the limit "by its encoding
 * overhead" and does not give a number. This one allows for the 16-byte tag
 * of the cipher, base64url (four characters for three bytes) and 4 KiB for
 * the other members.
 */
export const MAX_SEALED_BYTES = Math.ceil(((MAX_RECORD_BYTES + 16) * 4) / 3) + 4096;

/** The size in bytes of the canonical form of a value known to be within the JSON profile. */
function sizeOf(value: object): number {
  return canonicalBytesOf(value as JsonObject).length;
}

/** The records a container carries, with the path of each (core 1.6). */
function contained(record: OipRecord): [path: string, record: object][] {
  switch (record.type) {
    case "Bundle":
      return [
        ...record.log.map((event, i): [string, object] => [`/log/${i}`, event]),
        ...(record.location === undefined
          ? []
          : [["/location", record.location] as [string, object]]),
        ...(record.participant === undefined
          ? []
          : [["/participant", record.participant] as [string, object]]),
      ];
    case "LogPage":
      return record.events.map((event, i) => [`/events/${i}`, event]);
    case "FeedPage":
      return record.entries.map((entry, i) => [`/entries/${i}`, entry]);
    case "DuplicityEvidence":
      return record.pairs.flatMap((pair, i) =>
        pair.map((event, j): [string, object] => [`/pairs/${i}/${j}`, event]),
      );
    default:
      return [];
  }
}

/**
 * Checks a validated record against the size limit of core 1.6: its
 * canonical form, proofs included, is at most 1 MiB. For the containers
 * (`Bundle`, `LogPage`, `FeedPage`, `DuplicityEvidence`) the limit applies to
 * each record they contain and not to the container. A `Sealed` record may
 * exceed it by its encoding overhead.
 *
 * The answer is the issues found: none if the record is within the limit.
 */
export function checkSize(record: OipRecord): Issue[] {
  const tooLarge = (path: string, size: number, limit: number): Issue => ({
    path,
    message: `the canonical form is ${size} bytes; the limit is ${limit}. Carry larger content by reference`,
    clause: "core 1.6",
  });
  if ((CONTAINER_RECORD_TYPES as readonly string[]).includes(record.type)) {
    return contained(record).flatMap(([path, inner]) => {
      const size = sizeOf(inner);
      return size > MAX_RECORD_BYTES ? [tooLarge(path, size, MAX_RECORD_BYTES)] : [];
    });
  }
  const limit = record.type === "Sealed" ? MAX_SEALED_BYTES : MAX_RECORD_BYTES;
  const size = sizeOf(record);
  return size > limit ? [tooLarge("", size, limit)] : [];
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
  options: ParseOptions = {},
): Validation<OipRecord> {
  const parsed =
    typeof input === "string" ? parseJson(input, options) : parseJsonBytes(input, options);
  if (!parsed.ok) return parsed;
  const validated = validateRecord(parsed.value);
  if (!validated.ok) return validated;
  const [first, ...rest] = checkSize(validated.value);
  return first === undefined ? ok(validated.value) : { ok: false, issues: [first, ...rest] };
}
