// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Content identifiers and key hashes (core Section 3). */

import { type JsonValue, type Limits, patterns, validateJson, noteCutShort } from "@oip/schema";
import { base32nopad } from "@scure/base";

import { concatBytes, utf8 } from "./bytes.ts";
import { errorFrom, OipError } from "./errors.ts";
import { sha256 } from "./hash.ts";
import { canonicalBytesOf } from "./jcs.ts";

/** A JSON object within the profile of core Section 1. */
export type JsonObject = Readonly<Record<string, JsonValue>>;

/** The multihash prefix for a 32-byte SHA-256 digest (core 3.1). */
const MULTIHASH_SHA256 = Uint8Array.of(0x12, 0x20);

const CONTENT_ID = new RegExp(patterns.contentId);

/** Whether a value is a content ID in its one canonical spelling (core 3.2). */
export function isContentId(value: unknown): value is string {
  return typeof value === "string" && CONTENT_ID.test(value);
}

/** The content ID that carries a 32-byte SHA-256 digest (core 3.1). */
export function contentIdOfDigest(digest: Uint8Array): string {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    throw new TypeError("a content ID carries a SHA-256 digest of 32 bytes");
  }
  return `b${base32nopad.encode(concatBytes(MULTIHASH_SHA256, digest)).toLowerCase()}`;
}

/**
 * The 32-byte digest inside a content ID, or `undefined` if the string is
 * not a content ID in its canonical spelling (core 3.2). A spelling that
 * decodes to the same bytes but does not match the pattern is rejected.
 */
export function digestOfContentId(contentId: unknown): Uint8Array | undefined {
  if (!isContentId(contentId)) return undefined;
  // The pattern fixes the length and the alphabet, so decoding cannot fail.
  return base32nopad.decode(contentId.slice(1).toUpperCase()).subarray(2);
}

/** Whether a value is a JSON object: not an array, not null. */
export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A record without its `proof` member: what content IDs and proofs cover (core 3.1, 5.3). */
export function withoutProof(record: JsonObject): JsonObject {
  const { proof: _proof, ...rest } = record;
  return rest;
}

/**
 * The SHA-256 digest of a record's canonical form without `proof`, for a
 * record already known to be within the JSON profile. It is the digest
 * inside the record's content ID, and the `transformedDocumentHash` of
 * every proof on the record (core 3.3).
 */
export function documentHashOf(record: JsonObject): Uint8Array {
  return sha256(canonicalBytesOf(withoutProof(record)));
}

function jsonObject(record: unknown, limits?: Limits): JsonObject {
  // A container has a content ID too, and may nest as deep as a container does.
  const checked = validateJson(record, "container", limits);
  if (!checked.ok) throw errorFrom(checked);
  if (!isJsonObject(checked.value)) {
    throw new OipError("invalid-record", "a record is a JSON object", { clause: "core 1.1" });
  }
  return checked.value;
}

/**
 * The SHA-256 digest of a record's canonical form without `proof`
 * (core 3.3).
 *
 * @throws OipError `invalid-record` if the value is not a JSON object within
 * the profile of core Section 1.
 */
export function documentHash(record: unknown, limits?: Limits): Uint8Array {
  return documentHashOf(jsonObject(record, limits));
}

/**
 * The content ID of a record (core 3.1). Proofs are not part of it, so adding
 * a signature never changes it.
 *
 * It is computed for any JSON object within the profile; that an object has a
 * content ID does not make it a well-formed record. Validate first.
 *
 * A value that did not come from text is read up to `MAX_VALUES` values. A
 * caller that has accepted a longer container says so with `limits`.
 *
 * @throws OipError `invalid-record` if the value is not a JSON object within
 * the profile of core Section 1.
 * @throws UnfitProcess if other code in the process has put a `toJSON` on the
 * prototype of every object or every array: nothing is hashed then.
 */
export function contentId(record: unknown, limits?: Limits): string {
  return contentIdOfDigest(documentHash(record, limits));
}

/**
 * The content ID of a value if it has one, and `undefined` if it is not a
 * JSON object within the profile. For code that judges: it never throws.
 */
export function contentIdIfAny(record: unknown): string | undefined {
  try {
    const checked = validateJson(record, "container");
    return checked.ok && isJsonObject(checked.value)
      ? contentIdOfDigest(documentHashOf(checked.value))
      : undefined;
  } catch (error) {
    noteCutShort(error);
    // Nothing could be worked out, so there is nothing to compare with.
    return undefined;
  }
}

/**
 * The key hash of a Multikey string, used for pre-rotation commitments
 * (core 3.4). It is the hash of the string as written, so it is defined for
 * any string; whether the string is a Multikey is checked where the key is
 * revealed.
 *
 * @throws TypeError if the value is not a string of valid Unicode.
 */
export function keyHash(multikey: string): string {
  if (typeof multikey !== "string") throw new TypeError("a key hash is the hash of a string");
  return contentIdOfDigest(sha256(utf8(multikey)));
}
