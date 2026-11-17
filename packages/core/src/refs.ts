// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** References (core Section 6): addresses, versions, key references and record references. */

import { patterns } from "@oip/schema";

import { contentId, isContentId } from "./content-id.ts";

const MIND_ADDRESS = new RegExp(patterns.mindAddress);
const VERSION_ID = new RegExp(patterns.versionId);
const VERSIONED_MIND = new RegExp(patterns.versionedMind);
const KEY_REF = new RegExp(patterns.keyRef);
const CONTROL_KEY_REF = new RegExp(patterns.controlKeyRef);
const RECORD_REF = new RegExp(patterns.recordRef);
const MULTIKEY = /^z[1-9A-HJ-NP-Za-km-z]+$/;

const DID_OIP = "did:oip:";
const DID_KEY = "did:key:";
const VERSION_QUERY = "?versionId=";
/** A mind address is "did:oip:" and a content ID of 56 characters. */
const ADDRESS_LENGTH = DID_OIP.length + 56;

function need(condition: boolean, what: string): asserts condition {
  if (!condition) throw new TypeError(what);
}

/** Whether a value is a mind address, `did:oip:<content-id>` (core 6.1). */
export function isMindAddress(value: unknown): value is string {
  return typeof value === "string" && MIND_ADDRESS.test(value);
}

/**
 * The address of the mind whose genesis event has this content ID.
 *
 * @throws TypeError if the value is not a content ID.
 */
export function mindAddress(genesisContentId: string): string {
  need(isContentId(genesisContentId), "a mind address is made from a content ID");
  return DID_OIP + genesisContentId;
}

/** The content ID inside a mind address, or `undefined` if the value is not one. */
export function mindId(address: unknown): string | undefined {
  return isMindAddress(address) ? address.slice(DID_OIP.length) : undefined;
}

/** A version of a mind's identity: a position in its log and the event at that position (core 6.1). */
export interface VersionId {
  /** The event's position in the log. The genesis is at 0. */
  readonly seq: number;
  /** The event's content ID. */
  readonly contentId: string;
}

/**
 * Reads a `version-id`, `<seq>-<content-id>`. The answer is `undefined` if
 * the value does not match the grammar, or if its position is beyond
 * 2^53 - 1: no event has such a position (core 1.2), so no version has.
 */
export function parseVersionId(value: unknown): VersionId | undefined {
  if (typeof value !== "string" || !VERSION_ID.test(value)) return undefined;
  const dash = value.indexOf("-");
  const seq = Number(value.slice(0, dash));
  if (!Number.isSafeInteger(seq)) return undefined;
  return { seq, contentId: value.slice(dash + 1) };
}

/**
 * Writes a `version-id`.
 *
 * @throws TypeError if `seq` is not a non-negative safe integer or the other value is not a content ID.
 */
export function formatVersionId(seq: number, eventContentId: string): string {
  need(Number.isSafeInteger(seq) && seq >= 0, "a position in a log is a non-negative integer");
  need(isContentId(eventContentId), "a version names its event by content ID");
  return `${seq}-${eventContentId}`;
}

/** A mind at one version of its identity (core 6.1, `versioned-mind`). */
export interface VersionedMind {
  readonly mind: string;
  /** The version as written, `<seq>-<content-id>`. */
  readonly versionId: string;
  readonly version: VersionId;
}

/** Reads a `versioned-mind`, `<address>?versionId=<version-id>`. */
export function parseVersionedMind(value: unknown): VersionedMind | undefined {
  if (typeof value !== "string" || !VERSIONED_MIND.test(value)) return undefined;
  const versionId = value.slice(ADDRESS_LENGTH + VERSION_QUERY.length);
  const version = parseVersionId(versionId);
  if (version === undefined) return undefined;
  return { mind: value.slice(0, ADDRESS_LENGTH), versionId, version };
}

/** A reference to an operational key, pinned to a version of its mind's identity (core 6.2). */
export interface KeyRef extends VersionedMind {
  readonly kind: "key";
  /** The key, as a Multikey string. Its type is checked when it is used (core 4.2). */
  readonly key: string;
}

/** A reference to a control key, which names only the key (core 6.2). */
export interface ControlKeyRef {
  readonly kind: "control";
  /** The key, as a Multikey string. */
  readonly key: string;
}

/** What a proof's `verificationMethod` names. */
export type VerificationMethod = KeyRef | ControlKeyRef;

/** Reads a `key-ref`, `<address>?versionId=<version-id>#<multikey>`. */
export function parseKeyRef(value: unknown): KeyRef | undefined {
  if (typeof value !== "string" || !KEY_REF.test(value)) return undefined;
  const hash = value.indexOf("#");
  const versioned = parseVersionedMind(value.slice(0, hash));
  if (versioned === undefined) return undefined;
  return { kind: "key", ...versioned, key: value.slice(hash + 1) };
}

/**
 * Reads a `control-key-ref`, `did:key:<multikey>#<multikey>`. Both
 * occurrences of the key must be identical (core 6.2).
 */
export function parseControlKeyRef(value: unknown): ControlKeyRef | undefined {
  if (typeof value !== "string" || !CONTROL_KEY_REF.test(value)) return undefined;
  const hash = value.indexOf("#");
  const key = value.slice(hash + 1);
  if (value.slice(DID_KEY.length, hash) !== key) return undefined;
  return { kind: "control", key };
}

/** Reads a proof's `verificationMethod`: a `key-ref` or a `control-key-ref`. */
export function parseVerificationMethod(value: unknown): VerificationMethod | undefined {
  return parseKeyRef(value) ?? parseControlKeyRef(value);
}

/**
 * Writes a `key-ref`.
 *
 * @throws TypeError if a part does not have its form.
 */
export function formatKeyRef(mind: string, versionId: string, key: string): string {
  need(isMindAddress(mind), "a key reference starts with a mind address");
  need(parseVersionId(versionId) !== undefined, "a key reference pins a version of the identity");
  need(typeof key === "string" && MULTIKEY.test(key), "a key reference names a Multikey");
  return `${mind}${VERSION_QUERY}${versionId}#${key}`;
}

/**
 * Writes a `control-key-ref`.
 *
 * @throws TypeError if the key is not a Multikey string.
 */
export function formatControlKeyRef(key: string): string {
  need(typeof key === "string" && MULTIKEY.test(key), "a key reference names a Multikey");
  return `${DID_KEY}${key}#${key}`;
}

/** A reference to a record: where to fetch it from, and its content ID (core 6.3). */
export interface RecordRef {
  /** The mind whose records to fetch it from. Only a hint: it is ignored when matching. */
  readonly mind: string;
  readonly contentId: string;
}

/** Reads a `record-ref`, `<address>/<content-id>`. */
export function parseRecordRef(value: unknown): RecordRef | undefined {
  if (typeof value !== "string" || !RECORD_REF.test(value)) return undefined;
  return { mind: value.slice(0, ADDRESS_LENGTH), contentId: value.slice(ADDRESS_LENGTH + 1) };
}

/**
 * Writes a `record-ref`.
 *
 * @throws TypeError if a part does not have its form.
 */
export function formatRecordRef(mind: string, recordContentId: string): string {
  need(isMindAddress(mind), "a record reference starts with a mind address");
  need(isContentId(recordContentId), "a record reference names a content ID");
  return `${mind}/${recordContentId}`;
}

/**
 * Whether a `record-ref` names a record (core 6.3): its content ID equals
 * the record's. The mind part is ignored. A value that is not a record-ref,
 * or a record that has no content ID, matches nothing.
 */
export function recordRefMatches(ref: unknown, record: unknown): boolean {
  const parsed = parseRecordRef(ref);
  if (parsed === undefined) return false;
  try {
    return contentId(record) === parsed.contentId;
  } catch {
    return false;
  }
}
