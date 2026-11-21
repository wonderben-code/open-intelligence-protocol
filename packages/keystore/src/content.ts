// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What is sealed: the keys of one role, as JSON in canonical form.
 *
 * What comes out of a sealed document was authenticated by the cipher. It is
 * checked all the same, member by member, and each public key is worked out
 * again from its private key: a keystore must never hand out a signer whose
 * public key is not the one it signs with.
 */

import {
  base64urlToBytes,
  bytesToBase64url,
  canonicalBytes,
  ed25519PublicKey,
  encodeEd25519Multikey,
  encodeX25519Multikey,
  type JsonObject,
  type JsonValue,
  parseJsonBytes,
  PRIVATE_KEY_LENGTH,
  x25519PublicKey,
} from "@oip/core";

import { KeystoreError } from "./errors.ts";
import { draw, type Randomness } from "./randomness.ts";
import { MAX_DOCUMENT_BYTES, members } from "./seal.ts";

/**
 * The roles of a mind's keys (Layer 1, 3.4 and 3.5). Each is sealed apart
 * from the others, under a lock of its own if its owner wants one.
 *
 * - `control`: the keys that sign the mind's identity events. Each signs one
 *   event and is destroyed once that event is published (Layer 1, 3.11).
 * - `operational`: the keys that sign the mind's everyday records.
 * - `invocation`: the keys with which the mind, as a member, signs another
 *   mind's identity events.
 * - `agreement`: the X25519 keys to which records are sealed for the mind.
 */
export const KEY_ROLES = ["control", "operational", "invocation", "agreement"] as const;
/** One of `KEY_ROLES`. */
export type KeyRole = (typeof KEY_ROLES)[number];

/** The most keys one role holds. */
export const MAX_KEYS = 256;
/** The longest label of a key, as in an identity event (Layer 1, 3.5). */
export const MAX_LABEL_LENGTH = 64;
/** The most positions an invocation key remembers having signed for. */
export const MAX_POSITIONS = 10_000;

/** A key as the keystore holds it while its role is unlocked. */
export interface HeldKey {
  /** The Multikey of the public key: Ed25519, or X25519 for an agreement key. */
  readonly publicKey: string;
  /** Zeroed when the role is locked or the key is destroyed. */
  readonly privateKey: Uint8Array;
  label: string | undefined;
  /** A control key: the identity event it was asked to sign, until that event is published. */
  signing: JsonObject | undefined;
  /** An invocation key: the event it signed at each position, as `<mind>#<seq>` to content ID. */
  readonly signed: Map<string, string>;
}

/** The public key of a private key of a role, as a Multikey. */
export function publicKeyOf(role: KeyRole, privateKey: Uint8Array): string {
  return role === "agreement"
    ? encodeX25519Multikey(x25519PublicKey(privateKey))
    : encodeEd25519Multikey(ed25519PublicKey(privateKey));
}

/** A new key of a role, from 32 random bytes. */
export function newKey(role: KeyRole, randomness: Randomness, label?: string): HeldKey {
  const privateKey = draw(randomness, PRIVATE_KEY_LENGTH);
  return {
    publicKey: publicKeyOf(role, privateKey),
    privateKey,
    label,
    signing: undefined,
    signed: new Map(),
  };
}

/** The keys of a role as the plaintext that is sealed. */
export function encodeContent(keys: readonly HeldKey[]): Uint8Array {
  return canonicalBytes({ keys: keys.map((key) => keyValue(key)) });
}

/** One key as it is written. */
export function keyValue(key: HeldKey): JsonObject {
  return {
    publicKey: key.publicKey,
    privateKey: bytesToBase64url(key.privateKey),
    ...(key.label === undefined ? {} : { label: key.label }),
    ...(key.signing === undefined ? {} : { signing: key.signing }),
    ...(key.signed.size === 0 ? {} : { signed: Object.fromEntries(key.signed) }),
  };
}

/**
 * The keys of a role from an opened plaintext.
 *
 * @throws KeystoreError `damaged` if it is not what a keystore seals.
 */
export function decodeContent(role: KeyRole, plaintext: Uint8Array): HeldKey[] {
  const parsed = parseJsonBytes(plaintext, { maxLength: MAX_DOCUMENT_BYTES });
  if (!parsed.ok) throw new KeystoreError("damaged");
  return keysOf(role, parsed.value);
}

/** The keys of a role from the value that was sealed. */
export function keysOf(role: KeyRole, value: JsonValue | undefined): HeldKey[] {
  const content = members(value, ["keys"]);
  const listed = content?.["keys"];
  if (!isArray(listed) || listed.length > MAX_KEYS) throw new KeystoreError("damaged");
  const keys = listed.map((entry) => keyOf(role, entry));
  if (new Set(keys.map((key) => key.publicKey)).size !== keys.length) {
    throw new KeystoreError("damaged");
  }
  return keys;
}

function keyOf(role: KeyRole, value: JsonValue): HeldKey {
  const entry = members(value, ["publicKey", "privateKey"], ["label", "signing", "signed"]);
  if (entry === undefined) throw new KeystoreError("damaged");
  const { label, signing, signed } = entry;
  const privateKey =
    typeof entry["privateKey"] === "string" ? base64urlToBytes(entry["privateKey"]) : undefined;
  if (privateKey?.length !== PRIVATE_KEY_LENGTH) throw new KeystoreError("damaged");
  // The public key is the private key's own, whatever the document says.
  if (publicKeyOf(role, privateKey) !== entry["publicKey"]) throw new KeystoreError("damaged");
  if (label !== undefined && !isLabel(label)) throw new KeystoreError("damaged");
  if (signing !== undefined && (role !== "control" || !isObject(signing))) {
    throw new KeystoreError("damaged");
  }
  const positions = new Map<string, string>();
  if (signed !== undefined) {
    if (role !== "invocation" || !isObject(signed)) throw new KeystoreError("damaged");
    const entries = Object.entries(signed);
    if (entries.length > MAX_POSITIONS) throw new KeystoreError("damaged");
    for (const [position, event] of entries) {
      if (typeof event !== "string") throw new KeystoreError("damaged");
      positions.set(position, event);
    }
  }
  return {
    publicKey: entry["publicKey"],
    privateKey,
    label,
    signing,
    signed: positions,
  };
}

/** Whether a value is a label a key may have. */
export function isLabel(value: unknown): value is string {
  return typeof value === "string" && value.length <= MAX_LABEL_LENGTH;
}

const isArray = (value: JsonValue | undefined): value is readonly JsonValue[] =>
  Array.isArray(value);

const isObject = (value: JsonValue): value is JsonObject =>
  typeof value === "object" && value !== null && !Array.isArray(value);
