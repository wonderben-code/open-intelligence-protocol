// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Public keys as Multikey strings (core 4.1 to 4.3). */

import { patterns, type Validation } from "@oip/schema";
import { base58 } from "@scure/base";

import { concatBytes } from "./bytes.ts";
import { isEd25519PublicKey, PUBLIC_KEY_LENGTH } from "./ed25519.ts";
import { no, ok } from "./result.ts";

/** The key types of this revision (core 4.3). */
export type KeyType = "Ed25519" | "X25519";

interface Codec {
  readonly type: KeyType;
  /** The multicodec prefix (core 4.1). */
  readonly prefix: Uint8Array;
  /** The form of the string: its fixed start and its length. */
  readonly pattern: RegExp;
  readonly start: string;
}

const ED25519: Codec = {
  type: "Ed25519",
  prefix: Uint8Array.of(0xed, 0x01),
  pattern: new RegExp(patterns.ed25519Multikey),
  start: "z6Mk",
};

const X25519: Codec = {
  type: "X25519",
  prefix: Uint8Array.of(0xec, 0x01),
  pattern: new RegExp(patterns.x25519Multikey),
  start: "z6LS",
};

function encode(codec: Codec, publicKey: Uint8Array): string {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new TypeError(`an ${codec.type} public key is 32 bytes`);
  }
  return `z${base58.encode(concatBytes(codec.prefix, publicKey))}`;
}

/** core 4.2: the prefix and the length of a Multikey are checked before it is used. */
function decode(codec: Codec, multikey: unknown): Validation<Uint8Array> {
  const wrong = `not an ${codec.type} public key as a Multikey: expected "${codec.start}" followed by 44 base58 characters, which decode to the prefix and 32 bytes`;
  // The pattern bounds the length before any decoding is done.
  if (typeof multikey !== "string" || !codec.pattern.test(multikey)) return no(wrong, "core 4.2");
  const bytes = base58.decode(multikey.slice(1));
  // A few strings of the right form decode to other bytes, so both are checked.
  if (
    bytes.length !== codec.prefix.length + PUBLIC_KEY_LENGTH ||
    bytes[0] !== codec.prefix[0] ||
    bytes[1] !== codec.prefix[1]
  ) {
    return no(wrong, "core 4.2");
  }
  return ok(bytes.slice(codec.prefix.length));
}

/**
 * Writes an Ed25519 public key as a Multikey (core 4.1).
 *
 * @throws TypeError if the key is not 32 bytes, or is not a point of order
 * exactly L: no verifier would accept it (core 4.4).
 */
export function encodeEd25519Multikey(publicKey: Uint8Array): string {
  const multikey = encode(ED25519, publicKey);
  if (!isEd25519PublicKey(publicKey)) {
    throw new TypeError("not an Ed25519 public key: it is not a point of order L (core 4.4)");
  }
  return multikey;
}

/**
 * Reads an Ed25519 public key from a Multikey, checking its prefix and length
 * (core 4.2) and that it is a point of order exactly L (core 4.4).
 */
export function decodeEd25519Multikey(multikey: unknown): Validation<Uint8Array> {
  const decoded = decode(ED25519, multikey);
  if (!decoded.ok) return decoded;
  if (!isEd25519PublicKey(decoded.value)) {
    return no(
      "the Ed25519 key is not the canonical encoding of a point of order L, so no signature by it is accepted",
      "core 4.4",
    );
  }
  return decoded;
}

/** Whether a value is an Ed25519 public key this revision accepts, as a Multikey. */
export function isEd25519Multikey(multikey: unknown): multikey is string {
  return decodeEd25519Multikey(multikey).ok;
}

/**
 * Writes an X25519 public key as a Multikey (core 4.1).
 *
 * @throws TypeError if the key is not 32 bytes.
 */
export function encodeX25519Multikey(publicKey: Uint8Array): string {
  return encode(X25519, publicKey);
}

/** Reads an X25519 public key from a Multikey, checking its prefix and length (core 4.2). */
export function decodeX25519Multikey(multikey: unknown): Validation<Uint8Array> {
  return decode(X25519, multikey);
}

/** Whether a value is an X25519 public key as a Multikey. */
export function isX25519Multikey(multikey: unknown): multikey is string {
  return decodeX25519Multikey(multikey).ok;
}
