// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A sealed document: what a keystore writes to its storage. It is JSON, in
 * canonical form, with a header in the clear and a ciphertext.
 *
 * The cipher is XChaCha20-Poly1305 from `@noble/ciphers` (ADR-0002,
 * ADR-0017), under a 32-byte key that a lock gives and a nonce of 24 random
 * bytes, which is long enough to be drawn afresh for every sealing under one
 * key. The header is the associated data: a document whose header was
 * changed, to another role, another keystore or other parameters, does not
 * open.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import {
  base64urlToBytes,
  bytesToBase64url,
  canonicalBytes,
  type JsonObject,
  type JsonValue,
  parseJsonBytes,
} from "@oip/core";

import { KeystoreError } from "./errors.ts";
import {
  isScryptWork,
  KEY_LENGTH,
  type LockHeader,
  MAX_KEYCHAIN_NAME,
  SCRYPT_P,
  SCRYPT_R,
} from "./lock.ts";
import { draw, type Randomness } from "./randomness.ts";

/** The format this implementation writes and reads. */
export const FORMAT = "oip-keystore/1";

/** The length of a nonce of XChaCha20-Poly1305, in bytes. */
export const NONCE_LENGTH = 24;
/** The length of the tag of Poly1305, in bytes. */
export const TAG_LENGTH = 16;
/** The length of a keystore's identifier, in bytes. */
export const KEYSTORE_ID_LENGTH = 16;
/** The longest sealed document read, in bytes. */
export const MAX_DOCUMENT_BYTES = 4 * 2 ** 20;

/** What is sealed: the keys of a role, or a backup of all of them. */
export const SEALED_KINDS = [
  "control",
  "operational",
  "invocation",
  "agreement",
  "backup",
] as const;
/** One of `SEALED_KINDS`. */
export type SealedKind = (typeof SEALED_KINDS)[number];

/** What a sealed document says of itself in the clear. Every member is authenticated. */
export interface SealedHeader {
  /** The format: `oip-keystore/1`. */
  readonly format: typeof FORMAT;
  /** The keystore's identifier: base64url, 16 bytes. */
  readonly keystore: string;
  /** What is sealed. */
  readonly role: SealedKind;
  /**
   * How many times the set of keys sealed here has changed. A backup is of
   * a generation of each role, and is out of date once one has moved on.
   */
  readonly generation: number;
  /** How the key is found again. */
  readonly lock: LockHeader;
}

/** A sealed document as read: its header, and what the cipher needs. */
export interface Sealed {
  readonly header: SealedHeader;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

/**
 * Seals a plaintext under a key, with the header as associated data.
 *
 * @returns The document, as the bytes a storage keeps.
 */
export function sealDocument(
  header: SealedHeader,
  key: Uint8Array,
  plaintext: Uint8Array,
  randomness: Randomness,
): Uint8Array {
  if (key.length !== KEY_LENGTH) throw new KeystoreError("argument", "a key is 32 bytes");
  const nonce = draw(randomness, NONCE_LENGTH);
  const ciphertext = xchacha20poly1305(key, nonce, associated(header)).encrypt(plaintext);
  return canonicalBytes({
    ...headerValue(header),
    nonce: bytesToBase64url(nonce),
    ciphertext: bytesToBase64url(ciphertext),
  });
}

/**
 * Opens a sealed document.
 *
 * @throws KeystoreError `not-opened` if the key is not the one it was sealed
 *   under, or the document was changed since: the cipher cannot tell which.
 */
export function openDocument(sealed: Sealed, key: Uint8Array): Uint8Array {
  if (key.length !== KEY_LENGTH) throw new KeystoreError("not-opened");
  try {
    return xchacha20poly1305(key, sealed.nonce, associated(sealed.header)).decrypt(
      sealed.ciphertext,
    );
  } catch {
    throw new KeystoreError("not-opened");
  }
}

/** The header as the cipher authenticates it: its canonical form. */
function associated(header: SealedHeader): Uint8Array {
  return canonicalBytes(headerValue(header));
}

/** The header with its members and no others, whatever object carried them. */
function headerValue(header: SealedHeader): JsonObject {
  const lock: JsonObject =
    header.lock.kind === "scrypt"
      ? {
          kind: "scrypt",
          n: header.lock.n,
          r: header.lock.r,
          p: header.lock.p,
          salt: header.lock.salt,
        }
      : { kind: "keychain", service: header.lock.service, account: header.lock.account };
  return {
    format: header.format,
    keystore: header.keystore,
    role: header.role,
    generation: header.generation,
    lock,
  };
}

/**
 * Reads a sealed document from the bytes a storage gave. What is stored is
 * not trusted: every member is checked before anything is derived from it,
 * so that a document cannot ask for more work or memory than a lock allows.
 *
 * @throws KeystoreError `unsupported` if it is of a later format, or asks for
 *   settings this implementation refuses; `damaged` if it is not a sealed
 *   document at all.
 */
export function readSealed(bytes: Uint8Array): Sealed {
  const parsed = parseJsonBytes(bytes, { maxLength: MAX_DOCUMENT_BYTES });
  if (!parsed.ok) throw new KeystoreError("damaged");
  const document = members(parsed.value, [
    "format",
    "keystore",
    "role",
    "generation",
    "lock",
    "nonce",
    "ciphertext",
  ]);
  if (document === undefined) throw new KeystoreError("damaged");
  const { format, keystore, role, generation } = document;
  if (format !== FORMAT) {
    const later = typeof format === "string" && /^oip-keystore\/[1-9][0-9]{0,8}$/u.test(format);
    throw new KeystoreError(later ? "unsupported" : "damaged");
  }
  if (bytesOf(keystore)?.length !== KEYSTORE_ID_LENGTH) throw new KeystoreError("damaged");
  if (!SEALED_KINDS.includes(role as SealedKind)) throw new KeystoreError("damaged");
  if (typeof generation !== "number" || !Number.isSafeInteger(generation) || generation < 0) {
    throw new KeystoreError("damaged");
  }
  const nonce = bytesOf(document["nonce"]);
  const ciphertext = bytesOf(document["ciphertext"]);
  if (nonce?.length !== NONCE_LENGTH || ciphertext === undefined) {
    throw new KeystoreError("damaged");
  }
  if (ciphertext.length < TAG_LENGTH) throw new KeystoreError("damaged");
  return {
    header: {
      format: FORMAT,
      keystore: keystore as string,
      role: role as SealedKind,
      generation,
      lock: lockOf(document["lock"]),
    },
    nonce,
    ciphertext,
  };
}

/** The lock header of a document, checked. */
function lockOf(value: JsonValue | undefined): LockHeader {
  const kind = isObject(value) ? value["kind"] : undefined;
  if (kind === "scrypt") {
    const lock = members(value, ["kind", "n", "r", "p", "salt"]);
    if (lock === undefined) throw new KeystoreError("damaged");
    const salt = bytesOf(lock["salt"]);
    if (salt === undefined || salt.length < 16 || salt.length > 64) {
      throw new KeystoreError("damaged");
    }
    // Checked before any key is derived: the work a document asks for is bounded here.
    if (!isScryptWork(lock["n"]) || lock["r"] !== SCRYPT_R || lock["p"] !== SCRYPT_P) {
      throw new KeystoreError("unsupported");
    }
    return { kind, n: lock["n"], r: SCRYPT_R, p: SCRYPT_P, salt: lock["salt"] as string };
  }
  if (kind === "keychain") {
    const lock = members(value, ["kind", "service", "account"]);
    const service = lock?.["service"];
    const account = lock?.["account"];
    if (!isName(service) || !isName(account)) throw new KeystoreError("damaged");
    return { kind, service, account };
  }
  throw new KeystoreError(typeof kind === "string" ? "unsupported" : "damaged");
}

const isName = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= MAX_KEYCHAIN_NAME;

/** The bytes a base64url string stands for, or `undefined`. */
function bytesOf(value: JsonValue | undefined): Uint8Array | undefined {
  return typeof value === "string" ? base64urlToBytes(value) : undefined;
}

const isObject = (value: JsonValue | undefined): value is Readonly<Record<string, JsonValue>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The value as an object with exactly these members, or `undefined`. */
export function members(
  value: JsonValue | undefined,
  names: readonly string[],
  optional: readonly string[] = [],
): Readonly<Record<string, JsonValue>> | undefined {
  if (!isObject(value)) return undefined;
  const object = value;
  const present = Object.keys(object);
  if (!names.every((name) => Object.hasOwn(object, name))) return undefined;
  if (!present.every((name) => names.includes(name) || optional.includes(name))) return undefined;
  return object;
}
