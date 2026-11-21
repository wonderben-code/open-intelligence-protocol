// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A lock is what the keys of a role are sealed under: a passphrase, or a
 * secret the operating system's keychain holds. It yields the 32-byte key of
 * the cipher, and says in a header, which is stored in the clear, how that
 * key is found again.
 *
 * Key derivation is scrypt (RFC 7914) from `@noble/hashes` (ADR-0002,
 * ADR-0017). Nothing here implements it.
 */

import { scryptAsync } from "@noble/hashes/scrypt.js";
import { base64urlToBytes, bytesToBase64url, utf8 } from "@oip/core";

import { KeystoreError } from "./errors.ts";
import { draw, type Randomness } from "./randomness.ts";

/** The length of the cipher's key, in bytes. */
export const KEY_LENGTH = 32;

/** How a passphrase was stretched into a key: the parameters of scrypt, and its salt. */
export interface ScryptHeader {
  /** A passphrase, stretched with scrypt. */
  readonly kind: "scrypt";
  /** The work factor N: a power of two from `SCRYPT_MIN_N` to `SCRYPT_MAX_N`. */
  readonly n: number;
  /** The block size: 8. */
  readonly r: number;
  /** The parallelisation: 1. */
  readonly p: number;
  /** base64url, 16 to 64 bytes. */
  readonly salt: string;
}

/** Where in the operating system's keychain the key is. */
export interface KeychainHeader {
  /** A random key that a keychain keeps. */
  readonly kind: "keychain";
  /** The service the key is kept under: the one the lock was made with. */
  readonly service: string;
  /** The account: `<keystore>/<role>`. */
  readonly account: string;
}

/** How the key of a sealed document is found again. Stored in the clear, and authenticated. */
export type LockHeader = ScryptHeader | KeychainHeader;

/** What a key is for: a lock gives a different key for each. */
export interface LockContext {
  /** The keystore's identifier. */
  readonly keystore: string;
  /** The role whose keys are sealed, or `backup`. */
  readonly role: string;
}

/** What seals and opens the keys of a role. */
export interface Lock {
  /**
   * A header for something that is about to be sealed for the first time, or
   * sealed afresh, and the key that goes with it.
   *
   * @throws KeystoreError `weak-lock` if the lock is too weak to seal under.
   */
  fresh(
    context: LockContext,
    randomness: Randomness,
  ): Promise<{ header: LockHeader; key: Uint8Array }>;
  /**
   * The key for what was sealed under a header.
   *
   * @throws KeystoreError `not-opened` if this lock is of another kind than
   *   the header, or holds nothing for it.
   */
  key(header: LockHeader, context: LockContext): Promise<Uint8Array>;
}

/** The work factor a new passphrase lock uses: 2^17, which takes 128 MiB (ADR-0017). */
export const SCRYPT_N = 2 ** 17;
/** The least work factor accepted, for reading and for sealing. */
export const SCRYPT_MIN_N = 2 ** 14;
/** The greatest work factor accepted: 2^20, which takes 1 GiB. A stored document cannot ask for more. */
export const SCRYPT_MAX_N = 2 ** 20;
/** The block size of scrypt, fixed. */
export const SCRYPT_R = 8;
/** The parallelisation of scrypt, fixed. */
export const SCRYPT_P = 1;
/** The length of a new salt, in bytes. */
export const SALT_LENGTH = 32;
/** The fewest characters a passphrase may have to seal under. */
export const MIN_PASSPHRASE_LENGTH = 8;

/** Whether a work factor is one this implementation derives a key with. */
export function isScryptWork(n: unknown): n is number {
  return (
    typeof n === "number" &&
    Number.isSafeInteger(n) &&
    n >= SCRYPT_MIN_N &&
    n <= SCRYPT_MAX_N &&
    (n & (n - 1)) === 0
  );
}

/** What `passphrase` takes besides the passphrase. */
export interface PassphraseOptions {
  /**
   * The work factor N of scrypt for what this lock seals afresh: a power of
   * two from `SCRYPT_MIN_N` to `SCRYPT_MAX_N`. Default: `SCRYPT_N`. What is
   * already sealed is opened with the work factor it was sealed with.
   */
  readonly n?: number;
}

/**
 * A lock that is a passphrase. The passphrase is normalised (NFKC), so that
 * it is the same bytes however a keyboard composed it, and stretched with
 * scrypt under a salt of its own for each thing sealed.
 *
 * The lock keeps the passphrase for as long as it lives. Let go of it once
 * the keys are unlocked.
 *
 * @throws KeystoreError `argument` if the passphrase is not a string with
 *   something in it, or the work factor is not one that is accepted.
 */
export function passphrase(text: string, options: PassphraseOptions = {}): Lock {
  if (typeof text !== "string" || text.length === 0) {
    throw new KeystoreError("argument", "a passphrase is a string with something in it");
  }
  const n = options.n ?? SCRYPT_N;
  if (!isScryptWork(n)) {
    throw new KeystoreError("argument", "the work factor of scrypt is not one that is accepted");
  }
  const normalised = text.normalize("NFKC");
  const secret = utf8(normalised);
  const derive = async (header: ScryptHeader): Promise<Uint8Array> => {
    const salt = base64urlToBytes(header.salt);
    if (salt === undefined) throw new KeystoreError("damaged");
    return scryptAsync(secret, salt, {
      N: header.n,
      r: header.r,
      p: header.p,
      dkLen: KEY_LENGTH,
      // What the greatest work factor accepted takes, and a little: 128 * N * r bytes.
      maxmem: 128 * SCRYPT_MAX_N * SCRYPT_R + 2 ** 20,
    });
  };
  return {
    fresh: async (_context, randomness) => {
      // Counted in code points, as a person counts most characters, not in UTF-16 code units.
      let characters = 0;
      for (const _ of normalised) characters += 1;
      if (characters < MIN_PASSPHRASE_LENGTH) {
        throw new KeystoreError(
          "weak-lock",
          `a passphrase has at least ${String(MIN_PASSPHRASE_LENGTH)} characters`,
        );
      }
      const header: ScryptHeader = {
        kind: "scrypt",
        n,
        r: SCRYPT_R,
        p: SCRYPT_P,
        salt: bytesToBase64url(draw(randomness, SALT_LENGTH)),
      };
      return { header, key: await derive(header) };
    },
    key: (header) => {
      if (header.kind !== "scrypt") return Promise.reject(new KeystoreError("not-opened"));
      return derive(header);
    },
  };
}

/**
 * The operating system's keychain, or anything that keeps a secret under two
 * names. `@oip/keystore/node` has the one of the platform.
 */
export interface Keychain {
  /** The secret kept under a service and an account, or `undefined`. */
  get(service: string, account: string): Promise<string | undefined>;
  /** Keeps a secret, replacing the one there. */
  set(service: string, account: string, secret: string): Promise<void>;
  /** Removes a secret. Removing one that is not there is not an error. */
  delete(service: string, account: string): Promise<void>;
}

/** The longest name of a service or an account in a keychain header. */
export const MAX_KEYCHAIN_NAME = 128;

/**
 * A lock that is a random key the keychain keeps: one for each role of each
 * keystore, under the account `<keystore>/<role>`. Nobody chooses or types
 * it, so it is as strong as the keychain is.
 *
 * @param keychain - Where the keys are kept.
 * @param service - The name they are kept under, such as `oip`.
 * @throws KeystoreError `argument` if the service is not a short name.
 */
export function keychainLock(keychain: Keychain, service: string): Lock {
  if (typeof service !== "string" || service.length === 0 || service.length > MAX_KEYCHAIN_NAME) {
    throw new KeystoreError("argument", "a keychain service is a short name");
  }
  return {
    fresh: async (context, randomness) => {
      const account = `${context.keystore}/${context.role}`;
      const key = draw(randomness, KEY_LENGTH);
      await keychain.set(service, account, bytesToBase64url(key));
      return { header: { kind: "keychain", service, account }, key };
    },
    key: async (header, context) => {
      // The header is read from storage: it does not send this lock to another keystore's secret.
      if (
        header.kind !== "keychain" ||
        header.service !== service ||
        header.account !== `${context.keystore}/${context.role}`
      ) {
        throw new KeystoreError("not-opened");
      }
      const kept = await keychain.get(header.service, header.account);
      const key = kept === undefined ? undefined : base64urlToBytes(kept);
      if (key?.length !== KEY_LENGTH) throw new KeystoreError("not-opened");
      return key;
    },
  };
}
