// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The one exception the keystore throws. Its messages are built from
 * constants and public values: no passphrase, private key or decrypted
 * content is ever in one (ADR-0004).
 */

/** Why the keystore could not do what was asked. */
export const KEYSTORE_ERRORS = {
  "not-opened":
    "the lock does not open this: the passphrase is wrong, or what is stored was changed",
  damaged: "what is stored is not something this keystore wrote",
  unsupported: "what is stored was written by a later version, or with settings this one refuses",
  exists: "a keystore is already stored here",
  "not-found": "nothing of that name is stored here",
  changed: "what is stored was changed by someone else since it was read",
  locked: "these keys were locked",
  "in-use": "the keys of this role are already unlocked",
  "already-signed": "this key has been asked to sign another identity event",
  "weak-lock": "the lock is too weak to keep keys under",
  unsafe: "where the keys would be kept is open to others",
  "no-keychain": "the keychain of this machine could not be used",
  argument: "an argument is not what the keystore takes",
} as const;

/** One of the keystore's reasons. */
export type KeystoreErrorCode = keyof typeof KEYSTORE_ERRORS;

/** Thrown when the keystore cannot do what was asked. `code` says why. */
export class KeystoreError extends Error {
  /** The name of the error: `KeystoreError`. */
  override readonly name = "KeystoreError";
  /** Why: one of `KEYSTORE_ERRORS`. */
  readonly code: KeystoreErrorCode;

  /**
   * @param code - The reason.
   * @param detail - What it was about, in words that hold nothing secret.
   */
  constructor(code: KeystoreErrorCode, detail?: string) {
    super(detail === undefined ? KEYSTORE_ERRORS[code] : `${KEYSTORE_ERRORS[code]}: ${detail}`);
    this.code = code;
  }
}
