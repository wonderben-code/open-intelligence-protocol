// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `@oip/keystore`: the private keys of a mind, sealed and kept apart by role.
 *
 * This entry runs anywhere. `@oip/keystore/node` adds a storage that is a
 * directory.
 *
 * @packageDocumentation
 */

export { KEY_ROLES, type KeyRole, MAX_KEYS, MAX_LABEL_LENGTH, MAX_POSITIONS } from "./content.ts";
export { KEYSTORE_ERRORS, KeystoreError, type KeystoreErrorCode } from "./errors.ts";
export {
  AgreementKeys,
  ControlKeys,
  type ControlKeyInfo,
  type GenerateOptions,
  InvocationKeys,
  type KeyInfo,
  type MemberSigning,
  OperationalKeys,
  RoleKeys,
  type SealedToKey,
} from "./keys.ts";
export {
  type IdbDatabase,
  type IdbFactory,
  type IdbObjectStore,
  type IdbOpenRequest,
  type IdbRequest,
  type IdbTransaction,
  indexedDbStorage,
} from "./indexeddb.ts";
export {
  type AllKeys,
  type Backup,
  type CreateOptions,
  Keystore,
  type KeystoreOptions,
  type Locks,
  type RestoreOptions,
} from "./keystore.ts";
export {
  type Keychain,
  type KeychainHeader,
  keychainLock,
  KEY_LENGTH,
  type Lock,
  type LockContext,
  type LockHeader,
  MAX_KEYCHAIN_NAME,
  MIN_PASSPHRASE_LENGTH,
  passphrase,
  type PassphraseOptions,
  SALT_LENGTH,
  SCRYPT_MAX_N,
  SCRYPT_MIN_N,
  SCRYPT_N,
  SCRYPT_P,
  SCRYPT_R,
  type ScryptHeader,
} from "./lock.ts";
export { type Randomness, systemRandomness } from "./randomness.ts";
export {
  FORMAT,
  KEYSTORE_ID_LENGTH,
  MAX_DOCUMENT_BYTES,
  NONCE_LENGTH,
  SEALED_KINDS,
  type SealedHeader,
  type SealedKind,
  TAG_LENGTH,
} from "./seal.ts";
export { type KeyStorage, memoryStorage, STORAGE_NAME, type Stored } from "./storage.ts";
