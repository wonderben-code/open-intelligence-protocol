// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Where a keystore keeps its sealed documents. A storage holds named byte
 * strings and nothing else: it never sees a key or a passphrase.
 *
 * Every write names the version it replaces. Two writers of one document,
 * in one process or in two, cannot both succeed: the second is told that the
 * document changed. Without that, a writer that had read a compartment
 * before a control key was destroyed could write the key back.
 */

import { KeystoreError } from "./errors.ts";

/** A stored document, and the version a write must name to replace it. */
export interface Stored {
  /** The document, as it was written. */
  readonly value: Uint8Array;
  /** Opaque. It differs after every write. */
  readonly version: string;
}

/** Where sealed documents are kept. Names match `STORAGE_NAME`. */
export interface KeyStorage {
  /** The document of a name, or `undefined` if there is none. */
  get(name: string): Promise<Stored | undefined>;
  /**
   * Writes a document, replacing the version named.
   *
   * @param expected - The version read, or `undefined` if there must be no
   *   document of that name yet.
   * @returns The new version.
   * @throws KeystoreError `changed` if what is stored is not that version.
   */
  put(name: string, value: Uint8Array, expected: string | undefined): Promise<string>;
  /**
   * Removes a document.
   *
   * @throws KeystoreError `changed` if what is stored is not that version.
   */
  delete(name: string, expected: string): Promise<void>;
  /** The names of the documents held, in no particular order. */
  list(): Promise<string[]>;
}

/** The names a storage takes: a lower-case letter, then letters, digits and hyphens, 32 at most. */
export const STORAGE_NAME = /^[a-z][a-z0-9-]{0,31}$/u;

/** @throws KeystoreError `argument` if the name is not one a storage takes. */
export function checkStorageName(name: string): void {
  if (typeof name !== "string" || !STORAGE_NAME.test(name)) {
    throw new KeystoreError("argument", "a stored document has no such name");
  }
}

/**
 * A storage that lives in memory, and is gone with the process. For tests,
 * and for a mind that is meant to live no longer than its process.
 */
export function memoryStorage(): KeyStorage {
  const held = new Map<string, { value: Uint8Array; version: number }>();
  let writes = 0;
  const current = (name: string, expected: string | undefined): void => {
    const found = held.get(name);
    if ((found === undefined ? undefined : String(found.version)) !== expected) {
      throw new KeystoreError("changed");
    }
  };
  return {
    get: async (name) => {
      checkStorageName(name);
      const found = held.get(name);
      return Promise.resolve(
        found === undefined
          ? undefined
          : { value: found.value.slice(), version: String(found.version) },
      );
    },
    // Each is one step with nothing awaited in it: no other call comes between the check and the write.
    put: async (name, value, expected) => {
      checkStorageName(name);
      current(name, expected);
      const version = ++writes;
      held.set(name, { value: value.slice(), version });
      return Promise.resolve(String(version));
    },
    delete: async (name, expected) => {
      checkStorageName(name);
      current(name, expected);
      held.delete(name);
      return Promise.resolve();
    },
    list: () => Promise.resolve([...held.keys()]),
  };
}
