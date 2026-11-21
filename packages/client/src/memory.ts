// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a client remembers between runs of its own work: where its feed
 * stands, the number of its last location record, an entry it has signed and
 * may not have published.
 *
 * None of it is secret. All of it is what keeps a mind from saying two
 * things at one position, so it is written before anything leaves, and every
 * write names the version it replaces: two processes that work as one mind
 * find each other out here, and not by publishing a fork.
 *
 * It is kept in a `KeyStorage` of `@oip/keystore`: a directory, a browser's
 * IndexedDB, or memory that is gone when the process ends.
 */

import { canonicalize, type JsonObject, parseJsonBytes, utf8 } from "@oip/core";
import { type KeyStorage, KeystoreError } from "@oip/keystore";

/** A document of a client's memory, with the version a write of it names. */
export interface Remembered<T> {
  /** What is remembered, or `undefined` if nothing is yet. */
  readonly value: T | undefined;
  /** The version held, which the next write replaces. `undefined` if nothing is held. */
  readonly version: string | undefined;
}

/** What a client remembers for one mind. */
export class Memory {
  readonly #storage: KeyStorage;
  readonly #mind: string;

  /**
   * @param storage - Where it is kept.
   * @param mind - The mind it is the memory of.
   */
  constructor(storage: KeyStorage, mind: string) {
    this.#storage = storage;
    this.#mind = mind;
  }

  /**
   * Reads a document.
   *
   * @param name - Its name in the storage.
   * @param read - Makes the document of what is stored, or answers
   *   `undefined` if it is not one.
   * @throws KeystoreError `damaged` if what is stored cannot be read, or is
   *   another mind's.
   */
  async get<T>(name: string, read: (stored: JsonObject) => T | undefined): Promise<Remembered<T>> {
    const held = await this.#storage.get(name);
    if (held === undefined) return { value: undefined, version: undefined };
    const parsed = parseJsonBytes(held.value);
    const stored =
      parsed.ok &&
      typeof parsed.value === "object" &&
      parsed.value !== null &&
      !Array.isArray(parsed.value)
        ? (parsed.value as JsonObject)
        : undefined;
    if (stored === undefined) {
      throw new KeystoreError("damaged", `what the client remembers as ${name} cannot be read`);
    }
    if (stored["mind"] !== this.#mind) {
      throw new KeystoreError(
        "damaged",
        `what is remembered as ${name} is another mind's: each mind has a memory of its own`,
      );
    }
    const value = read(stored);
    if (value === undefined) {
      throw new KeystoreError("damaged", `what the client remembers as ${name} cannot be read`);
    }
    return { value, version: held.version };
  }

  /** The names of the documents held whose names start with `prefix`, in order. */
  async names(prefix: string): Promise<string[]> {
    return (await this.#storage.list()).filter((name) => name.startsWith(prefix)).sort();
  }

  /**
   * Writes a document in the place of the version that was read.
   *
   * @returns The version now held.
   * @throws KeystoreError `changed` if another process wrote it since.
   */
  put(
    name: string,
    value: Readonly<Record<string, unknown>>,
    expected: string | undefined,
  ): Promise<string> {
    return this.#storage.put(name, utf8(canonicalize({ ...value, mind: this.#mind })), expected);
  }

  /**
   * Forgets a document, if the version that was read is still the one held.
   *
   * @throws KeystoreError `changed` if another process wrote it since.
   */
  async forget(name: string, expected: string | undefined): Promise<void> {
    if (expected !== undefined) await this.#storage.delete(name, expected);
  }
}
