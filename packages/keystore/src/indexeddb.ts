// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A storage in IndexedDB, for a browser. One database holds one keystore's
 * documents, each under its name, with the count of the write that made it.
 *
 * A write reads the document, compares its version and writes, in one
 * transaction. IndexedDB runs the read-write transactions of one object
 * store one after another, in every tab and worker of the origin: of two
 * writers that read one version, the second finds the first's.
 *
 * What a browser keeps for an origin, anything that runs in that origin can
 * read. The documents are sealed. Their lock is the only thing between a
 * script that got into the page and the keys.
 */

import { KeystoreError } from "./errors.ts";
import { checkStorageName, type KeyStorage, type Stored } from "./storage.ts";

// The parts of IndexedDB that are used, written out: the package is typed without the
// browser's library, so that it means the same thing where there is no browser.

/** A request of IndexedDB, as far as it is used here. */
export interface IdbRequest<T = unknown> {
  /** What was asked for, once the request has succeeded. */
  readonly result: T;
  /** Why the request failed, once it has. */
  readonly error: unknown;
  /** Called when the request has succeeded. */
  onsuccess: (() => void) | null;
  /** Called when the request has failed. */
  onerror: (() => void) | null;
}

/** A request to open a database. */
export interface IdbOpenRequest extends IdbRequest<IdbDatabase> {
  /** Called when the database is new, and its object stores are to be made. */
  onupgradeneeded: (() => void) | null;
  /** Called when another connection holds an older version of the database open. */
  onblocked: (() => void) | null;
}

/** An object store of IndexedDB, as far as it is used here. */
export interface IdbObjectStore {
  /** Asks for the value kept under a key. */
  get(key: string): IdbRequest;
  /** Keeps a value under a key, in the place of the one there. */
  put(value: unknown, key: string): IdbRequest;
  /** Removes the value kept under a key. */
  delete(key: string): IdbRequest;
  /** Asks for every key of the store. */
  getAllKeys(): IdbRequest<unknown[]>;
}

/** A transaction of IndexedDB, as far as it is used here. */
export interface IdbTransaction {
  /** Why the transaction was aborted, once it has been. */
  readonly error: unknown;
  /** Called when everything the transaction did is kept. */
  oncomplete: (() => void) | null;
  /** Called when the transaction was given up, and nothing it did is kept. */
  onabort: (() => void) | null;
  /** An object store the transaction was opened over. */
  objectStore(name: string): IdbObjectStore;
  /** Gives the transaction up. */
  abort(): void;
}

/** A database of IndexedDB, as far as it is used here. */
export interface IdbDatabase {
  /** Makes an object store, while the database is being made. */
  createObjectStore(name: string): unknown;
  /** Opens a transaction over an object store. */
  transaction(store: string, mode: "readonly" | "readwrite"): IdbTransaction;
  /** Closes the connection. */
  close(): void;
}

/** What opens a database: `indexedDB` in a browser. */
export interface IdbFactory {
  /** Asks for a database to be opened, at a version. */
  open(name: string, version?: number): IdbOpenRequest;
}

/** The object store that holds the documents. */
const STORE = "documents";
/** Where the count of writes is kept. No document has this name: it is not one a storage takes. */
const WRITES = "#writes";

interface Kept {
  readonly value: Uint8Array;
  readonly version: number;
}

function isKept(value: unknown): value is Kept {
  if (typeof value !== "object" || value === null) return false;
  const { value: bytes, version } = value as { value?: unknown; version?: unknown };
  return (
    bytes instanceof Uint8Array && typeof version === "number" && Number.isSafeInteger(version)
  );
}

/** What IndexedDB reported, as an error that says so and holds nothing of what was stored. */
function failure(what: string, cause?: unknown): Error {
  const name = cause instanceof Error ? cause.name : "no reason was given";
  return new Error(`IndexedDB could not ${what}: ${name}`);
}

/**
 * A storage in the IndexedDB of a browser.
 *
 * @param database - The name of the database: one for each keystore.
 * @param factory - What opens it. Default: the `indexedDB` of the place this runs in.
 * @throws KeystoreError `argument` if there is no IndexedDB there.
 */
export function indexedDbStorage(database: string, factory?: IdbFactory): KeyStorage {
  const opener = factory ?? (globalThis as { indexedDB?: IdbFactory }).indexedDB;
  if (opener === undefined || typeof database !== "string" || database.length === 0) {
    throw new KeystoreError("argument", "there is no IndexedDB here, or the database has no name");
  }

  /** Opens the database, with its one object store, for the length of one transaction. */
  const open = (): Promise<IdbDatabase> =>
    new Promise((resolve, reject) => {
      const request = opener.open(database, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE);
      };
      request.onsuccess = () => {
        resolve(request.result);
      };
      request.onerror = () => {
        reject(failure("open the database", request.error));
      };
      request.onblocked = () => {
        reject(failure("open the database while another connection holds an older one"));
      };
    });

  /**
   * Runs one transaction. `work` makes its requests at once, and what it
   * resolves to is what the transaction gives once it has completed: a write
   * is not reported before it is durable. If `work` fails, the transaction is
   * aborted, and nothing of it is kept.
   */
  const transact = async <T>(
    mode: "readonly" | "readwrite",
    work: (store: IdbObjectStore) => Promise<T>,
  ): Promise<T> => {
    const db = await open();
    try {
      const transaction = db.transaction(STORE, mode);
      let answered = false;
      const completed = new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => {
          // A transaction that ended before its work did kept no promise about that work.
          if (answered) resolve();
          else reject(failure("finish what it was asked"));
        };
        // A request that fails aborts its transaction, so this hears of every failure.
        transaction.onabort = () => {
          reject(failure("write", transaction.error));
        };
      });
      // It is awaited below, or the work has failed and its own reason is given instead.
      completed.catch(() => undefined);
      let value: T;
      try {
        value = await work(transaction.objectStore(STORE));
        answered = true;
      } catch (error) {
        try {
          transaction.abort();
        } catch {
          // It has ended already.
        }
        throw error;
      }
      // A write is not reported before its transaction has completed.
      await completed;
      return value;
    } finally {
      db.close();
    }
  };

  /** A request as a promise. It settles inside the transaction, which stays open for the next. */
  const asked = <T>(request: IdbRequest<T>): Promise<T> =>
    new Promise((resolve, reject) => {
      request.onsuccess = () => {
        resolve(request.result);
      };
      request.onerror = () => {
        reject(failure("read", request.error));
      };
    });

  /** The document of a name as it is kept, checked: a browser's storage is not trusted either. */
  const kept = async (store: IdbObjectStore, name: string): Promise<Kept | undefined> => {
    const found = await asked(store.get(name));
    if (found === undefined) return undefined;
    if (!isKept(found)) throw new KeystoreError("damaged");
    return found;
  };

  /** @throws KeystoreError `changed` if what is kept is not the version expected. */
  const current = async (
    store: IdbObjectStore,
    name: string,
    expected: string | undefined,
  ): Promise<void> => {
    const found = await kept(store, name);
    if ((found === undefined ? undefined : String(found.version)) !== expected) {
      throw new KeystoreError("changed");
    }
  };

  return {
    get: async (name): Promise<Stored | undefined> => {
      checkStorageName(name);
      return transact("readonly", async (store) => {
        const found = await kept(store, name);
        return found === undefined
          ? undefined
          : { value: found.value.slice(), version: String(found.version) };
      });
    },
    put: async (name, value, expected) => {
      checkStorageName(name);
      return transact("readwrite", async (store) => {
        await current(store, name, expected);
        // One count for the whole storage: a version is never given twice, to any document.
        const writes: unknown = await asked(store.get(WRITES));
        const version = (typeof writes === "number" ? writes : 0) + 1;
        await asked(store.put(version, WRITES));
        await asked(store.put({ value: value.slice(), version } satisfies Kept, name));
        return String(version);
      });
    },
    delete: async (name, expected) => {
      checkStorageName(name);
      return transact("readwrite", async (store) => {
        await current(store, name, expected);
        await asked(store.delete(name));
      });
    },
    list: () =>
      transact("readonly", async (store) => {
        const keys = await asked(store.getAllKeys());
        return keys.filter((key): key is string => typeof key === "string" && key !== WRITES);
      }),
  };
}
