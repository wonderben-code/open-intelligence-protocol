// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it } from "vitest";

import {
  type IdbDatabase,
  type IdbFactory,
  type IdbObjectStore,
  type IdbOpenRequest,
  type IdbRequest,
  type IdbTransaction,
  indexedDbStorage,
  keychainLock,
  Keystore,
  KeystoreError,
} from "../src/index.ts";
import { fakeBrowser as browser, memoryKeychain, randomnessOf } from "./helpers.ts";

async function refusal(work: () => unknown): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return error.code;
    throw error;
  }
  throw new Error("nothing was refused");
}

const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);

/** Puts something under a key of the store, as another script of the origin could. */
function planted(factory: IdbFactory, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const opening = factory.open("keys", 1);
    opening.onupgradeneeded = () => {
      opening.result.createObjectStore("documents");
    };
    opening.onerror = () => {
      reject(new Error("the database did not open"));
    };
    opening.onsuccess = () => {
      const db = opening.result;
      const transaction = db.transaction("documents", "readwrite");
      transaction.objectStore("documents").put(value, key);
      transaction.oncomplete = () => {
        db.close();
        resolve();
      };
    };
  });
}

afterEach(() => {
  delete (globalThis as { indexedDB?: unknown }).indexedDB;
});

describe("a storage in IndexedDB", () => {
  it("is the browser's own IndexedDB, unless it is given another", async () => {
    expect(await refusal(() => indexedDbStorage("keys"))).toBe("argument");
    const factory = browser();
    (globalThis as { indexedDB?: unknown }).indexedDB = factory;
    const storage = indexedDbStorage("keys");
    const version = await storage.put("control", bytes(1), undefined);
    // Another storage over the same browser sees it.
    expect(await indexedDbStorage("keys", factory).get("control")).toStrictEqual({
      value: bytes(1),
      version,
    });
    // A database of another name is another storage.
    expect(await indexedDbStorage("other", factory).get("control")).toBeUndefined();
    expect(await refusal(() => indexedDbStorage("", factory))).toBe("argument");
    expect(await refusal(() => indexedDbStorage(7 as never, factory))).toBe("argument");
  });

  it("never gives a version twice, to any document, even one that was removed and made again", async () => {
    const storage = indexedDbStorage("keys", browser());
    const seen = new Set<string>();
    let version = await storage.put("control", bytes(1), undefined);
    seen.add(version);
    await storage.delete("control", version);
    version = await storage.put("control", bytes(2), undefined);
    expect(seen.has(version)).toBe(false);
    seen.add(version);
    const other = await storage.put("meta", bytes(3), undefined);
    expect(seen.has(other)).toBe(false);
    // So a writer that read the document before it was removed cannot write over the new one.
    expect(await refusal(() => storage.put("control", bytes(9), "1"))).toBe("changed");
    expect((await storage.list()).sort()).toStrictEqual(["control", "meta"]);
  });

  it("refuses what is kept under a document's name and is no document", async () => {
    const plants: unknown[] = [
      "text",
      7,
      { value: [1, 2, 3], version: 1 },
      { value: bytes(1), version: "1" },
      { value: bytes(1), version: 1.5 },
      { value: bytes(1) },
      null,
    ];
    for (const plant of plants) {
      const factory = browser();
      await planted(factory, "control", plant);
      const storage = indexedDbStorage("keys", factory);
      expect(await refusal(() => storage.get("control")), JSON.stringify(plant)).toBe("damaged");
      expect(await refusal(() => storage.put("control", bytes(1), undefined))).toBe("damaged");
      expect(await refusal(() => storage.delete("control", "1"))).toBe("damaged");
    }
    // Keys that are no names of documents are not listed.
    const factory = browser();
    await planted(factory, "control", { value: bytes(1), version: 1 });
    await planted(factory, "#writes", 1);
    expect(await indexedDbStorage("keys", factory).list()).toStrictEqual(["control"]);
  });

  it("holds a keystore, which another tab of the origin opens", async () => {
    const factory = browser();
    const keychain = memoryKeychain();
    const lock = keychainLock(keychain, "oip-test");
    const keystore = await Keystore.create({
      storage: indexedDbStorage("keys", factory),
      locks: lock,
      randomness: randomnessOf("browser"),
    });
    const operational = await keystore.unlock("operational", lock);
    const { publicKey } = await operational.generate();
    // Another tab.
    const other = await Keystore.open({ storage: indexedDbStorage("keys", factory) });
    expect(other.id).toBe(keystore.id);
    const theirs = await other.unlock("operational", lock);
    expect(theirs.has(publicKey)).toBe(true);
    // Both hold the role. The first to change it wins, and the other is told.
    await theirs.generate();
    expect(await refusal(() => operational.generate())).toBe("changed");
  });
});

/** An IndexedDB that fails where it is told to, and is otherwise the one given. */
function failing(
  real: IdbFactory,
  fault: {
    open?: "error" | "blocked";
    request?: (method: string) => boolean;
    /** The browser gives the transaction up when it would have completed. */
    abort?: boolean;
    /** The transaction says it completed before its requests were answered. */
    early?: boolean;
    /** The transaction has ended by the time it is given up. */
    ended?: boolean;
  },
): IdbFactory {
  const failed = <T>(request: IdbRequest<T>): IdbRequest<T> => {
    const broken = {
      result: undefined as T,
      error: Object.assign(new Error("planted"), { name: "PlantedError" }),
      onsuccess: null as (() => void) | null,
      onerror: null as (() => void) | null,
    };
    // The real request goes on, and this one reports an error in its place.
    request.onsuccess = () => broken.onerror?.();
    request.onerror = () => broken.onerror?.();
    return broken;
  };
  const storeOf = (store: IdbObjectStore): IdbObjectStore => ({
    get: (key) => (fault.request?.("get") === true ? failed(store.get(key)) : store.get(key)),
    put: (value, key) =>
      fault.request?.("put") === true ? failed(store.put(value, key)) : store.put(value, key),
    delete: (key) =>
      fault.request?.("delete") === true ? failed(store.delete(key)) : store.delete(key),
    getAllKeys: () =>
      fault.request?.("getAllKeys") === true ? failed(store.getAllKeys()) : store.getAllKeys(),
  });
  const transactionOf = (transaction: IdbTransaction): IdbTransaction => {
    const wrapped: IdbTransaction = {
      error: Object.assign(new Error("planted"), { name: "QuotaExceededError" }),
      oncomplete: null,
      onabort: null,
      objectStore: (name) => storeOf(transaction.objectStore(name)),
      abort: () => {
        if (fault.ended === true) throw new Error("the transaction has finished");
        transaction.abort();
      },
    };
    if (fault.early === true) queueMicrotask(() => wrapped.oncomplete?.());
    // A browser that runs out of room aborts the transaction when it would have completed.
    transaction.oncomplete = () => {
      if (fault.abort === true) wrapped.onabort?.();
      else wrapped.oncomplete?.();
    };
    transaction.onabort = () => wrapped.onabort?.();
    return wrapped;
  };
  return {
    open: (name, version) => {
      const request = real.open(name, version);
      const wrapped: IdbOpenRequest = {
        get result(): IdbDatabase {
          const db = request.result;
          return {
            createObjectStore: (store) => db.createObjectStore(store),
            transaction: (store, mode) => transactionOf(db.transaction(store, mode)),
            close: () => {
              db.close();
            },
          };
        },
        error: Object.assign(new Error("planted"), { name: "SecurityError" }),
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
        onblocked: null,
      };
      request.onupgradeneeded = () => wrapped.onupgradeneeded?.();
      request.onsuccess = () => {
        if (fault.open === "error") wrapped.onerror?.();
        else if (fault.open === "blocked") wrapped.onblocked?.();
        else wrapped.onsuccess?.();
      };
      return wrapped;
    },
  };
}

describe("a storage in IndexedDB, when the browser fails", () => {
  it("fails every call if the database does not open, and says what IndexedDB said", async () => {
    const closed = indexedDbStorage("keys", failing(browser(), { open: "error" }));
    await expect(closed.get("control")).rejects.toThrow(
      "IndexedDB could not open the database: SecurityError",
    );
    await expect(closed.put("control", bytes(1), undefined)).rejects.toThrow("SecurityError");
    await expect(closed.list()).rejects.toThrow("SecurityError");
    const blocked = indexedDbStorage("keys", failing(browser(), { open: "blocked" }));
    await expect(blocked.get("control")).rejects.toThrow(
      "IndexedDB could not open the database while another connection holds an older one",
    );
  });

  it("fails a call whose request fails, and keeps nothing of a write that did not finish", async () => {
    const real = browser();
    const good = indexedDbStorage("keys", real);
    const first = await good.put("control", bytes(1), undefined);
    for (const method of ["get", "put"]) {
      const storage = indexedDbStorage(
        "keys",
        failing(real, { request: (asked) => asked === method }),
      );
      await expect(storage.put("control", bytes(2), first), method).rejects.toThrow(
        "IndexedDB could not read: PlantedError",
      );
      // The document is as it was, and so is its version.
      expect(await good.get("control"), method).toStrictEqual({ value: bytes(1), version: first });
    }
    const unreadable = indexedDbStorage("keys", failing(real, { request: () => true }));
    await expect(unreadable.get("control")).rejects.toThrow("PlantedError");
    await expect(unreadable.list()).rejects.toThrow("PlantedError");
    await expect(unreadable.delete("control", first)).rejects.toThrow("PlantedError");
    expect((await good.get("control"))?.version).toBe(first);
  });

  it("reports a write only once its transaction has completed", async () => {
    const real = browser();
    const full = indexedDbStorage("keys", failing(real, { abort: true }));
    // Every request succeeded, and the browser then gave the transaction up.
    await expect(full.put("control", bytes(1), undefined)).rejects.toThrow(
      "IndexedDB could not write: QuotaExceededError",
    );
    // A transaction that says it is done before its requests were answered has promised nothing.
    const hasty = indexedDbStorage("keys", failing(real, { early: true }));
    await expect(hasty.put("operational", bytes(1), undefined)).rejects.toThrow(
      "IndexedDB could not finish what it was asked",
    );
  });

  it("says why the work failed, where the transaction had ended by itself", async () => {
    const real = browser();
    const good = indexedDbStorage("keys", real);
    const first = await good.put("control", bytes(1), undefined);
    // The request failed and the browser ended the transaction for it: giving it up again throws.
    const storage = indexedDbStorage(
      "keys",
      failing(real, { request: (asked) => asked === "get", ended: true }),
    );
    await expect(storage.put("control", bytes(2), first)).rejects.toThrow("PlantedError");
    // A refusal of the storage's own is heard as itself too.
    const ended = indexedDbStorage("keys", failing(real, { ended: true }));
    expect(await refusal(() => ended.put("control", bytes(2), "no version"))).toBe("changed");
  });
});
