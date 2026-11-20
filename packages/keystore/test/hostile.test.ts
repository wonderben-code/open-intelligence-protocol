// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a storage holds is not trusted: a file can be edited, replaced or cut
 * short. Whatever is there, a keystore answers with its keys or with a
 * `KeystoreError`, and with nothing else: no other exception, no key derived
 * from a document that was not checked, nothing written.
 */

import { canonicalBytes, type JsonValue, parseJsonBytes, utf8 } from "@oip/core";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  KEY_ROLES,
  keychainLock,
  Keystore,
  KeystoreError,
  type KeyStorage,
  memoryStorage,
} from "../src/index.ts";
import { memoryKeychain, quick, randomnessOf } from "./helpers.ts";

const RUNS = Number(process.env["OIP_KEYSTORE_RUNS"] ?? 300);

/** A keystore with a key in each role, and the documents it stored. */
async function stored() {
  const storage = memoryStorage();
  const lock = keychainLock(memoryKeychain(), "oip-test");
  const keystore = await Keystore.create({ storage, locks: lock, randomness: randomnessOf("h") });
  for (const role of KEY_ROLES) {
    const keys = await keystore.unlock(role, lock);
    await keys.generate();
    keys.lock();
  }
  const documents = new Map<string, Uint8Array>();
  for (const name of await storage.list()) {
    documents.set(name, (await storage.get(name))?.value ?? new Uint8Array());
  }
  return { keystore, lock, documents };
}

/** A storage that holds the documents given, and says whether anything was written to it. */
function holding(documents: ReadonlyMap<string, Uint8Array>): KeyStorage & { written: boolean } {
  const inner = memoryStorage();
  const storage = {
    written: false,
    get: async (name: string) => {
      const value = documents.get(name);
      return Promise.resolve(value === undefined ? undefined : { value, version: "1" });
    },
    put: (name: string, value: Uint8Array, expected: string | undefined) => {
      storage.written = true;
      return inner.put(name, value, expected);
    },
    delete: (name: string, expected: string) => {
      storage.written = true;
      return inner.delete(name, expected);
    },
    list: () => Promise.resolve([...documents.keys()]),
  };
  return storage;
}

/** Anything that is not a `KeystoreError` fails the test. */
async function refused(work: () => Promise<unknown>): Promise<boolean> {
  try {
    await work();
    return false;
  } catch (error) {
    expect(error).toBeInstanceOf(KeystoreError);
    return true;
  }
}

/** A JSON value with one thing in it changed, removed or added. */
function mutated(given: JsonValue): fc.Arbitrary<unknown> {
  const anything = fc.jsonValue({ maxDepth: 2 });
  if (typeof given !== "object" || given === null || Array.isArray(given)) return anything;
  const value = given as Readonly<Record<string, JsonValue>>;
  const names = Object.keys(value);
  const strings = names.filter((name) => typeof value[name] === "string");
  // A member added, which any object can have.
  const added = fc.tuple(fc.string({ maxLength: 8 }), anything).map(([name, other]) => ({
    ...value,
    [name]: other,
  }));
  if (names.length === 0) return fc.oneof(added, anything);
  const changes: fc.Arbitrary<unknown>[] = [
    added,
    // A member removed.
    fc.constantFrom(...names).map((name) => {
      const { [name]: _, ...rest } = value;
      return rest;
    }),
    // A member replaced by anything.
    fc.tuple(fc.constantFrom(...names), anything).map(([name, other]) => ({
      ...value,
      [name]: other,
    })),
    // A member changed inside.
    fc
      .constantFrom(...names)
      .chain((name) => mutated(value[name] ?? null).map((inner) => ({ ...value, [name]: inner }))),
  ];
  if (strings.length > 0) {
    // A character of a string changed.
    changes.push(
      fc
        .tuple(fc.constantFrom(...strings), fc.nat(), fc.constantFrom("A", "B", "-", "_", "!", ""))
        .map(([name, at, other]) => {
          const text = value[name] as string;
          const index = text.length === 0 ? 0 : at % text.length;
          return { ...value, [name]: text.slice(0, index) + other + text.slice(index + 1) };
        }),
    );
  }
  return fc.oneof(...changes);
}

/** What might be found in the place of a document: its bytes changed, or anything at all. */
function inPlaceOf(document: Uint8Array): fc.Arbitrary<Uint8Array> {
  const parsed = parseJsonBytes(document);
  if (!parsed.ok) throw new Error("the document is not JSON");
  return fc.oneof(
    // As JSON text of any kind: what was changed may hold what the keystore's JSON never does.
    mutated(parsed.value).map((value) => utf8(JSON.stringify(value))),
    fc.uint8Array({ maxLength: 256 }),
    fc.jsonValue({ maxDepth: 3 }).map((value) => utf8(JSON.stringify(value))),
    // Cut short, as a write that was interrupted on a storage that does not write whole.
    fc.nat({ max: document.length }).map((length) => document.slice(0, length)),
  );
}

describe("a keystore over a storage that holds anything", () => {
  it("unlocks a role whose document is its own, and refuses every other", async () => {
    const { keystore, lock, documents } = await stored();
    for (const role of KEY_ROLES) {
      const original = documents.get(role) ?? new Uint8Array();
      await fc.assert(
        fc.asyncProperty(inPlaceOf(original), async (bytes) => {
          const storage = holding(new Map([...documents, [role, bytes]]));
          const opened = await Keystore.open({ storage });
          expect(opened.id).toBe(keystore.id);
          let unlocked = false;
          const failed = await refused(async () => {
            (await opened.unlock(role, lock)).lock();
            unlocked = true;
          });
          // It opens only if it is, byte for byte or in other words, what was sealed.
          if (unlocked) {
            const read = parseJsonBytes(bytes);
            expect(read.ok && canonicalBytes(read.value)).toStrictEqual(original);
          }
          expect(failed).toBe(!unlocked);
          await refused(() => opened.backupDue());
          await refused(() => opened.changeLock(role, lock, quick()));
          expect(storage.written).toBe(unlocked);
        }),
        { numRuns: RUNS },
      );
    }
  });

  it("opens over a note of itself that is its own, and refuses every other", async () => {
    const { documents } = await stored();
    const original = documents.get("meta") ?? new Uint8Array();
    await fc.assert(
      fc.asyncProperty(inPlaceOf(original), async (bytes) => {
        const storage = holding(new Map([...documents, ["meta", bytes]]));
        await refused(async () => {
          const opened = await Keystore.open({ storage });
          // A note that reads as one names a keystore by 16 bytes, and nothing else by its name.
          expect(opened.id).toMatch(/^[A-Za-z0-9_-]{22}$/u);
          await refused(() => opened.backupDue());
        });
        expect(storage.written).toBe(false);
      }),
      { numRuns: RUNS },
    );
  });

  it("restores a backup that is one, and refuses every other", async () => {
    const { keystore, lock } = await stored();
    const keys = {
      control: await keystore.unlock("control", lock),
      operational: await keystore.unlock("operational", lock),
      invocation: await keystore.unlock("invocation", lock),
      agreement: await keystore.unlock("agreement", lock),
    };
    const backupLock = keychainLock(memoryKeychain(), "oip-backup");
    const { bytes: original } = await keystore.backup(keys, backupLock);
    await fc.assert(
      fc.asyncProperty(inPlaceOf(original), async (bytes) => {
        const storage = memoryStorage();
        let restored = false;
        await refused(async () => {
          await Keystore.restore({ storage, locks: lock, backup: bytes, backupLock });
          restored = true;
        });
        if (restored) {
          const read = parseJsonBytes(bytes);
          expect(read.ok && canonicalBytes(read.value)).toStrictEqual(original);
        }
        // Refused, it has stored nothing: no part of a keystore is left behind.
        expect(await storage.list()).toHaveLength(restored ? 5 : 0);
      }),
      { numRuns: RUNS },
    );
  });
});
