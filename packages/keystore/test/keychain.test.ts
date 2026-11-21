// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { keychainLock, Keystore, KeystoreError, memoryStorage } from "../src/index.ts";
import { type KeyringEntry, type KeyringLibrary, systemKeychain } from "../src/node.ts";
import { randomnessOf } from "./helpers.ts";

async function refusal(work: () => unknown): Promise<{ code: string; message: string }> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return { code: error.code, message: error.message };
    throw error;
  }
  throw new Error("nothing was refused");
}

/** A keyring library that is a map, with what it was asked. */
function standIn(fault?: (method: string) => Error | undefined) {
  const kept = new Map<string, string>();
  const asked: string[] = [];
  const failing = (method: string): void => {
    const error = fault?.(method);
    if (error !== undefined) throw error;
  };
  class AsyncEntry implements KeyringEntry {
    readonly #name: string;
    constructor(service: string, account: string) {
      failing("constructor");
      this.#name = `${service}\n${account}`;
    }
    getPassword(): Promise<string | null> {
      asked.push(`get ${this.#name}`);
      failing("getPassword");
      return Promise.resolve(kept.get(this.#name) ?? null);
    }
    setPassword(password: string): Promise<void> {
      asked.push(`set ${this.#name}`);
      failing("setPassword");
      kept.set(this.#name, password);
      return Promise.resolve();
    }
    deleteCredential(): Promise<boolean> {
      asked.push(`delete ${this.#name}`);
      failing("deleteCredential");
      return Promise.resolve(kept.delete(this.#name));
    }
  }
  const library: KeyringLibrary = { AsyncEntry };
  return { library, kept, asked };
}

describe("the keychain of the operating system", () => {
  it("keeps, gives and removes a secret under a service and an account", async () => {
    const { library, kept, asked } = standIn();
    const keychain = await systemKeychain({ load: () => Promise.resolve(library) });
    expect(await keychain.get("oip", "a/control")).toBeUndefined();
    await keychain.set("oip", "a/control", "one");
    await keychain.set("oip", "a/operational", "two");
    await keychain.set("mail", "a/control", "three");
    expect(await keychain.get("oip", "a/control")).toBe("one");
    expect(await keychain.get("oip", "a/operational")).toBe("two");
    expect(await keychain.get("mail", "a/control")).toBe("three");
    await keychain.set("oip", "a/control", "four");
    expect(await keychain.get("oip", "a/control")).toBe("four");
    await keychain.delete("oip", "a/control");
    expect(await keychain.get("oip", "a/control")).toBeUndefined();
    // Removing what is not there is not an error.
    await keychain.delete("oip", "a/control");
    expect([...kept.keys()].sort()).toStrictEqual(["mail\na/control", "oip\na/operational"]);
    expect(asked.slice(0, 2)).toStrictEqual(["get oip\na/control", "set oip\na/control"]);
  });

  it("is the library that is installed, unless it is given another", async () => {
    // Loading it reaches no keychain: that waits for the first call.
    const keychain = await systemKeychain();
    expect(Object.keys(keychain).sort()).toStrictEqual(["delete", "get", "set"]);
  });

  it("cannot be used where the library is not installed, or is not that library", async () => {
    const missing = () => Promise.reject(new Error("Cannot find package '@napi-rs/keyring'"));
    expect(await refusal(() => systemKeychain({ load: missing }))).toStrictEqual({
      code: "no-keychain",
      message:
        "the keychain of this machine could not be used: the package @napi-rs/keyring could not be loaded",
    });
    for (const other of [{}, { AsyncEntry: "no class" }, { Entry: Object }]) {
      const load = () => Promise.resolve(other as unknown as KeyringLibrary);
      expect((await refusal(() => systemKeychain({ load }))).code).toBe("no-keychain");
    }
  });

  it("says that it could not be reached, and nothing of what the platform said or of the secret", async () => {
    const platform = new Error(
      "Platform secure storage failure: the secret s3cret-value was refused",
    );
    for (const method of ["constructor", "getPassword", "setPassword", "deleteCredential"]) {
      const { library } = standIn((asked) => (asked === method ? platform : undefined));
      const keychain = await systemKeychain({ load: () => Promise.resolve(library) });
      const calls: [string, () => Promise<unknown>][] = [
        ["getPassword", () => keychain.get("oip", "a")],
        ["setPassword", () => keychain.set("oip", "a", "s3cret-value")],
        ["deleteCredential", () => keychain.delete("oip", "a")],
      ];
      for (const [name, call] of calls) {
        if (method !== "constructor" && method !== name) {
          await call();
          continue;
        }
        const refused = await refusal(call);
        expect(refused.code, `${method} ${name}`).toBe("no-keychain");
        expect(refused.message).not.toContain("s3cret-value");
        expect(refused.message).not.toContain("Platform");
        expect(refused.message).toMatch(
          /^the keychain of this machine could not be used: it did not /u,
        );
      }
    }
  });

  it("gives nothing for what it keeps that is no string", async () => {
    const { library } = standIn();
    const odd: KeyringLibrary = {
      AsyncEntry: class extends library.AsyncEntry {
        override getPassword(): Promise<string | null> {
          return Promise.resolve(7 as unknown as string);
        }
      },
    };
    const keychain = await systemKeychain({ load: () => Promise.resolve(odd) });
    expect(await keychain.get("oip", "a")).toBeUndefined();
  });

  it("locks a keystore: each role under a key of its own that the keychain keeps", async () => {
    const { library, kept } = standIn();
    const keychain = await systemKeychain({ load: () => Promise.resolve(library) });
    const lock = keychainLock(keychain, "oip");
    const storage = memoryStorage();
    const keystore = await Keystore.create({ storage, locks: lock, randomness: randomnessOf("k") });
    expect([...kept.keys()].sort()).toStrictEqual(
      ["agreement", "control", "invocation", "operational"].map(
        (role) => `oip\n${keystore.id}/${role}`,
      ),
    );
    expect(new Set(kept.values()).size).toBe(4);
    const operational = await keystore.unlock("operational", lock);
    const { publicKey } = await operational.generate();
    operational.lock();
    expect((await keystore.unlock("operational", lock)).has(publicKey)).toBe(true);
    // Without what the keychain keeps, the role does not open.
    kept.delete(`oip\n${keystore.id}/control`);
    expect((await refusal(() => keystore.unlock("control", lock))).code).toBe("not-opened");
  });
});
