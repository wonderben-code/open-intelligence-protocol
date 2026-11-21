// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What the tests of a mind of one's own share. */

import { OipError } from "@oip/core";
import {
  type Keychain,
  keychainLock,
  Keystore,
  KeystoreError,
  type KeyStorage,
  type Lock,
  memoryStorage,
} from "@oip/keystore";

import { type MindOptions, TransportError } from "../src/index.ts";
import type { World } from "./world.ts";

/** A keychain that is a map: a lock that costs no key derivation. */
export function memoryKeychain(): Keychain {
  const kept = new Map<string, string>();
  return {
    get: (service, account) => Promise.resolve(kept.get(`${service}\n${account}`)),
    set: (service, account, secret) => {
      kept.set(`${service}\n${account}`, secret);
      return Promise.resolve();
    },
    delete: (service, account) => {
      kept.delete(`${service}\n${account}`);
      return Promise.resolve();
    },
  };
}

/** A keystore with nothing in it, its lock, and what a mind over it is made with. */
export async function freshKeystore(
  world: World,
  resolvers: readonly string[],
  more: Partial<MindOptions> = {},
): Promise<{
  keystore: Keystore;
  lock: Lock;
  options: MindOptions;
  /** Where the keys are kept. */
  storage: KeyStorage;
  /** Where the client remembers its own work. */
  memory: KeyStorage;
}> {
  const lock = keychainLock(memoryKeychain(), "oip-test");
  const storage = memoryStorage();
  const keystore = await Keystore.create({ storage, locks: lock });
  const memory = memoryStorage();
  const options: MindOptions = {
    keystore,
    lock,
    resolvers,
    fetch: world.fetch,
    clock: world.clock,
    memory,
    ...more,
  };
  return { keystore, lock, options, storage, memory };
}

/** What a call is refused with. */
export async function refusal(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof OipError) return `oip: ${error.code}`;
    if (error instanceof TransportError) return `transport: ${error.failure}`;
    if (error instanceof KeystoreError) return `keystore: ${error.code}`;
    throw error;
  }
  throw new Error("nothing was refused");
}

/** A copy of a storage as it stands: what a second device would hold that was set up from it. */
export async function copyOf(storage: KeyStorage): Promise<KeyStorage> {
  const copy = memoryStorage();
  for (const name of await storage.list()) {
    const held = await storage.get(name);
    if (held !== undefined) await copy.put(name, held.value, undefined);
  }
  return copy;
}
