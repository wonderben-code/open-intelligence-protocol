// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";

import { IDBFactory as FakeFactory } from "fake-indexeddb";

import {
  type IdbFactory,
  type Keychain,
  passphrase,
  type Randomness,
  SCRYPT_MIN_N,
} from "../src/index.ts";

/**
 * A browser's IndexedDB, in memory: a new one at every call, as a new profile
 * is. The library is typed against the browser's own types, which this
 * package is built without, so it is given the type of what is used of it.
 */
export const fakeBrowser = (): IdbFactory => new (FakeFactory as unknown as new () => IdbFactory)();

/** Bytes that differ at every draw and are the same in every run: SHA-256 of a name and a count. */
export function randomnessOf(name: string): Randomness & { drawn: number } {
  const source = {
    drawn: 0,
    bytes: (length: number): Uint8Array => {
      const bytes = new Uint8Array(length);
      for (let offset = 0; offset < length; offset += 32) {
        const block = createHash("sha256")
          .update(`${name}/${String(source.drawn)}/${String(offset)}`)
          .digest();
        bytes.set(block.subarray(0, Math.min(32, length - offset)), offset);
      }
      source.drawn += 1;
      return bytes;
    },
  };
  return source;
}

/** A passphrase lock with the least work accepted, so that a test takes milliseconds. */
export const quick = (text = "correct horse battery staple") =>
  passphrase(text, { n: SCRYPT_MIN_N });

export const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
export const unhex = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, "hex"));

/** A keychain that is a map, and counts what is asked of it. */
export function memoryKeychain(): Keychain & { readonly kept: Map<string, string> } {
  const kept = new Map<string, string>();
  const name = (service: string, account: string): string => `${service}\n${account}`;
  return {
    kept,
    get: (service, account) => Promise.resolve(kept.get(name(service, account))),
    set: (service, account, secret) => {
      kept.set(name(service, account), secret);
      return Promise.resolve();
    },
    delete: (service, account) => {
      kept.delete(name(service, account));
      return Promise.resolve();
    },
  };
}
