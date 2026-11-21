// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The keychain of the operating system, for Node.js: the Keychain of macOS,
 * the Credential Manager of Windows, the Secret Service of a Linux desktop.
 *
 * It is reached through `@napi-rs/keyring` (ADR-0019), which a keystore
 * needs only if it is locked this way: the package is an optional peer, and
 * is loaded when `systemKeychain` is called.
 */

import { KeystoreError } from "./errors.ts";
import type { Keychain } from "./lock.ts";

/** One entry of the keychain, as far as it is used here. */
export interface KeyringEntry {
  /** The secret kept, or `null` if there is none. */
  getPassword(): Promise<string | null>;
  /** Keeps a secret, in the place of the one there. */
  setPassword(password: string): Promise<void>;
  /** Removes the secret. Whether there was one. */
  deleteCredential(): Promise<boolean>;
}

/** What is used of `@napi-rs/keyring`. */
export interface KeyringLibrary {
  /** An entry under a service and an account. */
  readonly AsyncEntry: new (service: string, account: string) => KeyringEntry;
}

/** What `systemKeychain` takes. */
export interface SystemKeychainOptions {
  /** Loads the library. Default: `import("@napi-rs/keyring")`. A test gives a stand-in. */
  readonly load?: () => Promise<KeyringLibrary>;
}

/**
 * The keychain of the operating system.
 *
 * What it keeps is as safe as the user's session: whatever runs as that
 * user, with the keychain unlocked, can ask it for the same secret. It keeps
 * keys from a copy of the disk, and from other users of the machine.
 *
 * @throws KeystoreError `no-keychain` if the library is not installed, or
 *   has nothing for this platform. Each call of the keychain it returns
 *   throws the same if the keychain cannot be reached: where there is none,
 *   as on a server without a desktop session, or where it is locked.
 */
export async function systemKeychain(options: SystemKeychainOptions = {}): Promise<Keychain> {
  const load = options.load ?? ((): Promise<KeyringLibrary> => import("@napi-rs/keyring"));
  let library: KeyringLibrary;
  try {
    library = await load();
  } catch {
    throw new KeystoreError("no-keychain", "the package @napi-rs/keyring could not be loaded");
  }
  if (typeof (library as Partial<KeyringLibrary>).AsyncEntry !== "function") {
    throw new KeystoreError("no-keychain", "the package @napi-rs/keyring is not the one expected");
  }
  /** Runs one call. What the platform says of a failure is not passed on: a secret may be near it. */
  const reaching = async <T>(what: string, call: () => Promise<T>): Promise<T> => {
    try {
      return await call();
    } catch {
      throw new KeystoreError("no-keychain", `it did not ${what}`);
    }
  };
  return {
    get: (service, account) =>
      reaching("give what it keeps", async () => {
        const kept: unknown = await new library.AsyncEntry(service, account).getPassword();
        return typeof kept === "string" ? kept : undefined;
      }),
    set: (service, account, secret) =>
      reaching("keep what it was given", () =>
        new library.AsyncEntry(service, account).setPassword(secret),
      ),
    delete: (service, account) =>
      reaching("remove what it keeps", async () => {
        await new library.AsyncEntry(service, account).deleteCredential();
      }),
  };
}
