// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A storage that is a directory. Each document is a file named
 * `<name>.<version>.json`, and the version counts its writes.
 *
 * A write never changes a file. It writes the whole document to a temporary
 * file, makes that durable, and then links it to the name of the next
 * version. A link is made whole or not at all, and fails if the name is
 * taken: of two writers that read one version, one links the next and the
 * other is told that the document changed. Only then is the old version
 * removed. A process that stops at any point leaves either the old document
 * or the new one, never a part of one.
 */

import { constants } from "node:fs";
import { link, mkdir, open, readdir, readFile, stat, unlink } from "node:fs/promises";
import { join } from "node:path";

import { bytesToBase64url } from "@oip/core";

import { KeystoreError } from "./errors.ts";
import { draw, type Randomness, systemRandomness } from "./randomness.ts";
import { checkStorageName, type KeyStorage, type Stored } from "./storage.ts";

/** What `fileStorage` takes besides the directory. */
export interface FileStorageOptions {
  /** Where the names of temporary files come from. Default: the platform's generator. */
  readonly randomness?: Randomness;
}

const DOCUMENT = /^([a-z][a-z0-9-]{0,31})\.([1-9][0-9]{0,14})\.json$/u;

const codeOf = (error: unknown): unknown => (error as { code?: unknown } | null)?.code;

/**
 * A storage in a directory of the file system, for Node.js.
 *
 * The directory is made if it is not there, for its owner alone (mode 700),
 * and every file in it is its owner's alone (mode 600). A directory that
 * others can read or enter is refused, as OpenSSH refuses a private key that
 * others can read: what is in it is sealed, and a passphrase can be guessed
 * at leisure by whoever has a copy. Windows has no such modes, and nothing
 * is checked there.
 *
 * @throws KeystoreError `unsafe`, from every call, if the directory is open
 *   to others.
 */
export function fileStorage(directory: string, options: FileStorageOptions = {}): KeyStorage {
  const randomness = options.randomness ?? systemRandomness;
  let checked: Promise<void> | undefined;

  /** Makes the directory, or checks that the one there is its owner's alone. Once. */
  const ready = (): Promise<void> => {
    checked ??= (async () => {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      if (process.platform === "win32") return;
      const { mode } = await stat(directory);
      if ((mode & 0o077) !== 0) {
        throw new KeystoreError("unsafe", "the directory can be read or entered by others");
      }
    })();
    return checked;
  };

  /** The versions of a document that are in the directory, greatest first. */
  const versionsOf = async (name: string): Promise<number[]> => {
    const versions: number[] = [];
    for (const file of await readdir(directory)) {
      const match = DOCUMENT.exec(file);
      if (match?.[1] === name) versions.push(Number(match[2]));
    }
    return versions.sort((a, b) => b - a);
  };

  const fileOf = (name: string, version: number): string =>
    join(directory, `${name}.${String(version)}.json`);

  /** Removes a file. One that is gone already was removed by another reader or writer. */
  const remove = async (path: string): Promise<void> => {
    try {
      await unlink(path);
    } catch (error) {
      if (codeOf(error) !== "ENOENT") throw error;
    }
  };

  /** Makes the names in the directory durable. Not every platform can: the files themselves are. */
  const syncDirectory = async (): Promise<void> => {
    let handle;
    try {
      handle = await open(directory, constants.O_RDONLY);
      await handle.sync();
    } catch {
      // Windows does not open a directory, and some file systems do not sync one.
    } finally {
      await handle?.close();
    }
  };

  const get = async (name: string): Promise<Stored | undefined> => {
    checkStorageName(name);
    await ready();
    // A writer may remove the version read between the listing and the reading: look again.
    for (let attempt = 0; attempt < 8; attempt++) {
      const [latest, ...older] = await versionsOf(name);
      if (latest === undefined) return undefined;
      try {
        const value = new Uint8Array(await readFile(fileOf(name, latest)));
        // What a writer that stopped left behind. The latest version has all that matters.
        for (const version of older) await remove(fileOf(name, version));
        return { value, version: String(latest) };
      } catch (error) {
        if (codeOf(error) !== "ENOENT") throw error;
      }
    }
    throw new KeystoreError("changed");
  };

  const put = async (
    name: string,
    value: Uint8Array,
    expected: string | undefined,
  ): Promise<string> => {
    checkStorageName(name);
    await ready();
    const [latest] = await versionsOf(name);
    if ((latest === undefined ? undefined : String(latest)) !== expected) {
      throw new KeystoreError("changed");
    }
    const next = (latest ?? 0) + 1;
    const temporary = join(directory, `.${name}.${bytesToBase64url(draw(randomness, 12))}.tmp`);
    const handle = await open(
      temporary,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600,
    );
    try {
      try {
        await handle.writeFile(value);
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        await link(temporary, fileOf(name, next));
      } catch (error) {
        // Another writer made this version first.
        if (codeOf(error) === "EEXIST") throw new KeystoreError("changed");
        throw error;
      }
    } finally {
      await remove(temporary);
    }
    if (latest !== undefined) await remove(fileOf(name, latest));
    await syncDirectory();
    return String(next);
  };

  return {
    get,
    put,
    delete: async (name, expected) => {
      checkStorageName(name);
      await ready();
      const [latest] = await versionsOf(name);
      if (latest === undefined || String(latest) !== expected) throw new KeystoreError("changed");
      await remove(fileOf(name, latest));
      await syncDirectory();
      // A writer that made the next version meanwhile has the document still.
      if ((await versionsOf(name)).length > 0) throw new KeystoreError("changed");
    },
    list: async () => {
      await ready();
      const names = new Set<string>();
      for (const file of await readdir(directory)) {
        const match = DOCUMENT.exec(file);
        if (match?.[1] !== undefined) names.add(match[1]);
      }
      return [...names];
    },
  };
}
