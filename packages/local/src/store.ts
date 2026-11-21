// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a program remembers of its work between its runs: small JSON files
 * in a directory, each under a name the program makes.
 *
 * A key may be a stranger's choice: the name a system outside the network
 * gives a task, say, which is any text at all. No file is named by one. A
 * file is named by the digest of its key, written whole or not at all, and
 * readable by its owner alone.
 *
 * What is written is on the disk when `put` returns: a program that notes
 * that it is about to do a thing once, and does it, must find its note
 * after a loss of power too.
 */

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";

import { sha256 } from "@oip/core";

const SUFFIX = ".json";
/** What a file is called while it is written. */
const PARTIAL = ".partial";
/** How old a file that was never finished is before it is cleared away, in milliseconds. */
const STALE_PARTIAL_MS = 60_000;

/** Has what was written to a file, or to a directory's list of names, put on the disk. */
function synced(path: string, flags: string): void {
  let opened: number;
  try {
    opened = openSync(path, flags);
  } catch {
    // A directory cannot be opened so everywhere. What can be made durable is.
    return;
  }
  try {
    fsyncSync(opened);
  } catch {
    // As above.
  } finally {
    closeSync(opened);
  }
}

/**
 * A name that any file system takes, for any text: forty hexadecimal
 * digits of the text's SHA-256 digest. Two texts have one name only if
 * their digests agree in 160 bits.
 */
export function fileNameOf(text: string): string {
  const digest = sha256(new TextEncoder().encode(text));
  const name = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return name.slice(0, 40);
}

/** A directory of JSON values, by key. */
export class Store<T> {
  readonly #dir: string;

  constructor(dir: string) {
    this.#dir = dir;
  }

  #file(key: string): string {
    // A text with half a pair of surrogates has no UTF-8 of its own: an encoder writes the
    // same bytes for any such half. Its JSON names it exactly, and two keys never share a file.
    const named = /\p{Cs}/u.test(key) ? JSON.stringify(key) : key;
    return join(this.#dir, `${fileNameOf(named)}${SUFFIX}`);
  }

  /**
   * Whether a file is kept under a key, readable or not. `get` and `all`
   * pass over a file they cannot read: this says that it is there all the
   * same, to whoever must not take "not read" for "not there".
   */
  has(key: string): boolean {
    return existsSync(this.#file(key));
  }

  /** What is kept under a key, or `undefined` if nothing is, or what is there is not JSON. */
  get(key: string): T | undefined {
    try {
      const kept = JSON.parse(readFileSync(this.#file(key), "utf8")) as { key?: unknown; value: T };
      // Two keys with one digest are not to be had: the key is kept all the same, and checked.
      return kept.key === key ? kept.value : undefined;
    } catch {
      return undefined;
    }
  }

  /** Keeps a value under a key, in place of what was there. It is on the disk when this returns. */
  put(key: string, value: T): void {
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    const file = this.#file(key);
    const partial = `${file}${PARTIAL}`;
    const opened = openSync(partial, "w", 0o600);
    try {
      writeSync(opened, JSON.stringify({ key, value }));
      fsyncSync(opened);
    } finally {
      closeSync(opened);
    }
    renameSync(partial, file);
    synced(this.#dir, "r");
  }

  /** Removes what is kept under a key, if anything is. */
  delete(key: string): void {
    rmSync(this.#file(key), { force: true });
  }

  /** Everything kept, in no particular order. A file that holds no such thing is passed over. */
  all(): { key: string; value: T }[] {
    let names: string[];
    try {
      names = readdirSync(this.#dir);
    } catch {
      return [];
    }
    for (const name of names) {
      if (!name.endsWith(PARTIAL)) continue;
      // What a stop between the writing and the naming left behind. It is nobody's value.
      const left = join(this.#dir, name);
      try {
        if (Date.now() - statSync(left).mtimeMs > STALE_PARTIAL_MS) rmSync(left, { force: true });
      } catch {
        // Gone already, or being written now.
      }
    }
    return names
      .filter((name) => name.endsWith(SUFFIX))
      .flatMap((name) => {
        try {
          const kept = JSON.parse(readFileSync(join(this.#dir, name), "utf8")) as {
            key?: unknown;
            value: T;
          };
          return typeof kept.key === "string" ? [{ key: kept.key, value: kept.value }] : [];
        } catch {
          return [];
        }
      });
  }
}
