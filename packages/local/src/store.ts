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
 */

import { mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { sha256 } from "@oip/core";

const SUFFIX = ".json";

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
    return join(this.#dir, `${fileNameOf(key)}${SUFFIX}`);
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

  /** Keeps a value under a key, in place of what was there. */
  put(key: string, value: T): void {
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    const file = this.#file(key);
    writeFileSync(`${file}.partial`, JSON.stringify({ key, value }), { mode: 0o600 });
    renameSync(`${file}.partial`, file);
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
