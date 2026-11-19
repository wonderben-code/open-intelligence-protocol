// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A bounded memo. Results of pure functions are remembered so that work is
 * not repeated, and the least recently used are forgotten so that hostile
 * input cannot grow the memory without bound. Remembering never changes a
 * result.
 */
export class BoundedCache<V> {
  readonly #entries = new Map<string, V>();
  readonly #capacity: number;

  constructor(capacity: number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) {
      throw new TypeError("a cache holds at least one entry");
    }
    this.#capacity = capacity;
  }

  /** How many results are remembered. */
  get size(): number {
    return this.#entries.size;
  }

  /** Whether a result for the key is remembered. It does not count as a use. */
  has(key: string): boolean {
    return this.#entries.has(key);
  }

  /** The remembered result for a key, or the result of `compute`, which is then remembered. */
  get(key: string, compute: () => V): V {
    if (this.#entries.has(key)) {
      const value = this.#entries.get(key) as V;
      // Moving the entry to the end marks it as the most recently used.
      this.#entries.delete(key);
      this.#entries.set(key, value);
      return value;
    }
    const value = compute();
    if (this.#entries.size >= this.#capacity) {
      // A Map iterates in insertion order, so the first key is the least recently used.
      for (const oldest of this.#entries.keys()) {
        this.#entries.delete(oldest);
        break;
      }
    }
    this.#entries.set(key, value);
    return value;
  }
}
