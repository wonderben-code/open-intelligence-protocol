// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Measuring what a value keeps in memory. A reading of the heap taken while
 * garbage is still on it depends on when the collector last ran, and a test
 * built on it fails once in so many runs. These readings are taken after a
 * collection.
 */

import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";

let collect: (() => void) | undefined;

/** Runs a full garbage collection. */
function collectGarbage(): void {
  if (collect === undefined) {
    // The collector is not offered to programs unless the engine is asked.
    setFlagsFromString("--expose-gc");
    collect = runInNewContext("gc") as () => void;
  }
  collect();
}

/** The bytes of heap in use, after a collection. */
export function heapInUse(): number {
  collectGarbage();
  return process.memoryUsage().heapUsed;
}

/**
 * The bytes of heap that a value keeps alive, once what it took to build it
 * has been collected: the value is built, and the heap is read before and
 * after, each time after a collection.
 */
export function heapKeptBy<T>(build: () => T): { readonly value: T; readonly bytes: number } {
  const before = heapInUse();
  const value = build();
  const bytes = heapInUse() - before;
  return { value, bytes };
}
