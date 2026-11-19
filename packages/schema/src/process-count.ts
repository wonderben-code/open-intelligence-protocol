// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The one count of checks cut short that a process keeps (ADR-0010).
 *
 * A program may hold two copies of this package, from two installed
 * versions or two bundles: `@oip/core` then notes a failure through one
 * while `@oip/identity` compares through the other, and a count that each
 * copy kept for itself would lose the note. So the count is kept where
 * every copy finds it, on the global object, under a symbol from the
 * registry a process shares.
 *
 * This is the only file of the pure packages that names the global object,
 * and it reads and writes that one property of it. The lint rules that
 * keep ambient state out of the pure packages make this one exception, and
 * `scripts/check-guards.ts` holds it to this.
 */

/** The count of failures noted. An object, so that every copy holds the same one. */
export interface Count {
  noted: number;
}

/** The name ends in a number, which changes if what is kept under it ever does. */
const COUNT = Symbol.for("@oip/schema/cut-short/1");

/**
 * The count of the process: the one an earlier copy of this package left
 * for the others, or a new one left for them.
 *
 * Where the global object takes no new property, or holds something else
 * under the name, the count is the caller's alone: one copy in such a
 * process works as it would with the count shared.
 *
 * Other code may freeze what the global object holds after this has run,
 * the count with it. Whoever adds to the count allows for that.
 *
 * @param shared - Where the count is kept. It is the global object, named
 *   as an object with this one property, so that the compiler lets no other
 *   be read. A test passes an object of its own.
 */
export function countOfTheProcess(shared: { [COUNT]?: unknown } = globalThis as object): Count {
  const own: Count = { noted: 0 };
  try {
    const left = shared[COUNT];
    if (
      typeof left === "object" &&
      left !== null &&
      // A count, and nothing that only looks like one: a number that is none would never
      // again compare equal to itself, and every judge would refuse for ever.
      Number.isSafeInteger((left as Partial<Count>).noted)
    ) {
      return left as Count;
    }
    Object.defineProperty(shared, COUNT, { value: own });
  } catch {
    // A global object that is frozen, or a property there that is something else.
  }
  return own;
}
