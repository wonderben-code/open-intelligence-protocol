// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that could not be finished leaves no trace.
 *
 * This test has a file of its own on purpose. Where a function runs out of
 * stack depends on how the engine has compiled it, and code that other tests
 * have already run many times is compiled into fewer and larger frames. In a
 * file of its own the code is as cold as in a process that has just started,
 * which is when the fault this guards against was found.
 */

import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { ed25519PublicKey, isEd25519PublicKey, signEd25519, verifyEd25519 } from "../src/index.ts";
import { withStackSpent } from "./stack.ts";

describe(`${clause("core 4.4")} a check that could not be finished`, () => {
  it("leaves no trace: a spent stack never marks an honest key as bad", () => {
    // A key that passes the order check is remembered. A check cut short must not
    // be remembered as a no: when every answer was remembered, one call from a deep
    // stack turned an honest key away until the memory forgot it.
    const text = new TextEncoder().encode("signed before the key was ever checked");
    let cutShort = 0;
    for (const fill of [77, 78, 79, 80]) {
      const seed = new Uint8Array(32).fill(fill);
      const key = ed25519PublicKey(seed);
      const made = signEd25519(text, seed);
      const spent =
        fill % 2 === 1
          ? withStackSpent(() => verifyEd25519(made, text, key))
          : withStackSpent(() => isEd25519PublicKey(key));
      // It answers from the moment it can be entered, and never throws.
      expect(spent).toHaveLength(200);
      expect(new Set(spent.map((answer) => typeof answer))).toEqual(new Set(["boolean"]));
      if (spent.includes(false)) cutShort++;
      // Whatever it could answer then, it answers rightly now.
      expect(verifyEd25519(made, text, key), `key ${fill}`).toBe(true);
      expect(isEd25519PublicKey(key), `key ${fill}`).toBe(true);
    }
    // The test means something only if a check really was cut short for a key
    // that had never passed one. If this fails, the engine no longer runs out of
    // stack inside the check, and the test must find another way to make it.
    expect(cutShort).toBeGreaterThan(0);
  });
});
