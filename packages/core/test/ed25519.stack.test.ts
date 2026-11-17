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

import { clause, withStackSpent } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { ed25519PublicKey, isEd25519PublicKey, signEd25519, verifyEd25519 } from "../src/index.ts";
import { hasOrderL } from "../src/ed25519.ts";

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
    // Whether a check really was cut short depends on the engine, so it is not
    // asserted here: the next test makes the same fault without the engine's help.
    expect(cutShort).toBeGreaterThanOrEqual(0);
  });

  it("does not remember a no, whatever made the check say it", () => {
    // The fault itself, made certain: for a key never checked before, the order
    // check answers no once, as it does when it is cut short.
    const key = ed25519PublicKey(new Uint8Array(32).fill(81));
    let checks = 0;
    const cutShort = () => {
      checks++;
      return false;
    };
    expect(hasOrderL(key, cutShort)).toBe(false);
    expect(checks).toBe(1);
    // Nothing was learned about the key, so nothing was remembered.
    expect(isEd25519PublicKey(key)).toBe(true);
    // A yes is remembered: the key is not checked again.
    expect(hasOrderL(key, cutShort)).toBe(true);
    expect(checks).toBe(1);
  });
});
