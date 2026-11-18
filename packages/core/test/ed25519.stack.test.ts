// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that could not be finished leaves no trace.
 *
 * `spent-stack.test.ts` cuts the order check short by spending the call
 * stack, which depends on the engine. This makes the same fault for certain.
 */

import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import { ed25519PublicKey, isEd25519PublicKey } from "../src/index.ts";
import { hasOrderL } from "../src/ed25519.ts";

describe(`${clause("core 4.4")} a check that could not be finished`, () => {
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
