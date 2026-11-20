// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Ed25519 by OpenSSL, as a service uses it. The rule is `@oip/core`'s, and
 * its own tests run it with OpenSSL too. Here the engine this package ships
 * is held to the library's answers, signature by signature.
 */

import {
  type Ed25519Engine,
  ed25519PublicKey,
  forgetVerifiedSignatures,
  signEd25519,
  useEd25519Engine,
  utf8,
  verifyEd25519,
} from "@oip/core";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { usePortableEd25519 } from "../../core/src/ed25519.ts";
import {
  craftSignature,
  expand,
  L,
  orderOf,
  Point,
  smallOrderPoints,
  unreduced,
} from "../../core/test/curve.ts";
import { nativeEd25519, useNativeEd25519 } from "../src/index.ts";

const privateKey = new Uint8Array(32).fill(31);
const publicKey = ed25519PublicKey(privateKey);
const message = utf8("checked by OpenSSL");
const honest = signEd25519(message, privateKey);

const fresh = (): void => {
  usePortableEd25519();
  forgetVerifiedSignatures();
};
beforeEach(fresh);
afterAll(fresh);

describe(`${clause("core 4.4")} Ed25519 by OpenSSL`, () => {
  it("is taken by @oip/core, which tries it first, and then does the arithmetic", () => {
    expect(useNativeEd25519()).toBe(true);
    // Asked again, it is in use already.
    expect(useNativeEd25519()).toBe(true);
    expect(verifyEd25519(honest, message, publicKey)).toBe(true);
    expect(verifyEd25519(honest, utf8("another message"), publicKey)).toBe(false);
    expect(verifyEd25519(unreduced(honest), message, publicKey)).toBe(false);
  });

  it("leaves the process as it was where another engine is in use", () => {
    let asked = 0;
    const other: Ed25519Engine = (signature, text, key) => {
      asked++;
      return nativeEd25519(signature, text, key);
    };
    useEd25519Engine(other);
    asked = 0;
    expect(useNativeEd25519()).toBe(false);
    expect(verifyEd25519(honest, message, publicKey)).toBe(true);
    expect(asked).toBe(1);
  });

  it("answers for itself what OpenSSL is asked: the equation without the cofactor", () => {
    expect(nativeEd25519(honest, message, publicKey)).toBe(true);
    expect(nativeEd25519(honest, utf8("another message"), publicKey)).toBe(false);
    expect(nativeEd25519(unreduced(honest), message, publicKey)).toBe(false);
    const { scalar, publicKey: key } = expand(new Uint8Array(32).fill(33));
    for (const point of smallOrderPoints()) {
      if (point.is0()) continue;
      // The equation with the cofactor holds for it, and the one without does not.
      expect(nativeEd25519(craftSignature(scalar, key, message, 77n, point), message, key)).toBe(
        false,
      );
    }
    // What it is not asked: a key with a small-order component, which it takes for some of
    // them. `@oip/core` checks the key before it asks, and refuses each.
    let taken = 0;
    for (const point of smallOrderPoints()) {
      if (point.is0()) continue;
      const mixed = Point.fromBytes(key, false).add(point).toBytes();
      const signature = craftSignature(scalar, mixed, message, 78n);
      if (nativeEd25519(signature, message, mixed)) taken++;
      expect(useNativeEd25519()).toBe(true);
      expect(verifyEd25519(signature, message, mixed)).toBe(false);
    }
    expect(taken).toBeGreaterThan(0);
  });

  it("gives the answer the library gives, for signatures of every kind", () => {
    const { scalar: secret, publicKey: key } = expand(new Uint8Array(32).fill(35));
    const small = smallOrderPoints().filter((point) => !point.is0());
    const order8 = small.find((point) => orderOf(point) === 8) ?? Point.ZERO;
    const mixedKey = Point.fromBytes(key, false).add(order8).toBytes();
    const flipped = (bytes: Uint8Array, bit: number): Uint8Array => {
      const copy = Uint8Array.from(bytes);
      const at = (bit >> 3) % copy.length;
      copy[at] = (copy[at] ?? 0) ^ (1 << (bit & 7));
      return copy;
    };
    const joined = (r: Uint8Array, s: Uint8Array): Uint8Array => Uint8Array.from([...r, ...s]);
    const cases = fc.record({
      text: fc.uint8Array({ maxLength: 48 }),
      nonce: fc.bigInt({ min: 0n, max: L - 1n }),
      kind: fc.constantFrom(
        "honest",
        "S not reduced",
        "R with a small-order part",
        "R of small order",
        "a mixed-order key",
        "a bit of R",
        "a bit of S",
        "a bit of the key",
        "a bit of the message",
        "random bytes",
      ),
      which: fc.nat(),
      random: fc.uint8Array({ minLength: 96, maxLength: 96 }),
    });
    let accepted = 0;
    fc.assert(
      fc.property(cases, ({ text, nonce, kind, which, random }) => {
        const offset = small[which % small.length] ?? Point.ZERO;
        const good = craftSignature(secret, key, text, nonce);
        const [r, s] = [good.subarray(0, 32), good.subarray(32)];
        const made: Record<string, () => [Uint8Array, Uint8Array, Uint8Array]> = {
          honest: () => [good, text, key],
          "S not reduced": () => [unreduced(good), text, key],
          "R with a small-order part": () => [
            craftSignature(secret, key, text, nonce, offset),
            text,
            key,
          ],
          "R of small order": () => [craftSignature(secret, key, text, 0n, offset), text, key],
          "a mixed-order key": () => [
            craftSignature(secret, mixedKey, text, nonce),
            text,
            mixedKey,
          ],
          "a bit of R": () => [joined(flipped(r, which), s), text, key],
          "a bit of S": () => [joined(r, flipped(s, which)), text, key],
          "a bit of the key": () => [good, text, flipped(key, which)],
          "a bit of the message": () => [good, flipped(Uint8Array.from([...text, 0]), which), key],
          "random bytes": () => [random.subarray(0, 64), text, random.subarray(64)],
        };
        const triple = (made[kind] ?? made["honest"])?.() ?? [good, text, key];
        fresh();
        const byLibrary = verifyEd25519(...triple);
        fresh();
        expect(useNativeEd25519()).toBe(true);
        expect(verifyEd25519(...triple), kind).toBe(byLibrary);
        // A nonce of 0 makes R the identity: the one honest-looking signature that is none.
        expect(byLibrary, kind).toBe(kind === "honest" && nonce !== 0n);
        if (byLibrary) accepted++;
      }),
      { numRuns: Number(process.env["OIP_ED25519_RUNS"] ?? 300) },
    );
    expect(accepted).toBeGreaterThan(0);
  });
});
