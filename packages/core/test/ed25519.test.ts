// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { ed25519 } from "@noble/curves/ed25519.js";
import { clause, readVectors, withAmbientTrapped } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { BoundedCache } from "../src/cache.ts";
import {
  bytesToHex,
  ed25519PublicKey,
  hexToBytes,
  isEd25519PublicKey,
  ORDER_CHECK_CACHE_SIZE,
  PRIVATE_KEY_LENGTH,
  PUBLIC_KEY_LENGTH,
  SIGNATURE_LENGTH,
  signEd25519,
  verifyEd25519,
} from "../src/index.ts";
import { withStackSpent } from "./stack.ts";
import {
  craftSignature,
  expand,
  fromLittleEndian,
  L,
  littleEndian,
  orderOf,
  P,
  Point,
  smallOrderPoints,
  unreduced,
} from "./curve.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);

/** RFC 8032, Section 7.1. */
const RFC8032 = [
  {
    name: "TEST 1",
    privateKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    message: "",
    signature:
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  },
  {
    name: "TEST 2",
    privateKey: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature:
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  },
  {
    name: "TEST 3",
    privateKey: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    publicKey: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    message: "af82",
    signature:
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
      "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  },
  {
    name: "TEST SHA(abc)",
    privateKey: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    publicKey: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    message:
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    signature:
      "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589" +
      "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
  },
];

const privateKey = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const { scalar, publicKey } = expand(privateKey);
const message = utf8("a message");
const honest = signEd25519(message, privateKey);
const torsion = smallOrderPoints();
const order8 = torsion.find((point) => orderOf(point) === 8) ?? Point.ZERO;

/** What the library alone answers, in its strict mode: the baseline that core 4.4 tightens. */
const libraryAccepts = (signature: Uint8Array, text: Uint8Array, key: Uint8Array) => {
  try {
    return ed25519.verify(signature, text, key, { zip215: false });
  } catch {
    return false;
  }
};

describe("Ed25519, as RFC 8032 defines it", () => {
  it.each(RFC8032)("reproduces $name", (vector) => {
    const key = hexToBytes(vector.privateKey);
    const text = hexToBytes(vector.message);
    expect(bytesToHex(ed25519PublicKey(key))).toBe(vector.publicKey);
    expect(bytesToHex(signEd25519(text, key))).toBe(vector.signature);
    expect(verifyEd25519(hexToBytes(vector.signature), text, hexToBytes(vector.publicKey))).toBe(
      true,
    );
    expect(isEd25519PublicKey(hexToBytes(vector.publicKey))).toBe(true);
  });

  it("has the lengths RFC 8032 gives", () => {
    expect([PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH]).toEqual([32, 32, 64]);
    expect(ed25519PublicKey(privateKey)).toHaveLength(32);
    expect(honest).toHaveLength(64);
  });

  it("derives every test key of the vectors from its seed", () => {
    for (const [label, key] of Object.entries(
      (readVectors() as unknown as { keys: Record<string, { seed_hex: string; type?: string }> })
        .keys,
    )) {
      if (key.type === "X25519") continue;
      expect(isEd25519PublicKey(ed25519PublicKey(hexToBytes(key.seed_hex))), label).toBe(true);
    }
  });

  it("signs deterministically and verifies what it signs", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ maxLength: 200 }),
        (key, text) => {
          const signature = signEd25519(text, key);
          expect(signEd25519(text, key)).toEqual(signature);
          expect(verifyEd25519(signature, text, ed25519PublicKey(key))).toBe(true);
        },
      ),
      { numRuns: 30 },
    );
  });

  it("rejects a signature when any bit of the signature, the message or the key changes", () => {
    fc.assert(
      fc.property(
        fc.constantFrom("signature", "message", "key"),
        fc.nat(),
        fc.integer({ min: 0, max: 7 }),
        (part, position, bit) => {
          const changed = {
            signature: Uint8Array.from(honest),
            message: Uint8Array.from(message),
            key: Uint8Array.from(publicKey),
          };
          const target = changed[part];
          const index = position % target.length;
          target[index] = (target[index] ?? 0) ^ (1 << bit);
          expect(verifyEd25519(changed.signature, changed.message, changed.key)).toBe(false);
        },
      ),
      { numRuns: 300 },
    );
  });

  it("refuses private keys and messages of the wrong form, and says nothing about them", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0), "key", null]) {
      expect(() => ed25519PublicKey(bad as Uint8Array)).toThrow(
        new TypeError("an Ed25519 private key is 32 bytes"),
      );
      expect(() => signEd25519(message, bad as Uint8Array)).toThrow(
        new TypeError("an Ed25519 private key is 32 bytes"),
      );
    }
    expect(() => signEd25519("text" as unknown as Uint8Array, privateKey)).toThrow(
      new TypeError("a message to sign is bytes"),
    );
  });

  it("never throws when verifying, whatever it is given", () => {
    const wrong: unknown[] = [undefined, null, "text", 1, {}, [], new Uint8Array(0), honest.buffer];
    for (const value of wrong) {
      expect(verifyEd25519(value as Uint8Array, message, publicKey)).toBe(false);
      expect(verifyEd25519(honest, value as Uint8Array, publicKey)).toBe(false);
      expect(verifyEd25519(honest, message, value as Uint8Array)).toBe(false);
      expect(isEd25519PublicKey(value as Uint8Array)).toBe(false);
    }
    expect(verifyEd25519(honest.subarray(0, 63), message, publicKey)).toBe(false);
    expect(verifyEd25519(Uint8Array.from([...honest, 0]), message, publicKey)).toBe(false);
    expect(verifyEd25519(honest, message, publicKey.subarray(0, 31))).toBe(false);
    expect(verifyEd25519(honest, message, Uint8Array.from([...publicKey, 0]))).toBe(false);
  });

  it("verifies without reading the clock or any randomness", () => {
    const answers = withAmbientTrapped(() => [
      verifyEd25519(honest, message, publicKey),
      verifyEd25519(unreduced(honest), message, publicKey),
      isEd25519PublicKey(publicKey),
      isEd25519PublicKey(littleEndian(12345n)),
    ]);
    expect(answers).toEqual([true, false, true, false]);
  });

  it("signs without reading the clock, and the signature does not depend on randomness", () => {
    // The library masks the secret scalar with random values against side
    // channels (ADR-0002). That is the only ambient state signing may reach.
    const signed = withAmbientTrapped(
      () => [
        bytesToHex(signEd25519(message, privateKey)),
        bytesToHex(ed25519PublicKey(privateKey)),
      ],
      { randomness: true },
    );
    expect(signed).toEqual([bytesToHex(honest), bytesToHex(publicKey)]);
    // With a generator that always returns the same bytes, the signature is the same.
    const real = crypto.getRandomValues.bind(crypto);
    let calls = 0;
    crypto.getRandomValues = <T extends ArrayBufferView | null>(array: T): T => {
      calls++;
      if (array instanceof Uint8Array) array.fill(0x5a);
      return array;
    };
    try {
      expect(bytesToHex(signEd25519(message, privateKey))).toBe(bytesToHex(honest));
    } finally {
      crypto.getRandomValues = real;
    }
    expect(calls).toBeGreaterThan(0);
  });
});

describe(`${clause("core 4.4")} one verification rule for every implementation`, () => {
  it("has exactly eight points of small order to guard against", () => {
    expect(torsion.map(orderOf).sort()).toEqual([1, 2, 4, 4, 8, 8, 8, 8]);
    expect(orderOf(order8)).toBe(8);
  });

  it("item 1: rejects a signature whose S is not less than L", () => {
    const notReduced = unreduced(honest);
    expect(fromLittleEndian(notReduced.subarray(32))).toBe(
      fromLittleEndian(honest.subarray(32)) + L,
    );
    expect(verifyEd25519(honest, message, publicKey)).toBe(true);
    expect(verifyEd25519(notReduced, message, publicKey)).toBe(false);
    // S = L itself, and the largest S that fits.
    const atL = Uint8Array.from([...honest.subarray(0, 32), ...littleEndian(L)]);
    const largest = Uint8Array.from([...honest.subarray(0, 32), ...new Uint8Array(32).fill(0xff)]);
    expect(verifyEd25519(atL, message, publicKey)).toBe(false);
    expect(verifyEd25519(largest, message, publicKey)).toBe(false);
  });

  it("item 2: rejects every non-canonical encoding of a point, as a key and as R", () => {
    const nonCanonical = [
      // The identity and the point of order 2, with the sign bit set on x = 0.
      "0100000000000000000000000000000000000000000000000000000000000080",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      // y = p and y = p + 1: the y-coordinate is not less than 2^255 - 19.
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      // The largest y that 255 bits hold.
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    for (const hex of nonCanonical) {
      const encoded = hexToBytes(hex);
      expect(isEd25519PublicKey(encoded), hex).toBe(false);
      const asR = Uint8Array.from([...encoded, ...honest.subarray(32)]);
      expect(verifyEd25519(asR, message, publicKey), hex).toBe(false);
      expect(verifyEd25519(honest, message, encoded), hex).toBe(false);
    }
    // No point of order L has a second encoding: one needs y below 19, and no such point has order L.
    for (let y = 0n; y < 19n; y++) {
      for (const sign of [0, 0x80]) {
        const canonical = littleEndian(y);
        canonical[31] = (canonical[31] ?? 0) | sign;
        const second = littleEndian(y + P);
        second[31] = (second[31] ?? 0) | sign;
        expect(isEd25519PublicKey(canonical), `y = ${y}`).toBe(false);
        expect(isEd25519PublicKey(second), `y = ${y} + p`).toBe(false);
      }
    }
  });

  it("rejects bytes that are no point at all", () => {
    // y = 2 is on no point of the curve.
    expect(isEd25519PublicKey(littleEndian(2n))).toBe(false);
    expect(verifyEd25519(honest, message, littleEndian(2n))).toBe(false);
    const asR = Uint8Array.from([...littleEndian(2n), ...honest.subarray(32)]);
    expect(verifyEd25519(asR, message, publicKey)).toBe(false);
  });

  it("item 3: rejects the identity point as a key, for which anyone can sign anything", () => {
    const identity = Point.ZERO.toBytes();
    // With A the identity, [S]B = R + [k]A holds for S = nonce and R = [nonce]B: no secret is needed.
    const forged = craftSignature(0n, identity, message, 12345n);
    expect(isEd25519PublicKey(identity)).toBe(false);
    expect(verifyEd25519(forged, message, identity)).toBe(false);
  });

  it("item 3: rejects every small-order point as a key", () => {
    for (const point of torsion) {
      const key = point.toBytes();
      // The forgery satisfies the cofactored equation: [8][k]A is the identity for any k.
      const forged = craftSignature(0n, key, message, 777n);
      expect(isEd25519PublicKey(key), point.toHex()).toBe(false);
      expect(verifyEd25519(forged, message, key), point.toHex()).toBe(false);
    }
  });

  it("item 3: rejects a key with a small-order component, though the library accepts its signatures", () => {
    for (const point of torsion.filter((candidate) => !candidate.is0())) {
      const mixed = Point.fromBytes(publicKey, false).add(point).toBytes();
      const signature = craftSignature(scalar, mixed, message, 4242n);
      expect(libraryAccepts(signature, message, mixed), point.toHex()).toBe(true);
      expect(isEd25519PublicKey(mixed), point.toHex()).toBe(false);
      expect(verifyEd25519(signature, message, mixed), point.toHex()).toBe(false);
    }
  });

  it("item 3: rejects a signature whose R is the identity point", () => {
    const signature = craftSignature(scalar, publicKey, message, 0n);
    expect(bytesToHex(signature.subarray(0, 32))).toBe(Point.ZERO.toHex());
    expect(libraryAccepts(signature, message, publicKey)).toBe(true);
    expect(verifyEd25519(signature, message, publicKey)).toBe(false);
  });

  it("item 3: rejects a signature whose R has a small-order component", () => {
    for (const point of torsion.filter((candidate) => !candidate.is0())) {
      const signature = craftSignature(scalar, publicKey, message, 987654321n, point);
      expect(libraryAccepts(signature, message, publicKey), point.toHex()).toBe(true);
      expect(verifyEd25519(signature, message, publicKey), point.toHex()).toBe(false);
    }
    // R of small order alone: the nonce is zero and only the offset remains.
    for (const point of torsion) {
      const signature = craftSignature(scalar, publicKey, message, 0n, point);
      expect(verifyEd25519(signature, message, publicKey), point.toHex()).toBe(false);
    }
  });

  it("accepts the honest signature beside each of those: the control", () => {
    const control = craftSignature(scalar, publicKey, message, 987654321n);
    expect(verifyEd25519(control, message, publicKey)).toBe(true);
    expect(verifyEd25519(honest, message, publicKey)).toBe(true);
    expect(isEd25519PublicKey(publicKey)).toBe(true);
    expect(isEd25519PublicKey(Point.BASE.toBytes())).toBe(true);
  });

  it("item 4: rejects a signature that does not satisfy the equation", () => {
    const other = signEd25519(utf8("another message"), privateKey);
    expect(verifyEd25519(other, message, publicKey)).toBe(false);
    const swapped = Uint8Array.from([...honest.subarray(0, 32), ...other.subarray(32)]);
    expect(verifyEd25519(swapped, message, publicKey)).toBe(false);
    const otherKey = ed25519PublicKey(new Uint8Array(32).fill(7));
    expect(verifyEd25519(honest, message, otherKey)).toBe(false);
  });

  it("gives the same answer for a key whether or not its order check is remembered", () => {
    const mixed = Point.fromBytes(publicKey, false).add(order8).toBytes();
    for (let round = 0; round < 3; round++) {
      expect(isEd25519PublicKey(publicKey)).toBe(true);
      expect(isEd25519PublicKey(mixed)).toBe(false);
      expect(verifyEd25519(honest, message, publicKey)).toBe(true);
    }
    // A flood of distinct keys does not change the answer for one seen before.
    for (let i = 0; i < ORDER_CHECK_CACHE_SIZE + 10; i++) {
      isEd25519PublicKey(littleEndian(BigInt(i) + 1000n));
    }
    expect(isEd25519PublicKey(publicKey)).toBe(true);
    expect(isEd25519PublicKey(mixed)).toBe(false);
  });

  it("does not mistake one key for another that shares all but one of its bytes", () => {
    // What a key's order check is remembered under is the whole key. For each
    // position, a key of order L and its neighbour that differs in that byte
    // alone and is no such key: each keeps its own answer, whichever was seen first.
    const isKey = (bytes: Uint8Array): boolean => {
      try {
        const point = Point.fromBytes(bytes, false);
        // [L]P is the identity, worked out as [L-1]P + P: the library takes no scalar of L itself.
        return (
          !point.is0() &&
          point
            .multiplyUnsafe(L - 1n)
            .add(point)
            .is0()
        );
      } catch {
        return false;
      }
    };
    let pairs = 0;
    for (const position of [0, 1, 15, 16, 30, 31]) {
      for (const validFirst of [true, false]) {
        const key = ed25519PublicKey(new Uint8Array(32).fill(100 + pairs));
        const neighbour = Uint8Array.from(key);
        do neighbour[position] = ((neighbour[position] ?? 0) + 1) & 0xff;
        while (isKey(neighbour));
        expect(isKey(key)).toBe(true);
        expect(neighbour.filter((byte, i) => byte !== key[i])).toHaveLength(1);
        const [first, second] = validFirst ? [key, neighbour] : [neighbour, key];
        expect(isEd25519PublicKey(first), `position ${position}`).toBe(validFirst);
        expect(isEd25519PublicKey(second), `position ${position}`).toBe(!validFirst);
        // And both again, now that both are remembered.
        expect(isEd25519PublicKey(key), `position ${position}`).toBe(true);
        expect(isEd25519PublicKey(neighbour), `position ${position}`).toBe(false);
        // Verification uses the same memory: a mixed-order key next to a good one stays rejected.
        const { scalar: secret, publicKey: honestKey } = expand(
          new Uint8Array(32).fill(200 + pairs),
        );
        const good = craftSignature(secret, honestKey, message, 31337n);
        expect(verifyEd25519(good, message, honestKey)).toBe(true);
        pairs++;
      }
    }
    expect(pairs).toBe(12);
  });

  it("remembers a mixed-order key apart from the honest key it was made from, in either order", () => {
    // The two differ in many bytes, but the same rule holds: one answer per key.
    for (const [seed, mixedFirst] of [
      [51, true],
      [52, false],
    ] as const) {
      const { scalar: secret, publicKey: honestKey } = expand(new Uint8Array(32).fill(seed));
      const mixed = Point.fromBytes(honestKey, false).add(order8).toBytes();
      const onMixed = craftSignature(secret, mixed, message, 99n);
      const onHonest = craftSignature(secret, honestKey, message, 99n);
      expect(libraryAccepts(onMixed, message, mixed)).toBe(true);
      const checks = [
        () => expect(verifyEd25519(onMixed, message, mixed)).toBe(false),
        () => expect(verifyEd25519(onHonest, message, honestKey)).toBe(true),
      ];
      for (const check of mixedFirst ? checks : checks.toReversed()) check();
      for (const check of checks) check();
    }
  });
});

describe("a check that could not be finished", () => {
  it("leaves no trace: a spent stack never marks an honest key as bad", () => {
    // A key that passes the order check is remembered. A check cut short must not
    // be remembered as a no: when every answer was remembered, one call from a deep
    // stack turned an honest key away until the memory forgot it.
    for (const fill of [77, 78]) {
      const seed = new Uint8Array(32).fill(fill);
      const key = ed25519PublicKey(seed);
      const text = utf8("signed before the key was ever checked");
      const made = signEd25519(text, seed);
      const spent =
        fill === 77
          ? withStackSpent(() => verifyEd25519(made, text, key))
          : withStackSpent(() => isEd25519PublicKey(key));
      // It answers from the moment it can be entered, and never throws.
      expect(spent).toHaveLength(200);
      expect(new Set(spent.map((answer) => typeof answer))).toEqual(new Set(["boolean"]));
      // Whatever it could answer then, it answers rightly now.
      expect(verifyEd25519(made, text, key)).toBe(true);
      expect(isEd25519PublicKey(key)).toBe(true);
    }
  });

  it("works a no out again each time, and gives the same no", () => {
    const { publicKey: honestKey } = expand(new Uint8Array(32).fill(80));
    const mixed = Point.fromBytes(honestKey, false).add(order8).toBytes();
    for (let round = 0; round < 5; round++) {
      expect(isEd25519PublicKey(mixed)).toBe(false);
      expect(isEd25519PublicKey(littleEndian(2n))).toBe(false);
    }
  });
});

describe("the bytes that are verified are the bytes that were checked", () => {
  const privateKey = new Uint8Array(32).fill(9);
  const { scalar, publicKey } = expand(privateKey);
  const message = utf8("one reading");
  const honest = signEd25519(message, privateKey);
  const order8 = smallOrderPoints().find((point) => orderOf(point) === 8)!;
  // The library alone accepts this one: its R has a small-order component.
  const mixedR = craftSignature(scalar, publicKey, message, 2468n, order8);

  it("has a signature only the order check stands against", () => {
    expect(ed25519.verify(mixedR, message, publicKey, { zip215: false })).toBe(true);
    expect(verifyEd25519(mixedR, message, publicKey)).toBe(false);
  });

  it("is not told one thing by subarray and another by the bytes", () => {
    // An array that shows an honest R to whoever asks for a part of it.
    class TwoFaced extends Uint8Array {
      override subarray(begin?: number, end?: number): Uint8Array<ArrayBuffer> {
        return begin === 0 && end === 32
          ? (honest.subarray(0, 32) as Uint8Array<ArrayBuffer>)
          : super.subarray(begin, end);
      }
      override slice(begin?: number, end?: number): Uint8Array<ArrayBuffer> {
        return begin === 0 && end === 32 ? honest.slice(0, 32) : super.slice(begin, end);
      }
    }
    const twoFaced = new TwoFaced(mixedR);
    expect(twoFaced.subarray(0, 32)).toEqual(honest.subarray(0, 32));
    expect(verifyEd25519(twoFaced, message, publicKey)).toBe(false);
    // The same array with an honest signature in it verifies: the class is not what is refused.
    expect(verifyEd25519(new TwoFaced(honest), message, publicKey)).toBe(true);
  });

  it("is not told a length the bytes do not have", () => {
    class Long extends Uint8Array {
      override get length(): number {
        return 64;
      }
    }
    expect(verifyEd25519(new Long(63), message, publicKey)).toBe(false);
    expect(verifyEd25519(new Long(honest.subarray(0, 63)), message, publicKey)).toBe(false);
    class Short extends Uint8Array {
      override get length(): number {
        return 32;
      }
    }
    expect(isEd25519PublicKey(new Short(33))).toBe(false);
    expect(verifyEd25519(honest, message, new Short(Uint8Array.from([...publicKey, 0])))).toBe(
      false,
    );
  });

  it("reads each input once, so a change made afterwards changes nothing", () => {
    // A key whose bytes are swapped for a mixed-order key's as soon as they have been read.
    const mixedKey = Point.fromBytes(publicKey, false).add(order8).toBytes();
    const onMixed = craftSignature(scalar, mixedKey, message, 1357n);
    expect(ed25519.verify(onMixed, message, mixedKey, { zip215: false })).toBe(true);
    let reads = 0;
    class Changing extends Uint8Array {
      override get buffer(): ArrayBuffer {
        reads++;
        return super.buffer;
      }
    }
    const key = new Changing(publicKey);
    expect(verifyEd25519(honest, message, key)).toBe(true);
    key.set(mixedKey);
    expect(verifyEd25519(onMixed, message, key)).toBe(false);
    expect(verifyEd25519(honest, message, key)).toBe(false);
    expect(reads).toBe(0);
  });

  it("answers false, and does not throw, for something that only looks like bytes", () => {
    const boom = () => {
      throw new Error("boom");
    };
    const revoked = Proxy.revocable(new Uint8Array(32), {});
    revoked.revoke();
    for (const fake of [
      new Proxy(Uint8Array.from(publicKey), {}),
      new Proxy(Uint8Array.from(publicKey), { get: boom }),
      revoked.proxy,
      Object.create(Uint8Array.prototype) as Uint8Array,
      Array.from(publicKey) as unknown as Uint8Array,
      new Uint16Array(32) as unknown as Uint8Array,
      publicKey.buffer as unknown as Uint8Array,
    ]) {
      expect(isEd25519PublicKey(fake)).toBe(false);
      expect(verifyEd25519(honest, message, fake)).toBe(false);
      expect(verifyEd25519(fake, message, publicKey)).toBe(false);
      expect(verifyEd25519(honest, fake, publicKey)).toBe(false);
    }
  });
});

describe("the memo that remembers order checks", () => {
  it("computes once per key", () => {
    const cache = new BoundedCache<number>(3);
    let calls = 0;
    const compute = () => ++calls;
    expect(cache.get("a", compute)).toBe(1);
    expect(cache.get("a", compute)).toBe(1);
    expect(cache.get("b", compute)).toBe(2);
    expect(calls).toBe(2);
    expect(cache.size).toBe(2);
    expect(cache.has("a")).toBe(true);
    expect(cache.has("c")).toBe(false);
  });

  it("remembers a result that is false or undefined as well as any other", () => {
    const cache = new BoundedCache<boolean | undefined>(2);
    let calls = 0;
    expect(
      cache.get("no", () => {
        calls++;
        return false;
      }),
    ).toBe(false);
    expect(cache.get("no", () => (calls++, true))).toBe(false);
    expect(cache.get("nothing", () => (calls++, undefined))).toBeUndefined();
    expect(cache.get("nothing", () => (calls++, true))).toBeUndefined();
    expect(calls).toBe(2);
  });

  it("forgets the least recently used when it is full", () => {
    const cache = new BoundedCache<string>(3);
    for (const key of ["a", "b", "c"]) cache.get(key, () => key);
    // Using "a" makes "b" the least recently used.
    cache.get("a", () => "never");
    cache.get("d", () => "d");
    expect(cache.size).toBe(3);
    expect([cache.has("a"), cache.has("b"), cache.has("c"), cache.has("d")]).toEqual([
      true,
      false,
      true,
      true,
    ]);
    cache.get("e", () => "e");
    expect([cache.has("a"), cache.has("c"), cache.has("d"), cache.has("e")]).toEqual([
      true,
      false,
      true,
      true,
    ]);
    expect(cache.size).toBe(3);
  });

  it("holds one entry at least", () => {
    const cache = new BoundedCache<number>(1);
    expect(cache.get("a", () => 1)).toBe(1);
    expect(cache.get("b", () => 2)).toBe(2);
    expect(cache.size).toBe(1);
    expect(cache.has("a")).toBe(false);
    for (const bad of [0, -1, 1.5, Number.NaN, Infinity]) {
      expect(() => new BoundedCache(bad)).toThrow(
        new TypeError("a cache holds at least one entry"),
      );
    }
  });
});
