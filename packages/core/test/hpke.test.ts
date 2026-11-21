// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * HPKE as the protocol uses it (Layer 1, 12.6), against the vectors of
 * RFC 9180, Appendix A.2: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
 * ChaCha20-Poly1305, base mode.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  base64urlToBytes,
  bytesToBase64url,
  bytesToHex,
  hexToBytes,
  HPKE_SUITE,
  hpkeOpen,
  hpkeSeal,
  utf8,
  x25519PublicKey,
} from "../src/index.ts";

/** RFC 9180, A.2.1: the base setup, and its first encryption. */
const RFC = {
  info: hexToBytes("4f6465206f6e2061204772656369616e2055726e"),
  ikmE: hexToBytes("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"),
  pkEm: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
  pkRm: hexToBytes("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
  skRm: hexToBytes("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"),
  pt: hexToBytes("4265617574792069732074727574682c20747275746820626561757479"),
  aad: hexToBytes("436f756e742d30"),
  ct: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28",
};

const sealRfc = () =>
  hpkeSeal({
    recipientPublicKey: RFC.pkRm,
    info: RFC.info,
    aad: RFC.aad,
    plaintext: RFC.pt,
    randomness: RFC.ikmE,
  });

/** The points of small order on Curve25519, as X25519 reads them (RFC 7748, Section 6.1; RFC 9180, 7.1.4). */
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
  "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

describe(`${clause("L1 12.6")} HPKE in the suite a Sealed record names`, () => {
  it("is named as 12.6 names it", () => {
    expect(HPKE_SUITE).toBe("hpke-base-x25519-sha256-chacha20poly1305");
  });

  it("reproduces RFC 9180, A.2.1: the encapsulated key and the first ciphertext", async () => {
    const sealed = await sealRfc();
    if (sealed === undefined) throw new Error("not sealed");
    expect(bytesToHex(sealed.enc)).toBe(RFC.pkEm);
    expect(bytesToHex(sealed.ciphertext)).toBe(RFC.ct);
    // The ciphertext is the plaintext and a tag of 16 bytes.
    expect(sealed.ciphertext).toHaveLength(RFC.pt.length + 16);
  });

  it("opens what the RFC's sender sealed, with the RFC's recipient key", async () => {
    const opened = await hpkeOpen({
      recipientPrivateKey: RFC.skRm,
      enc: hexToBytes(RFC.pkEm),
      info: RFC.info,
      aad: RFC.aad,
      ciphertext: hexToBytes(RFC.ct),
    });
    expect(opened && bytesToHex(opened)).toBe(bytesToHex(RFC.pt));
  });

  it("derives the public key of a private key as the RFC and the curve library do", () => {
    expect(bytesToHex(x25519PublicKey(RFC.skRm))).toBe(bytesToHex(RFC.pkRm));
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (secret) => {
        expect(bytesToHex(x25519PublicKey(secret))).toBe(bytesToHex(x25519.getPublicKey(secret)));
      }),
      { numRuns: 20 },
    );
  });

  it("opens only with the key, the info and the associated data it was sealed with", async () => {
    const sealed = await sealRfc();
    if (sealed === undefined) throw new Error("not sealed");
    const good = {
      recipientPrivateKey: RFC.skRm,
      enc: sealed.enc,
      info: RFC.info,
      aad: RFC.aad,
      ciphertext: sealed.ciphertext,
    };
    expect(await hpkeOpen(good)).toBeDefined();
    const flipped = (bytes: Uint8Array, at: number) => {
      const copy = Uint8Array.from(bytes);
      copy[at] = (copy[at] ?? 0) ^ 1;
      return copy;
    };
    const others = [
      { ...good, recipientPrivateKey: flipped(RFC.skRm, 5) },
      { ...good, info: utf8("another purpose") },
      { ...good, aad: utf8("another recipient") },
      { ...good, enc: flipped(sealed.enc, 0) },
      { ...good, ciphertext: flipped(sealed.ciphertext, 0) },
      { ...good, ciphertext: flipped(sealed.ciphertext, sealed.ciphertext.length - 1) },
      { ...good, ciphertext: sealed.ciphertext.subarray(0, sealed.ciphertext.length - 1) },
      { ...good, ciphertext: new Uint8Array(0) },
      { ...good, enc: sealed.enc.subarray(0, 31) },
      { ...good, enc: new Uint8Array(33) },
    ];
    for (const [index, other] of others.entries()) {
      expect(await hpkeOpen(other), String(index)).toBeUndefined();
    }
  });

  it("seals the same bytes for the same randomness, and others for other randomness", async () => {
    const first = await sealRfc();
    const again = await sealRfc();
    const other = await hpkeSeal({
      recipientPublicKey: RFC.pkRm,
      info: RFC.info,
      aad: RFC.aad,
      plaintext: RFC.pt,
      randomness: new Uint8Array(32).fill(7),
    });
    if (!first || !again || !other) throw new Error("not sealed");
    expect(bytesToHex(again.ciphertext)).toBe(bytesToHex(first.ciphertext));
    expect(bytesToHex(other.enc)).not.toBe(bytesToHex(first.enc));
    expect(bytesToHex(other.ciphertext)).not.toBe(bytesToHex(first.ciphertext));
  });

  it("seals what it was given, whatever the caller does to its bytes meanwhile", async () => {
    const plaintext = Uint8Array.from(RFC.pt);
    const pending = hpkeSeal({
      recipientPublicKey: RFC.pkRm,
      info: RFC.info,
      aad: RFC.aad,
      plaintext,
      randomness: RFC.ikmE,
    });
    plaintext.fill(0);
    const sealed = await pending;
    expect(sealed && bytesToHex(sealed.ciphertext)).toBe(RFC.ct);
  });

  it("round-trips any message to any key", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ maxLength: 300 }),
        fc.uint8Array({ maxLength: 64 }),
        async (secret, randomness, plaintext, aad) => {
          const sealed = await hpkeSeal({
            recipientPublicKey: x25519PublicKey(secret),
            info: RFC.info,
            aad,
            plaintext,
            randomness,
          });
          if (sealed === undefined) throw new Error("not sealed");
          const opened = await hpkeOpen({
            recipientPrivateKey: secret,
            enc: sealed.enc,
            info: RFC.info,
            aad,
            ciphertext: sealed.ciphertext,
          });
          expect(opened && bytesToHex(opened)).toBe(bytesToHex(plaintext));
        },
      ),
      { numRuns: 25 },
    );
  });
});

describe(`${clause("L1 12.6")} keys of small order (RFC 9180, 7.1.4)`, () => {
  it("are sealed to by nobody: every sender would share the same secret with them", async () => {
    for (const point of SMALL_ORDER) {
      const sealed = await hpkeSeal({
        recipientPublicKey: hexToBytes(point),
        info: RFC.info,
        aad: RFC.aad,
        plaintext: RFC.pt,
        randomness: RFC.ikmE,
      });
      expect(sealed, point).toBeUndefined();
    }
  });

  it("open nothing as an encapsulated key", async () => {
    for (const point of SMALL_ORDER) {
      const opened = await hpkeOpen({
        recipientPrivateKey: RFC.skRm,
        enc: hexToBytes(point),
        info: RFC.info,
        aad: RFC.aad,
        ciphertext: hexToBytes(RFC.ct),
      });
      expect(opened, point).toBeUndefined();
    }
  });
});

describe("the arguments of sealing and opening", () => {
  const seal = {
    recipientPublicKey: RFC.pkRm,
    info: RFC.info,
    aad: RFC.aad,
    plaintext: RFC.pt,
    randomness: RFC.ikmE,
  };
  const open = {
    recipientPrivateKey: RFC.skRm,
    enc: hexToBytes(RFC.pkEm),
    info: RFC.info,
    aad: RFC.aad,
    ciphertext: hexToBytes(RFC.ct),
  };

  it("are the caller's where the caller makes them: a wrong one is a TypeError that repeats nothing", async () => {
    const wrong = [
      { ...seal, recipientPublicKey: new Uint8Array(31) },
      { ...seal, recipientPublicKey: "key" },
      { ...seal, randomness: new Uint8Array(31) },
      { ...seal, randomness: new Uint8Array(64) },
      { ...seal, randomness: undefined },
      { ...seal, info: "info" },
      { ...seal, aad: undefined },
      { ...seal, plaintext: "text" },
    ];
    for (const [index, input] of wrong.entries()) {
      await expect(hpkeSeal(input as never), String(index)).rejects.toThrow(TypeError);
    }
    const secret = bytesToHex(RFC.skRm);
    for (const input of [
      { ...open, recipientPrivateKey: RFC.skRm.subarray(0, 31) },
      { ...open, recipientPrivateKey: secret },
      { ...open, info: undefined },
      { ...open, aad: "aad" },
    ]) {
      const failure = await hpkeOpen(input as never).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(TypeError);
      expect((failure as Error).message).not.toContain(secret.slice(0, 16));
    }
    expect(() => x25519PublicKey(new Uint8Array(31))).toThrow(TypeError);
    expect(() => x25519PublicKey(secret as never)).toThrow(TypeError);
  });

  it("are whatever arrived, for an encapsulated key and a ciphertext: opening never throws on them", async () => {
    for (const value of [undefined, null, 7, "enc", [], {}, new Uint8Array(0)]) {
      expect(await hpkeOpen({ ...open, enc: value as never })).toBeUndefined();
      expect(await hpkeOpen({ ...open, ciphertext: value as never })).toBeUndefined();
    }
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ maxLength: 80 }),
        async (enc, ciphertext) => {
          expect(await hpkeOpen({ ...open, enc, ciphertext })).toBeUndefined();
        },
      ),
      { numRuns: 25 },
    );
  });
});

describe("base64url without padding (RFC 4648, Section 5)", () => {
  it("writes bytes and reads them back", () => {
    expect(bytesToBase64url(hexToBytes("fbff"))).toBe("-_8");
    expect(bytesToBase64url(new Uint8Array(0))).toBe("");
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 100 }), (bytes) => {
        const read = base64urlToBytes(bytesToBase64url(bytes));
        expect(read && bytesToHex(read)).toBe(bytesToHex(bytes));
      }),
    );
    expect(() => bytesToBase64url("text" as never)).toThrow(TypeError);
  });

  it("reads one text for each sequence of bytes, and nothing else", () => {
    expect(base64urlToBytes("QQ")).toStrictEqual(hexToBytes("41"));
    for (const text of [
      // Padding, the other alphabet, white space, a length no encoding has.
      "QQ==",
      "+/8",
      "QQ ",
      " QQ",
      "Q",
      "QQQQQ",
      // Bits set that encode nothing: another text for the same byte.
      "QR",
      "QUI=",
      "é",
    ]) {
      expect(base64urlToBytes(text), text).toBeUndefined();
    }
    for (const value of [undefined, null, 7, [], {}]) {
      expect(base64urlToBytes(value)).toBeUndefined();
    }
  });
});
