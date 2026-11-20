// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * ADR-0002, item 2: every library is checked against published vectors
 * before it is trusted. Here: scrypt of `@noble/hashes` against RFC 7914,
 * Section 12, and against the scrypt of OpenSSL; and XChaCha20-Poly1305 of
 * `@noble/ciphers` against draft-irtf-cfrg-xchacha-03, Appendix A.3.1.
 */

import { scryptSync } from "node:crypto";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { scrypt, scryptAsync } from "@noble/hashes/scrypt.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { hex, unhex } from "./helpers.ts";

describe("scrypt of @noble/hashes", () => {
  const RFC_7914 = [
    {
      password: "",
      salt: "",
      N: 16,
      r: 1,
      p: 1,
      key: "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    },
    {
      password: "password",
      salt: "NaCl",
      N: 1024,
      r: 8,
      p: 16,
      key: "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    },
    {
      password: "pleaseletmein",
      salt: "SodiumChloride",
      N: 16384,
      r: 8,
      p: 1,
      key: "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
    },
  ];

  it("gives the keys of RFC 7914, Section 12", async () => {
    for (const { password, salt, key, ...work } of RFC_7914) {
      expect(hex(scrypt(password, salt, { ...work, dkLen: 64 }))).toBe(key);
      expect(hex(await scryptAsync(password, salt, { ...work, dkLen: 64 }))).toBe(key);
    }
  });

  it("gives the keys the scrypt of OpenSSL gives, with the parameters the keystore uses", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 64 }),
        fc.uint8Array({ minLength: 16, maxLength: 64 }),
        async (password, salt) => {
          const normalised = password.normalize("NFKC");
          const ours = await scryptAsync(new TextEncoder().encode(normalised), salt, {
            N: 2 ** 14,
            r: 8,
            p: 1,
            dkLen: 32,
          });
          const theirs = scryptSync(Buffer.from(normalised, "utf8"), salt, 32, {
            N: 2 ** 14,
            r: 8,
            p: 1,
            maxmem: 2 ** 26,
          });
          expect(hex(ours)).toBe(hex(theirs));
        },
      ),
      { numRuns: 12 },
    );
  });
});

describe("XChaCha20-Poly1305 of @noble/ciphers", () => {
  // draft-irtf-cfrg-xchacha-03, Appendix A.3.1.
  const key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
  const nonce = unhex("404142434445464748494a4b4c4d4e4f5051525354555657");
  const aad = unhex("50515253c0c1c2c3c4c5c6c7");
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const sealed =
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39" +
    "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
    "21f9664c97637da9768812f615c68b13b52e" +
    "c0875924c1c7987947deafd8780acf49";

  it("gives the ciphertext and tag of the draft's vector, and opens it", () => {
    expect(hex(xchacha20poly1305(key, nonce, aad).encrypt(plaintext))).toBe(sealed);
    expect(hex(xchacha20poly1305(key, nonce, aad).decrypt(unhex(sealed)))).toBe(hex(plaintext));
  });

  it("opens nothing that was changed: a bit of the ciphertext, the tag, the nonce, the data or the key", () => {
    const flipped = (bytes: Uint8Array, at: number) => {
      const copy = bytes.slice();
      copy[at] = (copy[at] ?? 0) ^ 1;
      return copy;
    };
    const whole = unhex(sealed);
    expect(() => xchacha20poly1305(key, nonce, aad).decrypt(flipped(whole, 0))).toThrow();
    expect(() =>
      xchacha20poly1305(key, nonce, aad).decrypt(flipped(whole, whole.length - 1)),
    ).toThrow();
    expect(() => xchacha20poly1305(key, flipped(nonce, 23), aad).decrypt(whole)).toThrow();
    expect(() => xchacha20poly1305(key, nonce, flipped(aad, 0)).decrypt(whole)).toThrow();
    expect(() => xchacha20poly1305(flipped(key, 31), nonce, aad).decrypt(whole)).toThrow();
    expect(() => xchacha20poly1305(key, nonce, aad).decrypt(whole.subarray(0, 15))).toThrow();
  });
});
