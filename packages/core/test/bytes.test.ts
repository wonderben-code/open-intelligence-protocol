// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  bytesEqual,
  bytesToHex,
  codePointLength,
  decodeUtf8,
  hexToBytes,
  isWellFormed,
  signerFromPrivateKey,
  utf8,
} from "../src/index.ts";
import { keys } from "./vectors.ts";

describe(`${clause("core 1.1")} valid Unicode`, () => {
  it("tells a string with an unpaired surrogate from one without", () => {
    for (const good of [
      "",
      "a",
      "é€",
      "😀",
      "\ud83d\ude00",
      "a\u{10ffff}b",
      "\ud7ff\ue000",
      "\uffff",
    ]) {
      expect(isWellFormed(good), JSON.stringify(good)).toBe(true);
    }
    for (const bad of [
      "\ud800",
      "\udc00",
      "a\ud800",
      "\udfffa",
      "\ud800\ud800",
      "\udc00\ud800",
      "\ud83d\u0041",
      "😀\ud83d",
      "\udbff",
      "\ud800a\udc00",
    ]) {
      expect(isWellFormed(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  it("agrees with the platform on any string", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), (text) => {
        expect(isWellFormed(text)).toBe(text.isWellFormed());
      }),
      { numRuns: 3000 },
    );
  });

  it("encodes valid Unicode as UTF-8 and refuses anything else", () => {
    expect([...utf8("aé€😀")]).toEqual([
      0x61, 0xc3, 0xa9, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80,
    ]);
    expect(utf8("")).toHaveLength(0);
    // An encoder would write U+FFFD for an unpaired surrogate: two different strings, one encoding.
    for (const bad of ["\ud800", "a\udc00b"]) {
      expect(() => utf8(bad)).toThrow(
        new TypeError("the string has an unpaired surrogate, so it has no UTF-8 encoding"),
      );
    }
  });

  it("decodes UTF-8 strictly", () => {
    expect(decodeUtf8(Uint8Array.of(0x61, 0xc3, 0xa9, 0xf0, 0x9f, 0x98, 0x80))).toBe("aé😀");
    expect(decodeUtf8(new Uint8Array())).toBe("");
    // A byte order mark is kept, not skipped.
    expect(decodeUtf8(Uint8Array.of(0xef, 0xbb, 0xbf, 0x61))).toBe("\ufeffa");
    for (const bad of [
      [0xff],
      [0xc3],
      [0xc0, 0xaf],
      [0xed, 0xa0, 0x80],
      [0xf4, 0x90, 0x80, 0x80],
      [0x80],
    ]) {
      expect(decodeUtf8(Uint8Array.from(bad)), String(bad)).toBeUndefined();
    }
  });

  it("round-trips any valid string", () => {
    fc.assert(
      fc.property(
        fc.string({ unit: "binary" }).filter((text) => text.isWellFormed()),
        (text) => {
          expect(decodeUtf8(utf8(text))).toBe(text);
          expect([...utf8(text)]).toEqual([...new TextEncoder().encode(text)]);
        },
      ),
      { numRuns: 1000 },
    );
  });
});

describe(`${clause("core 1.8")} string lengths count code points`, () => {
  it("counts a character outside the basic plane once", () => {
    expect(codePointLength("")).toBe(0);
    expect(codePointLength("abc")).toBe(3);
    expect(codePointLength("é")).toBe(1);
    expect(codePointLength("e\u0301")).toBe(2);
    expect(codePointLength("😀")).toBe(1);
    expect("😀").toHaveLength(2);
    expect(codePointLength("a😀b😀")).toBe(4);
    expect(codePointLength("\u{10ffff}\u{10000}")).toBe(2);
    expect(codePointLength("👨‍👩‍👧")).toBe(5);
  });

  it("counts an unpaired surrogate as one, as the platform does", () => {
    expect(codePointLength("\ud800")).toBe(1);
    expect(codePointLength("\udc00\ud800")).toBe(2);
    expect(codePointLength("\ud800\ud800\udc00")).toBe(2);
    expect(codePointLength("\ud800a")).toBe(2);
  });

  it("agrees with the platform on any string", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), (text) => {
        expect(codePointLength(text)).toBe(Array.from(text).length);
      }),
      { numRuns: 3000 },
    );
  });
});

describe("bytes", () => {
  it("compares byte strings", () => {
    expect(bytesEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3))).toBe(true);
    expect(bytesEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    expect(bytesEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4))).toBe(false);
    expect(bytesEqual(Uint8Array.of(0, 2, 3), Uint8Array.of(1, 2, 3))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2))).toBe(false);
    expect(bytesEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2, 3))).toBe(false);
    expect(bytesEqual(new Uint8Array(), Uint8Array.of(0))).toBe(false);
  });

  it("writes and reads hex", () => {
    expect(bytesToHex(Uint8Array.of(0, 1, 0xab, 0xff))).toBe("0001abff");
    expect([...hexToBytes("0001abff")]).toEqual([0, 1, 0xab, 0xff]);
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), (bytes) => {
        expect(bytesEqual(hexToBytes(bytesToHex(bytes)), bytes)).toBe(true);
      }),
    );
  });
});

describe("a signer that holds its key in memory", () => {
  const key = keys["amina-phone"];
  const privateKey = hexToBytes(key?.seed_hex ?? "");

  it("names its public key and signs with the private one", async () => {
    const signer = signerFromPrivateKey(privateKey);
    expect(signer.publicKey).toBe(key?.multikey);
    const signature = await signer.sign(utf8("message"));
    expect(signature).toHaveLength(64);
    expect(await signer.sign(utf8("message"))).toEqual(signature);
  });

  it("shows nothing of the private key", () => {
    const signer = signerFromPrivateKey(privateKey);
    const secret = key?.seed_hex ?? "";
    expect(Object.keys(signer)).toEqual(["publicKey", "sign"]);
    expect(Object.isFrozen(signer)).toBe(true);
    for (const shown of [JSON.stringify(signer), Object.values(signer).map(String).join(" ")]) {
      expect(shown).not.toContain(secret);
      expect(shown).not.toContain(Buffer.from(privateKey).toString("base64"));
    }
    expect(JSON.stringify(signer)).toBe(JSON.stringify({ publicKey: key?.multikey }));
  });

  it("keeps working when the caller wipes its own copy of the key", async () => {
    const mine = Uint8Array.from(privateKey);
    const signer = signerFromPrivateKey(mine);
    const before = await signer.sign(utf8("message"));
    mine.fill(0);
    expect(await signer.sign(utf8("message"))).toEqual(before);
  });

  it("refuses a private key of the wrong length without repeating it", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(64), "key", null]) {
      expect(() => signerFromPrivateKey(bad as Uint8Array)).toThrow(
        new TypeError("an Ed25519 private key is 32 bytes"),
      );
    }
  });
});
