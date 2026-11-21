// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { scryptSync } from "node:crypto";

import { base64urlToBytes, bytesToBase64url } from "@oip/core";
import { describe, expect, it } from "vitest";

import {
  KEY_LENGTH,
  keychainLock,
  Keystore,
  KeystoreError,
  type LockHeader,
  memoryStorage,
  passphrase,
  SALT_LENGTH,
  SCRYPT_MAX_N,
  SCRYPT_MIN_N,
  SCRYPT_N,
  type ScryptHeader,
  systemRandomness,
} from "../src/index.ts";
import { hex, memoryKeychain, quick, randomnessOf } from "./helpers.ts";

async function refusal(work: () => unknown): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return error.code;
    throw error;
  }
  throw new Error("nothing was refused");
}

const CONTEXT = { keystore: "AAAAAAAAAAAAAAAAAAAAAA", role: "operational" };

describe("a passphrase", () => {
  it("is stretched with scrypt, under a salt of its own for each thing sealed", async () => {
    const randomness = randomnessOf("lock");
    const lock = quick("correct horse battery staple");
    const one = await lock.fresh(CONTEXT, randomness);
    const two = await lock.fresh(CONTEXT, randomness);
    const header = one.header as ScryptHeader;
    expect(header).toStrictEqual({
      kind: "scrypt",
      n: SCRYPT_MIN_N,
      r: 8,
      p: 1,
      salt: header.salt,
    });
    expect(base64urlToBytes(header.salt)).toHaveLength(SALT_LENGTH);
    expect(one.key).toHaveLength(KEY_LENGTH);
    expect((two.header as ScryptHeader).salt).not.toBe(header.salt);
    expect(hex(two.key)).not.toBe(hex(one.key));
    // The key is the one scrypt gives for that passphrase and that salt, as OpenSSL works it out.
    const expected = scryptSync(
      Buffer.from("correct horse battery staple", "utf8"),
      base64urlToBytes(header.salt) ?? new Uint8Array(),
      KEY_LENGTH,
      { N: SCRYPT_MIN_N, r: 8, p: 1, maxmem: 2 ** 26 },
    );
    expect(hex(one.key)).toBe(hex(expected));
    // And it is found again from the header alone.
    expect(hex(await quick("correct horse battery staple").key(header, CONTEXT))).toBe(
      hex(one.key),
    );
    expect(hex(await quick("correct horse battery stapler").key(header, CONTEXT))).not.toBe(
      hex(one.key),
    );
  });

  it("is the same passphrase however its characters were composed", async () => {
    const randomness = randomnessOf("lock");
    // "é" as one code point, and as "e" with a combining accent; a ligature, and its letters.
    const composed = quick("café ﬁn de siècle");
    const decomposed = quick("café fin de siècle");
    const { header, key } = await composed.fresh(CONTEXT, randomness);
    expect(hex(await decomposed.key(header, CONTEXT))).toBe(hex(key));
    // Case and spaces are part of it.
    expect(hex(await quick("Café ﬁn de siècle").key(header, CONTEXT))).not.toBe(hex(key));
  });

  it("works as hard as it is told for what it seals, and as hard as a header says to open", async () => {
    expect(SCRYPT_N).toBe(2 ** 17);
    expect(SCRYPT_MIN_N).toBe(2 ** 14);
    expect(SCRYPT_MAX_N).toBe(2 ** 20);
    const randomness = randomnessOf("lock");
    const harder = passphrase("correct horse battery staple", { n: 2 ** 15 });
    const { header, key } = await harder.fresh(CONTEXT, randomness);
    expect((header as ScryptHeader).n).toBe(2 ** 15);
    // A lock made for another work factor opens it with the header's.
    expect(hex(await quick("correct horse battery staple").key(header, CONTEXT))).toBe(hex(key));
    // The default is the one of ADR-0017. It is not run here: it takes 128 MiB and most of a second.
    const usual = passphrase("correct horse battery staple");
    expect(hex(await usual.key(header, CONTEXT))).toBe(hex(key));
  });

  it("opens nothing that a keychain sealed", async () => {
    const keychain: LockHeader = { kind: "keychain", service: "oip", account: "a/b" };
    expect(await refusal(() => quick().key(keychain, CONTEXT))).toBe("not-opened");
    const unsalted: LockHeader = {
      kind: "scrypt",
      n: SCRYPT_MIN_N,
      r: 8,
      p: 1,
      salt: "not base64url!",
    };
    expect(await refusal(() => quick().key(unsalted, CONTEXT))).toBe("damaged");
  });
});

describe("a lock that is the keychain", () => {
  it("keeps a random key for each role of each keystore, under the keystore's own account", async () => {
    const keychain = memoryKeychain();
    const lock = keychainLock(keychain, "oip");
    const randomness = randomnessOf("keychain");
    const one = await lock.fresh(CONTEXT, randomness);
    const other = await lock.fresh({ ...CONTEXT, role: "control" }, randomness);
    expect(one.header).toStrictEqual({
      kind: "keychain",
      service: "oip",
      account: `${CONTEXT.keystore}/operational`,
    });
    expect(one.key).toHaveLength(KEY_LENGTH);
    expect(hex(other.key)).not.toBe(hex(one.key));
    expect([...keychain.kept.keys()].sort()).toStrictEqual([
      `oip\n${CONTEXT.keystore}/control`,
      `oip\n${CONTEXT.keystore}/operational`,
    ]);
    expect(keychain.kept.get(`oip\n${CONTEXT.keystore}/operational`)).toBe(
      bytesToBase64url(one.key),
    );
    expect(hex(await lock.key(one.header, CONTEXT))).toBe(hex(one.key));
    // Sealing afresh replaces the key.
    const again = await lock.fresh(CONTEXT, randomness);
    expect(hex(again.key)).not.toBe(hex(one.key));
    expect(hex(await lock.key(one.header, CONTEXT))).toBe(hex(again.key));
  });

  it("is not sent by a stored header to another secret than its own", async () => {
    const keychain = memoryKeychain();
    const lock = keychainLock(keychain, "oip");
    const { header } = await lock.fresh(CONTEXT, randomnessOf("keychain"));
    // Something else the keychain holds, which a changed header points at.
    await keychain.set("mail", "password", bytesToBase64url(new Uint8Array(32).fill(7)));
    await keychain.set("oip", "another/operational", bytesToBase64url(new Uint8Array(32).fill(8)));
    const elsewhere: LockHeader[] = [
      { kind: "keychain", service: "mail", account: "password" },
      { kind: "keychain", service: "oip", account: "another/operational" },
      { kind: "keychain", service: "oip", account: `${CONTEXT.keystore}/control` },
      { kind: "scrypt", n: SCRYPT_MIN_N, r: 8, p: 1, salt: bytesToBase64url(new Uint8Array(32)) },
    ];
    for (const changed of elsewhere) {
      expect(await refusal(() => lock.key(changed, CONTEXT)), JSON.stringify(changed)).toBe(
        "not-opened",
      );
    }
    // Asked for another role, or by a lock of another service, the same header opens nothing.
    expect(await refusal(() => lock.key(header, { ...CONTEXT, role: "control" }))).toBe(
      "not-opened",
    );
    expect(await refusal(() => keychainLock(keychain, "other").key(header, CONTEXT))).toBe(
      "not-opened",
    );
  });

  it("opens nothing where the keychain has no key, or something that is none", async () => {
    const keychain = memoryKeychain();
    const lock = keychainLock(keychain, "oip");
    const { header } = await lock.fresh(CONTEXT, randomnessOf("keychain"));
    const account = `${CONTEXT.keystore}/operational`;
    for (const kept of [
      "",
      "not base64url!",
      bytesToBase64url(new Uint8Array(31)),
      bytesToBase64url(new Uint8Array(33)),
    ]) {
      await keychain.set("oip", account, kept);
      expect(await refusal(() => lock.key(header, CONTEXT)), kept).toBe("not-opened");
    }
    await keychain.delete("oip", account);
    expect(await refusal(() => lock.key(header, CONTEXT))).toBe("not-opened");
    expect(() => keychainLock(keychain, "")).toThrow(KeystoreError);
    expect(() => keychainLock(keychain, "s".repeat(129))).toThrow(KeystoreError);
    expect(() => keychainLock(keychain, 7 as never)).toThrow(KeystoreError);
  });

  it("seals a keystore whose roles open with what the keychain holds, and not without it", async () => {
    const keychain = memoryKeychain();
    const lock = keychainLock(keychain, "oip");
    const storage = memoryStorage();
    const keystore = await Keystore.create({ storage, locks: lock, randomness: randomnessOf("k") });
    expect(keychain.kept.size).toBe(4);
    const operational = await keystore.unlock("operational", lock);
    const { publicKey } = await operational.generate();
    operational.lock();
    expect((await keystore.unlock("operational", lock)).has(publicKey)).toBe(true);
    // Another machine's keychain has nothing for it.
    const elsewhere = keychainLock(memoryKeychain(), "oip");
    expect(await refusal(() => keystore.unlock("control", elsewhere))).toBe("not-opened");
    expect(await refusal(() => keystore.unlock("control", quick()))).toBe("not-opened");
  });
});

describe("the source of randomness", () => {
  it("is the platform's, unless a keystore is given another", () => {
    const one = systemRandomness.bytes(32);
    const two = systemRandomness.bytes(32);
    expect(one).toHaveLength(32);
    expect(hex(one)).not.toBe(hex(two));
    expect(systemRandomness.bytes(0)).toHaveLength(0);
  });

  it("is not believed when it gives something other than what was asked", async () => {
    const sources = [
      { bytes: () => new Uint8Array(8) },
      { bytes: (length: number) => new Uint8Array(length + 1) },
      { bytes: (length: number) => Array.from({ length }, () => 0) as unknown as Uint8Array },
      { bytes: () => undefined as unknown as Uint8Array },
    ];
    for (const randomness of sources) {
      expect(
        await refusal(() =>
          Keystore.create({ storage: memoryStorage(), locks: quick(), randomness }),
        ),
      ).toBe("argument");
    }
  });

  it("is copied from: a source that hands out one array for every draw gives no two things the same bytes", async () => {
    const shared = new Uint8Array(64);
    let draws = 0;
    const randomness = {
      bytes: (length: number): Uint8Array => {
        shared.fill(++draws);
        return shared.subarray(0, length);
      },
    };
    const lock = keychainLock(memoryKeychain(), "oip");
    const keystore = await Keystore.create({ storage: memoryStorage(), locks: lock, randomness });
    const operational = await keystore.unlock("operational", lock);
    const first = await operational.generate();
    const second = await operational.generate();
    expect(second.publicKey).not.toBe(first.publicKey);
    expect(operational.keys()).toStrictEqual([first, second]);
  });
});
