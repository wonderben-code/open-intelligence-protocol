// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The keychain of the machine the tests run on, for real. It is run where
 * there is one that is unlocked, with `OIP_KEYCHAIN=real`: the `keychain` job
 * of CI does so on Linux, macOS and Windows. Everything it keeps is under a
 * service of its own, and is removed again.
 */

import { randomBytes } from "node:crypto";

import { afterAll, describe, expect, it } from "vitest";

import { KEY_ROLES, keychainLock, Keystore, memoryStorage } from "../src/index.ts";
import { systemKeychain } from "../src/node.ts";

const SERVICE = `oip-test-${randomBytes(6).toString("hex")}`;
const kept: string[] = [];

describe.skipIf(process.env["OIP_KEYCHAIN"] !== "real")("the keychain of this machine", () => {
  afterAll(async () => {
    const keychain = await systemKeychain();
    for (const account of kept) await keychain.delete(SERVICE, account);
  });

  it("keeps a secret, gives it back, replaces it and removes it", async () => {
    const keychain = await systemKeychain();
    kept.push("probe");
    expect(await keychain.get(SERVICE, "probe")).toBeUndefined();
    await keychain.set(SERVICE, "probe", "one");
    expect(await keychain.get(SERVICE, "probe")).toBe("one");
    await keychain.set(SERVICE, "probe", "two");
    expect(await keychain.get(SERVICE, "probe")).toBe("two");
    // Another account of the service, and the same account of another service, are other entries.
    expect(await keychain.get(SERVICE, "other")).toBeUndefined();
    expect(await keychain.get(`${SERVICE}-other`, "probe")).toBeUndefined();
    await keychain.delete(SERVICE, "probe");
    expect(await keychain.get(SERVICE, "probe")).toBeUndefined();
    await keychain.delete(SERVICE, "probe");
  });

  it("locks a keystore, which opens again from what the keychain keeps", async () => {
    const lock = keychainLock(await systemKeychain(), SERVICE);
    const storage = memoryStorage();
    const keystore = await Keystore.create({ storage, locks: lock });
    for (const role of KEY_ROLES) kept.push(`${keystore.id}/${role}`);
    const control = await keystore.unlock("control", lock);
    const { publicKey } = await control.generate();
    control.lock();
    // Another process: a keystore opened afresh, and a lock made afresh over the same keychain.
    const again = await Keystore.open({ storage });
    const opened = await again.unlock("control", keychainLock(await systemKeychain(), SERVICE));
    expect(opened.has(publicKey)).toBe(true);
    // Under another service the keychain has nothing for it.
    const elsewhere = keychainLock(await systemKeychain(), `${SERVICE}-other`);
    await expect(again.unlock("operational", elsewhere)).rejects.toMatchObject({
      code: "not-opened",
    });
  });
});
