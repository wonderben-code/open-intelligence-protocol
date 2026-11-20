// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canonicalBytes,
  contentId,
  type JsonObject,
  keyHash,
  mindAddress,
  parseJsonBytes,
  utf8,
} from "@oip/core";
import { draftGenesis } from "@oip/identity";
import { T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  type AllKeys,
  KEY_ROLES,
  keychainLock,
  Keystore,
  KeystoreError,
  type Lock,
  memoryStorage,
  passphrase,
  SCRYPT_MIN_N,
} from "../src/index.ts";
import { memoryKeychain, quick, randomnessOf } from "./helpers.ts";

async function refusal(work: () => unknown): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return error.code;
    throw error;
  }
  throw new Error("nothing was refused");
}

const MIND = mindAddress(contentId({ a: "mind" }));

/** A keystore under a keychain, which costs no key derivation, with a key or two in every role. */
async function filled(name = "backup") {
  const storage = memoryStorage();
  const randomness = randomnessOf(name);
  const lock = keychainLock(memoryKeychain(), "oip-test");
  const keystore = await Keystore.create({ storage, locks: lock, randomness });
  const keys = await all(keystore, lock);
  const first = await keys.control.generate({ label: "first" });
  const next = await keys.control.generate({ label: "next" });
  const operational = await keys.operational.generate({ label: "everyday" });
  const invocation = await keys.invocation.generate();
  const agreement = await keys.agreement.generate();
  return {
    storage,
    randomness,
    lock,
    keystore,
    keys,
    first,
    next,
    operational,
    invocation,
    agreement,
  };
}

async function all(keystore: Keystore, lock: Lock): Promise<AllKeys> {
  return {
    control: await keystore.unlock("control", lock),
    operational: await keystore.unlock("operational", lock),
    invocation: await keystore.unlock("invocation", lock),
    agreement: await keystore.unlock("agreement", lock),
  };
}

const lockAll = (keys: AllKeys): void => {
  for (const role of KEY_ROLES) keys[role].lock();
};

const publicKeys = (keys: AllKeys) =>
  Object.fromEntries(KEY_ROLES.map((role) => [role, keys[role].keys()]));

describe("a backup", () => {
  it("holds the keys of every role, and is restored into a keystore that has them all", async () => {
    const { keystore, keys, operational } = await filled();
    await keystore.setMind(MIND);
    const message = utf8("signed before and after");
    const before = keys.operational.signer(operational.publicKey).sign(message);
    const backup = await keystore.backup(keys, quick("the backup passphrase"));

    const storage = memoryStorage();
    const lock = quick("a new passphrase");
    const restored = await Keystore.restore({
      storage,
      locks: lock,
      backup: backup.bytes,
      backupLock: quick("the backup passphrase"),
      randomness: randomnessOf("restored"),
    });
    expect(restored.id).toBe(keystore.id);
    expect(restored.mind).toBe(MIND);
    const again = await all(restored, lock);
    expect(publicKeys(again)).toStrictEqual(publicKeys(keys));
    for (const role of KEY_ROLES) expect(again[role].generation).toBe(keys[role].generation);
    // The same private keys: Ed25519 gives the same signature.
    expect(again.operational.signer(operational.publicKey).sign(message)).toStrictEqual(before);
    // What was restored is what the backup holds.
    expect(await restored.backupDue()).toStrictEqual([]);
    // And it is found again where it was restored to.
    lockAll(again);
    const reopened = await Keystore.open({ storage });
    expect(reopened.mind).toBe(MIND);
    expect((await reopened.unlock("control", lock)).keys()).toStrictEqual(keys.control.keys());
  });

  it("keeps what a control key and an invocation key remember of what they signed", async () => {
    const { keystore, keys, first, next, invocation } = await filled();
    const genesis = draftGenesis(T(0), {
      kind: "agent",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
    });
    await keys.control.sign(genesis);
    const head = contentId({ an: "event" });
    const as = { publicKey: invocation.publicKey, member: MIND, versionId: `0-${head}` };
    const event = {
      oip: "1",
      type: "Update",
      mind: mindAddress(contentId({ a: "club" })),
      seq: 1,
      prev: head,
      created: T(5),
    } as const;
    await keys.invocation.sign(event, as);
    const backup = await keystore.backup(keys, quick());
    const lock = quick("a new passphrase");
    const restored = await Keystore.restore({
      storage: memoryStorage(),
      locks: lock,
      backup: backup.bytes,
      backupLock: quick(),
      randomness: randomnessOf("restored"),
    });
    const again = await all(restored, lock);
    expect(again.control.pending()).toStrictEqual([genesis]);
    const other = { ...genesis, kind: "service" };
    expect(await refusal(() => again.control.sign(other))).toBe("already-signed");
    expect(await refusal(() => again.invocation.sign({ ...event, created: T(6) }, as))).toBe(
      "already-signed",
    );
  });

  it("is due for each role whose keys have changed since the last one that was saved", async () => {
    const { keystore, keys } = await filled();
    expect(await keystore.backupDue()).toStrictEqual([...KEY_ROLES]);
    const backup = await keystore.backup(keys, quick());
    // Made is not saved: until its owner says so, the backup is owed still.
    expect(await keystore.backupDue()).toStrictEqual([...KEY_ROLES]);
    await backup.saved();
    expect(await keystore.backupDue()).toStrictEqual([]);
    // An identity event makes a control key and destroys one: a backup is owed again.
    await keys.control.generate();
    expect(await keystore.backupDue()).toStrictEqual(["control"]);
    await keys.agreement.generate();
    expect(await keystore.backupDue()).toStrictEqual(["control", "agreement"]);
    await (await keystore.backup(keys, quick())).saved();
    expect(await keystore.backupDue()).toStrictEqual([]);
    // What a key remembers of what it signed changes no set of keys.
    const [first, next] = keys.control.keys();
    await keys.control.sign(
      draftGenesis(T(0), {
        kind: "agent",
        controller: {
          keys: [first?.publicKey ?? ""],
          next: [keyHash(next?.publicKey ?? "")],
        },
      }),
    );
    expect(await keystore.backupDue()).toStrictEqual([]);
  });

  it("opens under its own lock and no other", async () => {
    const { keystore, keys, lock } = await filled();
    const backup = await keystore.backup(keys, quick("the backup passphrase"));
    const restore = (backupLock: Lock, bytes = backup.bytes) =>
      Keystore.restore({ storage: memoryStorage(), locks: quick(), backup: bytes, backupLock });
    expect(await refusal(() => restore(quick("another passphrase")))).toBe("not-opened");
    // The keystore's own lock is not the backup's.
    expect(await refusal(() => restore(lock))).toBe("not-opened");
    // Nor is the backup a role of the keystore, or a role a backup.
    const tampered = parseJsonBytes(backup.bytes);
    if (!tampered.ok) throw new Error("not JSON");
    const asRole = canonicalBytes({ ...(tampered.value as JsonObject), role: "control" });
    expect(await refusal(() => restore(quick("the backup passphrase"), asRole))).toBe("damaged");
    expect(await refusal(() => restore(quick("the backup passphrase"), utf8("{}")))).toBe(
      "damaged",
    );
  });

  it("is not restored over a keystore, and is made of nothing but this keystore's own keys", async () => {
    const { keystore, keys, storage } = await filled();
    const backup = await keystore.backup(keys, quick());
    expect(
      await refusal(() =>
        Keystore.restore({ storage, locks: quick(), backup: backup.bytes, backupLock: quick() }),
      ),
    ).toBe("exists");
    const other = await filled("other");
    expect(
      await refusal(() => keystore.backup({ ...keys, control: other.keys.control }, quick())),
    ).toBe("argument");
    expect(
      await refusal(() =>
        keystore.backup({ ...keys, control: keys.operational as never }, quick()),
      ),
    ).toBe("argument");
    // A backup is sealed under nothing weak.
    const weak = passphrase("1234567", { n: SCRYPT_MIN_N });
    expect(await refusal(() => keystore.backup(keys, weak))).toBe("weak-lock");
    keys.agreement.lock();
    expect(await refusal(() => keystore.backup(keys, quick()))).toBe("locked");
  });
});

describe("the lock of a role", () => {
  it("is changed for another, and the old one opens nothing more", async () => {
    const { keystore, keys, lock, operational } = await filled();
    lockAll(keys);
    const next = quick("a passphrase in place of the keychain");
    await keystore.changeLock("operational", lock, next);
    expect(await refusal(() => keystore.unlock("operational", lock))).toBe("not-opened");
    const opened = await keystore.unlock("operational", next);
    expect(opened.keys()).toStrictEqual([operational]);
    // The keys are the same keys: nothing is owed a backup for a change of lock.
    expect(opened.generation).toBe(1);
    // The other roles are under the lock they had.
    (await keystore.unlock("control", lock)).lock();
    opened.lock();
    // And back again.
    await keystore.changeLock("operational", next, lock);
    expect((await keystore.unlock("operational", lock)).keys()).toStrictEqual([operational]);
  });

  it("is not changed by one who cannot open the role, or while the role is unlocked", async () => {
    const { keystore, keys, lock } = await filled();
    expect(await refusal(() => keystore.changeLock("control", lock, quick()))).toBe("in-use");
    lockAll(keys);
    expect(await refusal(() => keystore.changeLock("control", quick("a guess"), quick()))).toBe(
      "not-opened",
    );
    expect(await refusal(() => keystore.changeLock("owner" as never, lock, quick()))).toBe(
      "argument",
    );
    // A failed change leaves the role free, and under its lock.
    (await keystore.unlock("control", lock)).lock();
  });
});

describe("what a keystore notes of itself", () => {
  it("is the mind its keys are of, once it is told, and nothing that is not an address", async () => {
    const { keystore, storage } = await filled();
    expect(keystore.mind).toBeUndefined();
    expect(await refusal(() => keystore.setMind("did:web:example.com"))).toBe("argument");
    expect(keystore.mind).toBeUndefined();
    await keystore.setMind(MIND);
    expect(keystore.mind).toBe(MIND);
    expect((await Keystore.open({ storage })).mind).toBe(MIND);
  });

  it("is refused if it is not what a keystore wrote", async () => {
    const cases: [string, (meta: Record<string, unknown>) => unknown, string][] = [
      ["a later format", (meta) => ({ ...meta, format: "oip-keystore/2" }), "unsupported"],
      ["another format", (meta) => ({ ...meta, format: "x" }), "damaged"],
      [
        "a mind that is no address",
        (meta) => ({ ...meta, mind: "did:web:example.com" }),
        "damaged",
      ],
      ["a member too many", (meta) => ({ ...meta, extra: 1 }), "damaged"],
      ["no keystore", ({ keystore: _, ...meta }) => meta, "damaged"],
      [
        "a keystore that is no identifier",
        (meta) => ({ ...meta, keystore: "../../etc" }),
        "damaged",
      ],
      ["a keystore that is no string", (meta) => ({ ...meta, keystore: 7 }), "damaged"],
      ["a backup record that is no object", (meta) => ({ ...meta, backedUp: [] }), "damaged"],
      [
        "a backup of a role that is none",
        (meta) => ({ ...meta, backedUp: { owner: 1 } }),
        "damaged",
      ],
      [
        "a generation that is no count",
        (meta) => ({ ...meta, backedUp: { control: -1 } }),
        "damaged",
      ],
    ];
    for (const [what, change, code] of cases) {
      const { storage } = await filled();
      const stored = await storage.get("meta");
      const parsed = parseJsonBytes(stored?.value ?? new Uint8Array());
      if (!parsed.ok) throw new Error("not JSON");
      await storage.put(
        "meta",
        canonicalBytes(change({ ...(parsed.value as JsonObject) })),
        stored?.version,
      );
      expect(await refusal(() => Keystore.open({ storage })), what).toBe(code);
    }
    const { storage } = await filled();
    const stored = await storage.get("meta");
    await storage.put("meta", utf8("not JSON"), stored?.version);
    expect(await refusal(() => Keystore.open({ storage }))).toBe("damaged");
  });

  it("is written by one keystore object at a time", async () => {
    const { keystore, storage } = await filled();
    const other = await Keystore.open({ storage });
    await keystore.setMind(MIND);
    // The other read the note before it changed.
    expect(await refusal(() => other.setMind(MIND))).toBe("changed");
    expect(other.mind).toBeUndefined();
  });
});
