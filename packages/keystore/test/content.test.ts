// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What is sealed is authenticated, and checked all the same. Each test here
 * seals, under the keystore's own key, something a keystore would not have
 * written, as a later version with a fault or a careless tool might.
 */

import {
  bytesToBase64url,
  canonicalBytes,
  contentId,
  type JsonObject,
  type JsonValue,
  mindAddress,
  parseJsonBytes,
  utf8,
} from "@oip/core";
import { T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  type AllKeys,
  FORMAT,
  KEY_ROLES,
  keychainLock,
  type KeyRole,
  Keystore,
  KeystoreError,
  type KeyStorage,
  type Lock,
  MAX_KEYS,
  MAX_POSITIONS,
  memoryStorage,
  type SealedHeader,
} from "../src/index.ts";
import { openDocument, readSealed, sealDocument } from "../src/seal.ts";
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

const MEMBER = mindAddress(contentId({ a: "member" }));
const CLUB = mindAddress(contentId({ a: "club" }));
const HEAD = contentId({ an: "event" });

async function filled() {
  const storage = memoryStorage();
  const randomness = randomnessOf("content");
  const lock = keychainLock(memoryKeychain(), "oip-test");
  const keystore = await Keystore.create({ storage, locks: lock, randomness });
  const keys: AllKeys = {
    control: await keystore.unlock("control", lock),
    operational: await keystore.unlock("operational", lock),
    invocation: await keystore.unlock("invocation", lock),
    agreement: await keystore.unlock("agreement", lock),
  };
  for (const role of KEY_ROLES) {
    await keys[role].generate({ label: "one" });
    await keys[role].generate();
    keys[role].lock();
  }
  return { storage, randomness, lock, keystore };
}

type Content = { keys: Record<string, JsonValue>[] } & Record<string, JsonValue>;

/** Seals something else in the place of a role's keys, under the key the role is sealed with. */
async function resealed(
  context: { storage: KeyStorage; lock: Lock; keystore: Keystore },
  role: KeyRole,
  change: (content: Content) => unknown,
): Promise<void> {
  const stored = await context.storage.get(role);
  if (stored === undefined) throw new Error("nothing is stored");
  const sealed = readSealed(stored.value);
  const key = await context.lock.key(sealed.header.lock, { keystore: context.keystore.id, role });
  const parsed = parseJsonBytes(openDocument(sealed, key));
  if (!parsed.ok) throw new Error("not JSON");
  const changed = change(structuredClone(parsed.value) as Content);
  const plaintext = changed instanceof Uint8Array ? changed : canonicalBytes(changed);
  const document = sealDocument(sealed.header, key, plaintext, randomnessOf("resealed"));
  await context.storage.put(role, document, stored.version);
}

describe("the keys that are sealed", () => {
  it("are read back as they were written", async () => {
    const context = await filled();
    // Sealed again with nothing changed, they open as before.
    for (const role of KEY_ROLES) {
      await resealed(context, role, (content) => content);
      const keys = await context.keystore.unlock(role, context.lock);
      expect(keys.keys()).toHaveLength(2);
      expect(keys.keys()[0]?.label).toBe("one");
      keys.lock();
    }
  });

  it("are refused if they are not the keys of that role, each with its own public key", async () => {
    const swapped = (content: Content): Content => {
      const [first, second] = content.keys;
      if (first === undefined || second === undefined) throw new Error("no keys");
      return { keys: [{ ...first, publicKey: second["publicKey"] ?? null }, second] };
    };
    const first = (change: (key: Record<string, JsonValue>) => unknown) => (content: Content) => ({
      keys: [change(content.keys[0] ?? {}), ...content.keys.slice(1)],
    });
    const cases: [string, KeyRole, (content: Content) => unknown][] = [
      ["no JSON", "operational", () => utf8("not JSON")],
      ["an array", "operational", () => []],
      ["a member too many", "operational", (content) => ({ ...content, more: true })],
      ["no keys", "operational", () => ({})],
      ["keys that are no list", "operational", () => ({ keys: {} })],
      ["a key that is no object", "operational", () => ({ keys: ["key"] })],
      ["a key with a member too many", "operational", first((key) => ({ ...key, more: 1 }))],
      ["a key without its private half", "operational", first(({ privateKey: _, ...key }) => key)],
      [
        "a private key that is no string",
        "operational",
        first((key) => ({ ...key, privateKey: 7 })),
      ],
      [
        "a private key that is no base64url",
        "operational",
        first((key) => ({ ...key, privateKey: "!" })),
      ],
      [
        "a private key of 31 bytes",
        "operational",
        first((key) => ({ ...key, privateKey: bytesToBase64url(new Uint8Array(31)) })),
      ],
      ["a public key that is another key's", "operational", swapped],
      ["a public key that is another key's", "agreement", swapped],
      ["a public key that is no string", "operational", first((key) => ({ ...key, publicKey: 7 }))],
      [
        "the same key twice",
        "operational",
        (content) => ({ keys: [content.keys[0], content.keys[0]] }),
      ],
      [
        "a label that is too long",
        "operational",
        first((key) => ({ ...key, label: "x".repeat(65) })),
      ],
      ["a label that is no string", "operational", first((key) => ({ ...key, label: 7 }))],
      [
        "an event on a key that is not a control key",
        "operational",
        first((key) => ({ ...key, signing: {} })),
      ],
      ["an event that is no object", "control", first((key) => ({ ...key, signing: "event" }))],
      [
        "positions on a key that is not an invocation key",
        "control",
        first((key) => ({ ...key, signed: {} })),
      ],
      ["positions that are no object", "invocation", first((key) => ({ ...key, signed: [] }))],
      [
        "a position with no event",
        "invocation",
        first((key) => ({ ...key, signed: { [`${CLUB}#1`]: 7 } })),
      ],
      [
        "more positions than a key remembers",
        "invocation",
        first((key) => ({
          ...key,
          signed: Object.fromEntries(
            Array.from({ length: MAX_POSITIONS + 1 }, (_, seq) => [`${CLUB}#${String(seq)}`, HEAD]),
          ),
        })),
      ],
      [
        "more keys than a role holds",
        "operational",
        (content) => ({ keys: Array.from({ length: MAX_KEYS + 1 }, () => content.keys[0]) }),
      ],
    ];
    for (const [what, role, change] of cases) {
      const context = await filled();
      await resealed(context, role, change);
      expect(await refusal(() => context.keystore.unlock(role, context.lock)), what).toBe(
        "damaged",
      );
      // Nothing of it is in use: the role can be asked for again.
      expect(await refusal(() => context.keystore.unlock(role, context.lock)), what).toBe(
        "damaged",
      );
    }
  });

  it("are as many as a role holds, and no more", async () => {
    const context = await filled();
    // A role that is full: 256 keys, here the same two made 128 times over would not be distinct,
    // so the role is filled by making them.
    const operational = await context.keystore.unlock("operational", context.lock);
    for (let made = operational.keys().length; made < MAX_KEYS; made++)
      await operational.generate();
    expect(operational.keys()).toHaveLength(MAX_KEYS);
    expect(await refusal(() => operational.generate())).toBe("argument");
    expect(operational.keys()).toHaveLength(MAX_KEYS);
    // And it is read back whole.
    operational.lock();
    expect((await context.keystore.unlock("operational", context.lock)).keys()).toHaveLength(
      MAX_KEYS,
    );
  });

  it("remember as many positions as an invocation key may have signed for, and no more", async () => {
    const context = await filled();
    await resealed(context, "invocation", (content) => ({
      keys: [
        {
          ...content.keys[0],
          signed: Object.fromEntries(
            Array.from({ length: MAX_POSITIONS }, (_, seq) => [`${CLUB}#${String(seq + 2)}`, HEAD]),
          ),
        },
        ...content.keys.slice(1),
      ],
    }));
    const invocation = await context.keystore.unlock("invocation", context.lock);
    const [full, other] = invocation.keys();
    const event = {
      oip: "1",
      type: "Update",
      mind: CLUB,
      seq: 1,
      prev: HEAD,
      created: T(5),
    } as const;
    const as = (publicKey = "") => ({ publicKey, member: MEMBER, versionId: `0-${HEAD}` });
    // The key that is full signs for no new position, and says so before it signs.
    expect(await refusal(() => invocation.sign(event, as(full?.publicKey)))).toBe("argument");
    // A position it has signed for is refused another event, as ever.
    expect(await refusal(() => invocation.sign({ ...event, seq: 2 }, as(full?.publicKey)))).toBe(
      "already-signed",
    );
    // Another key of the role is not full.
    expect((await invocation.sign(event, as(other?.publicKey))).proof).toHaveLength(1);
  });
});

describe("a sealed document", () => {
  const header: SealedHeader = {
    format: FORMAT,
    keystore: bytesToBase64url(new Uint8Array(16).fill(1)),
    role: "operational",
    generation: 3,
    lock: { kind: "keychain", service: "oip", account: "a/operational" },
  };
  const key = new Uint8Array(32).fill(9);

  it("is canonical JSON with its header in the clear, and opens to what was sealed", () => {
    const plaintext = utf8("what is sealed");
    const document = sealDocument(header, key, plaintext, randomnessOf("seal"));
    const parsed = parseJsonBytes(document);
    expect(parsed.ok && Object.keys(parsed.value as JsonObject).sort()).toStrictEqual([
      "ciphertext",
      "format",
      "generation",
      "keystore",
      "lock",
      "nonce",
      "role",
    ]);
    expect(parsed.ok && canonicalBytes(parsed.value)).toStrictEqual(document);
    const sealed = readSealed(document);
    expect(sealed.header).toStrictEqual(header);
    expect(sealed.nonce).toHaveLength(24);
    expect(sealed.ciphertext).toHaveLength(plaintext.length + 16);
    expect(openDocument(sealed, key)).toStrictEqual(plaintext);
    // A nonce of its own for every sealing: the same thing sealed twice is two documents.
    const again = sealDocument(header, key, plaintext, randomnessOf("another"));
    expect(readSealed(again).nonce).not.toStrictEqual(sealed.nonce);
    expect(readSealed(again).ciphertext).not.toStrictEqual(sealed.ciphertext);
  });

  it("authenticates every member of its header, whatever object carried them", () => {
    const plaintext = utf8("what is sealed");
    // Members a header does not have are not sealed in, and not written.
    const carried = { ...header, more: "ignored", lock: { ...header.lock, more: "ignored" } };
    const sealed = readSealed(sealDocument(carried, key, plaintext, randomnessOf("seal")));
    expect(sealed.header).toStrictEqual(header);
    const changes: SealedHeader[] = [
      { ...header, role: "control" },
      { ...header, generation: 4 },
      { ...header, keystore: bytesToBase64url(new Uint8Array(16).fill(2)) },
      { ...header, lock: { kind: "keychain", service: "oip", account: "b/operational" } },
      { ...header, lock: { kind: "keychain", service: "mail", account: "a/operational" } },
      {
        ...header,
        lock: {
          kind: "scrypt",
          n: 2 ** 14,
          r: 8,
          p: 1,
          salt: bytesToBase64url(new Uint8Array(32)),
        },
      },
    ];
    for (const changed of changes) {
      expect(() => openDocument({ ...sealed, header: changed }, key)).toThrow(KeystoreError);
    }
    expect(openDocument(sealed, key)).toStrictEqual(plaintext);
  });

  it("is sealed and opened with a key of 32 bytes, and no other", () => {
    const plaintext = utf8("what is sealed");
    for (const length of [0, 16, 31, 33, 64]) {
      const wrong = new Uint8Array(length).fill(9);
      expect(() => sealDocument(header, wrong, plaintext, randomnessOf("seal"))).toThrow(
        expect.objectContaining({ code: "argument" }) as Error,
      );
      const sealed = readSealed(sealDocument(header, key, plaintext, randomnessOf("seal")));
      expect(() => openDocument(sealed, wrong)).toThrow(
        expect.objectContaining({ code: "not-opened" }) as Error,
      );
    }
    const sealed = readSealed(sealDocument(header, key, plaintext, randomnessOf("seal")));
    expect(() => openDocument(sealed, new Uint8Array(32).fill(8))).toThrow(
      expect.objectContaining({ code: "not-opened" }) as Error,
    );
  });

  it("is read only if its header is one a keystore writes", () => {
    const written = parseJsonBytes(sealDocument(header, key, utf8("x"), randomnessOf("seal")));
    if (!written.ok) throw new Error("not JSON");
    const document = written.value as JsonObject;
    const reading = (changed: JsonValue): string => {
      try {
        readSealed(canonicalBytes(changed));
      } catch (error) {
        if (error instanceof KeystoreError) return error.code;
        throw error;
      }
      return "read";
    };
    expect(reading(document)).toBe("read");
    const lock = document["lock"] as JsonObject;
    const cases: [string, JsonValue, string][] = [
      ["a keystore that is no identifier", { ...document, keystore: "AAAA" }, "damaged"],
      ["a keystore that is no string", { ...document, keystore: 7 }, "damaged"],
      ["a format that is no string", { ...document, format: 1 }, "damaged"],
      ["a format of version nought", { ...document, format: "oip-keystore/0" }, "damaged"],
      ["a generation that is a string", { ...document, generation: "3" }, "damaged"],
      ["a nonce that is no string", { ...document, nonce: 7 }, "damaged"],
      ["a ciphertext that is no base64url", { ...document, ciphertext: "!" }, "damaged"],
      [
        "a keychain service that is empty",
        { ...document, lock: { ...lock, service: "" } },
        "damaged",
      ],
      [
        "a keychain account that is too long",
        { ...document, lock: { ...lock, account: "a".repeat(129) } },
        "damaged",
      ],
      [
        "a keychain account that is no string",
        { ...document, lock: { ...lock, account: 7 } },
        "damaged",
      ],
      [
        "a keychain lock with a member too many",
        { ...document, lock: { ...lock, more: 1 } },
        "damaged",
      ],
      ["a lock that is no object", { ...document, lock: "keychain" }, "damaged"],
      ["a lock whose kind is no string", { ...document, lock: { kind: 7 } }, "damaged"],
      [
        "a salt that is too long",
        {
          ...document,
          lock: {
            kind: "scrypt",
            n: 2 ** 14,
            r: 8,
            p: 1,
            salt: bytesToBase64url(new Uint8Array(65)),
          },
        },
        "damaged",
      ],
      [
        "a salt that is no string",
        { ...document, lock: { kind: "scrypt", n: 2 ** 14, r: 8, p: 1, salt: 7 } },
        "damaged",
      ],
      [
        "a work factor that is a string",
        {
          ...document,
          lock: {
            kind: "scrypt",
            n: "16384",
            r: 8,
            p: 1,
            salt: bytesToBase64url(new Uint8Array(32)),
          },
        },
        "unsupported",
      ],
    ];
    for (const [what, changed, code] of cases) expect(reading(changed), what).toBe(code);
    // Nothing larger than a keystore writes is read at all.
    expect(() => readSealed(new Uint8Array(4 * 2 ** 20 + 1).fill(0x20))).toThrow(KeystoreError);
  });
});

describe("a backup that is not what a keystore made", () => {
  /** A backup of a keystore, with something else sealed in it under the backup's own key. */
  async function backup(change: (content: Record<string, JsonValue>) => unknown) {
    const context = await filled();
    const keys: AllKeys = {
      control: await context.keystore.unlock("control", context.lock),
      operational: await context.keystore.unlock("operational", context.lock),
      invocation: await context.keystore.unlock("invocation", context.lock),
      agreement: await context.keystore.unlock("agreement", context.lock),
    };
    const lock = quick("the backup passphrase");
    const made = await context.keystore.backup(keys, lock);
    const sealed = readSealed(made.bytes);
    const key = await lock.key(sealed.header.lock, {
      keystore: context.keystore.id,
      role: "backup",
    });
    const parsed = parseJsonBytes(openDocument(sealed, key));
    if (!parsed.ok) throw new Error("not JSON");
    const changed = change(structuredClone(parsed.value) as Record<string, JsonValue>);
    const plaintext = changed instanceof Uint8Array ? changed : canonicalBytes(changed);
    const bytes = sealDocument(sealed.header, key, plaintext, randomnessOf("backup"));
    const storage = memoryStorage();
    const restore = () =>
      Keystore.restore({
        storage,
        locks: keychainLock(memoryKeychain(), "oip-test"),
        backup: bytes,
        backupLock: lock,
      });
    return { restore, storage };
  }

  it("is restored if nothing in it was changed", async () => {
    const { restore, storage } = await backup((content) => content);
    expect((await restore()).id).toHaveLength(22);
    expect(await storage.list()).toHaveLength(5);
  });

  it("is refused, and nothing is stored", async () => {
    const roles =
      (change: (roles: Record<string, JsonValue>) => unknown) =>
      (content: Record<string, JsonValue>) => ({
        ...content,
        roles: change(content["roles"] as Record<string, JsonValue>),
      });
    const cases: [string, (content: Record<string, JsonValue>) => unknown][] = [
      ["no JSON", () => utf8("not JSON")],
      ["no roles", ({ roles: _, ...content }) => content],
      ["a member too many", (content) => ({ ...content, more: 1 })],
      ["a mind that is no address", (content) => ({ ...content, mind: "did:web:example.com" })],
      ["a role too few", roles(({ control: _, ...others }) => others)],
      ["a role too many", roles((all) => ({ ...all, owner: all["control"] ?? null }))],
      ["a role that is no object", roles((all) => ({ ...all, control: "keys" }))],
      ["a role without its generation", roles((all) => ({ ...all, control: { keys: [] } }))],
      [
        "a generation that is no count",
        roles((all) => ({ ...all, control: { generation: -1, keys: [] } })),
      ],
      ["a role without its keys", roles((all) => ({ ...all, control: { generation: 1 } }))],
      [
        "keys that are not that role's",
        roles((all) => ({ ...all, agreement: all["control"] ?? null })),
      ],
    ];
    for (const [what, change] of cases) {
      const { restore, storage } = await backup(change);
      expect(await refusal(restore), what).toBe("damaged");
      expect(await storage.list(), what).toStrictEqual([]);
    }
  });
});
