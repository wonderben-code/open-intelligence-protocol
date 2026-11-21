// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  bytesToBase64url,
  canonicalBytes,
  contentId,
  createProofSync,
  decodeX25519Multikey,
  formatKeyRef,
  formatVersionId,
  hpkeSeal,
  isEd25519Multikey,
  isX25519Multikey,
  keyHash,
  mindAddress,
  parseJsonBytes,
  utf8,
  verifyEd25519,
  decodeEd25519Multikey,
} from "@oip/core";
import { draftGenesis, draftUpdate, FirstSeen, witnessLog } from "@oip/identity";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  type AllKeys,
  KEY_ROLES,
  keychainLock,
  type KeyRole,
  Keystore,
  KeystoreError,
  type KeyStorage,
  type Lock,
  memoryStorage,
  OperationalKeys,
  passphrase,
  SCRYPT_MIN_N,
} from "../src/index.ts";
import { handleOver } from "../src/keys.ts";
import { memoryKeychain, quick, randomnessOf } from "./helpers.ts";

/** Addresses and a content ID that are well formed, and of nothing. */
const MEMBER = mindAddress(contentId({ a: "member" }));
const OTHER = mindAddress(contentId({ an: "other" }));
const CLUB = mindAddress(contentId({ a: "club" }));
const HEAD = contentId({ an: "event" });

/** What a call is refused with. */
async function refusal(work: () => unknown): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return error.code;
    throw error;
  }
  throw new Error("nothing was refused");
}

/**
 * A keystore in memory, under one lock for every role. The lock is a keychain
 * that is a map, unless a test is about passphrases: it costs no key derivation.
 */
async function made(
  name = "keystore",
  storage: KeyStorage = memoryStorage(),
  lock: Lock = keychainLock(memoryKeychain(), "oip-test"),
) {
  const randomness = randomnessOf(name);
  const keystore = await Keystore.create({ storage, locks: lock, randomness });
  return { keystore, storage, lock, randomness };
}

/** Every role of a keystore, unlocked. */
async function all(keystore: Keystore, lock: Lock): Promise<AllKeys> {
  return {
    control: await keystore.unlock("control", lock),
    operational: await keystore.unlock("operational", lock),
    invocation: await keystore.unlock("invocation", lock),
    agreement: await keystore.unlock("agreement", lock),
  };
}

/** The genesis of a mind whose keys are all in a keystore, not yet signed, and the keys it names. */
async function founding(keys: AllKeys, seconds = 0) {
  const first = await keys.control.generate({ label: "first" });
  const next = await keys.control.generate({ label: "next" });
  const operational = await keys.operational.generate({ label: "everyday" });
  const invocation = await keys.invocation.generate();
  const agreement = await keys.agreement.generate();
  const genesis = draftGenesis(T(seconds), {
    kind: "agent",
    controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
    keys: [{ key: operational.publicKey, label: "everyday" }],
    invocation: [{ key: invocation.publicKey }],
    agreement: [{ key: agreement.publicKey }],
  });
  return { genesis, first, next, operational, invocation, agreement };
}

/** How many events of a log verify, for a verifier that sees them now. */
function verified(events: readonly object[]): number {
  const replayed = witnessLog(events, at(1000), new FirstSeen());
  return replayed.log?.entries.length ?? 0;
}

describe("a keystore", () => {
  it("is made with four roles and no keys, and is found again where it was stored", async () => {
    const { keystore, storage, lock } = await made();
    expect((await storage.list()).sort()).toStrictEqual(
      ["agreement", "control", "invocation", "meta", "operational"].sort(),
    );
    for (const role of KEY_ROLES) {
      const keys = await keystore.unlock(role, lock);
      expect(keys.role).toBe(role);
      expect(keys.keys()).toStrictEqual([]);
      expect(keys.generation).toBe(0);
      keys.lock();
    }
    const again = await Keystore.open({ storage });
    expect(again.id).toBe(keystore.id);
    expect(again.mind).toBeUndefined();
    expect(await again.backupDue()).toStrictEqual([]);
  });

  it("is not made where one is stored already, in whole or in part", async () => {
    const { storage } = await made();
    expect(await refusal(() => Keystore.create({ storage, locks: quick() }))).toBe("exists");
    // What an interrupted creation left behind is not written over either.
    const partial = memoryStorage();
    await partial.put("control", new Uint8Array([1]), undefined);
    expect(await refusal(() => Keystore.create({ storage: partial, locks: quick() }))).toBe(
      "exists",
    );
    expect(await refusal(() => Keystore.open({ storage: partial }))).toBe("not-found");
    expect(await refusal(() => Keystore.open({ storage: memoryStorage() }))).toBe("not-found");
  });

  it("is sealed under nothing weak: a passphrase has eight characters", async () => {
    const storage = memoryStorage();
    const weak = passphrase("1234567", { n: SCRYPT_MIN_N });
    expect(await refusal(() => Keystore.create({ storage, locks: weak }))).toBe("weak-lock");
    // Counted as a person counts: seven letters with accents are seven.
    const accented = passphrase("é".repeat(7), { n: SCRYPT_MIN_N });
    expect(
      await refusal(() => Keystore.create({ storage: memoryStorage(), locks: accented })),
    ).toBe("weak-lock");
    expect(() => passphrase("")).toThrow(KeystoreError);
    expect(() => passphrase("long enough", { n: 1000 })).toThrow(KeystoreError);
    expect(() => passphrase("long enough", { n: 2 ** 21 })).toThrow(KeystoreError);
    expect(() => passphrase("long enough", { n: 2 ** 13 })).toThrow(KeystoreError);
  });

  it("makes keys of the kind its role has, and gives out their public halves only", async () => {
    const { keystore, lock, storage, randomness } = await made();
    const keys = await all(keystore, lock);
    const drawnBefore = randomness.drawn;
    for (const role of ["control", "operational", "invocation"] as const) {
      const key = await keys[role].generate({ label: `a ${role} key` });
      expect(isEd25519Multikey(key.publicKey)).toBe(true);
      expect(key).toStrictEqual({ publicKey: key.publicKey, label: `a ${role} key` });
      expect(keys[role].has(key.publicKey)).toBe(true);
      expect(keys[role].keys()).toStrictEqual([key]);
      expect(keys[role].generation).toBe(1);
    }
    const agreed = await keys.agreement.generate();
    expect(isX25519Multikey(agreed.publicKey)).toBe(true);
    expect(agreed).toStrictEqual({ publicKey: agreed.publicKey });
    // Nothing a handle answers with, and nothing stored, holds a private key in the clear.
    // Every draw since the keystore was made is a private key or a nonce: here they are again.
    const secrets: string[] = [];
    for (let index = drawnBefore; index < randomness.drawn; index++) {
      const again = randomnessOf("keystore");
      again.drawn = index;
      secrets.push(bytesToBase64url(again.bytes(32)));
    }
    expect(secrets).toHaveLength(8);
    const said = JSON.stringify(KEY_ROLES.map((role) => keys[role].keys()));
    const stored = (
      await Promise.all(
        (await storage.list()).map(async (name) => (await storage.get(name))?.value),
      )
    )
      .map((value) => new TextDecoder().decode(value))
      .join("\n");
    for (const secret of secrets) {
      expect(said.includes(secret)).toBe(false);
      expect(stored.includes(secret)).toBe(false);
    }
    await expect(keys.operational.generate({ label: "x".repeat(65) })).rejects.toMatchObject({
      code: "argument",
    });
  });

  it("signs with an operational key what its public key verifies", async () => {
    const { keystore, lock } = await made();
    const operational = await keystore.unlock("operational", lock);
    const { publicKey } = await operational.generate();
    const signer = operational.signer(publicKey);
    expect(signer.publicKey).toBe(publicKey);
    const message = utf8("Translate the lease.");
    const raw = decodeEd25519Multikey(publicKey);
    expect(raw.ok && verifyEd25519(signer.sign(message), message, raw.value)).toBe(true);
    // A record signed with it carries a proof by that key.
    const record = {
      oip: "1",
      type: "Intent",
      author: MEMBER,
      created: T(1),
      want: "A translation.",
    };
    const proof = createProofSync(
      record,
      {
        verificationMethod: formatKeyRef(MEMBER, formatVersionId(0, HEAD), publicKey),
        created: T(1),
      },
      signer,
    );
    expect(proof.verificationMethod.endsWith(publicKey)).toBe(true);
    expect(await refusal(() => operational.signer("z6Mkunknown"))).toBe("not-found");
  });

  it("opens with an agreement key what was sealed to it, and nothing else", async () => {
    const { keystore, lock } = await made();
    const agreement = await keystore.unlock("agreement", lock);
    const mine = await agreement.generate();
    const other = await agreement.generate();
    const to = decodeX25519Multikey(mine.publicKey);
    if (!to.ok) throw new Error("not a key");
    const info = utf8("info");
    const aad = utf8("aad");
    const sealed = await hpkeSeal({
      aad,
      info,
      plaintext: utf8("Only for you."),
      randomness: randomnessOf("sender").bytes(32),
      recipientPublicKey: to.value,
    });
    if (sealed === undefined) throw new Error("nothing was sealed");
    const opened = await agreement.open(mine.publicKey, { ...sealed, info, aad });
    expect(new TextDecoder().decode(opened)).toBe("Only for you.");
    expect(await agreement.open(other.publicKey, { ...sealed, info, aad })).toBeUndefined();
    expect(await agreement.open(mine.publicKey, { ...sealed, info, aad: utf8("other") })).toBe(
      undefined,
    );
    expect(await refusal(() => agreement.open("z6LSunknown", { ...sealed, info, aad }))).toBe(
      "not-found",
    );
  });
});

describe("the roles of a keystore", () => {
  it("are sealed apart: each under its own lock, and one opened leaves the others shut", async () => {
    const storage = memoryStorage();
    const locks = Object.fromEntries(
      KEY_ROLES.map((role) => [role, quick(`the ${role} passphrase`)]),
    ) as Record<KeyRole, ReturnType<typeof quick>>;
    const keystore = await Keystore.create({ storage, locks, randomness: randomnessOf("apart") });
    for (const role of KEY_ROLES) {
      for (const other of KEY_ROLES) {
        if (other === role) continue;
        expect(await refusal(() => keystore.unlock(role, locks[other]))).toBe("not-opened");
      }
      const keys = await keystore.unlock(role, locks[role]);
      await keys.generate();
      keys.lock();
    }
    // Each role is a document of its own, and a key made in one changes no other.
    const before = new Map<string, string>();
    for (const name of await storage.list()) {
      before.set(name, (await storage.get(name))?.version ?? "");
    }
    const operational = await keystore.unlock("operational", locks.operational);
    await operational.generate();
    for (const name of await storage.list()) {
      const version = (await storage.get(name))?.version;
      expect(version === before.get(name), name).toBe(name !== "operational");
    }
  });

  it("are unlocked one handle at a time, and a locked handle does nothing more", async () => {
    const { keystore, lock } = await made();
    const operational = await keystore.unlock("operational", lock);
    expect(await refusal(() => keystore.unlock("operational", lock))).toBe("in-use");
    const { publicKey } = await operational.generate();
    const signer = operational.signer(publicKey);
    expect(operational.locked).toBe(false);
    operational.lock();
    operational.lock();
    expect(operational.locked).toBe(true);
    expect(() => signer.sign(utf8("after"))).toThrow(KeystoreError);
    expect(await refusal(() => operational.keys())).toBe("locked");
    expect(await refusal(() => operational.has(publicKey))).toBe("locked");
    expect(await refusal(() => operational.generate())).toBe("locked");
    expect(await refusal(() => operational.remove(publicKey))).toBe("locked");
    expect(await refusal(() => operational.signer(publicKey))).toBe("locked");
    expect(await refusal(() => operational.role)).toBe("locked");
    // Locked, the role can be unlocked again, and the key is there.
    const again = await keystore.unlock("operational", lock);
    expect(again.has(publicKey)).toBe(true);
    // A failed unlock leaves the role free.
    again.lock();
    expect(await refusal(() => keystore.unlock("operational", quick("another passphrase")))).toBe(
      "not-opened",
    );
    (await keystore.unlock("operational", lock)).lock();
    expect(await refusal(() => keystore.unlock("owner" as KeyRole, lock))).toBe("argument");
  });

  it("do not make a change that was asked for before they were locked and had not begun", async () => {
    const { keystore, lock } = await made();
    const operational = await keystore.unlock("operational", lock);
    const asked = operational.generate();
    operational.lock();
    await expect(asked).rejects.toMatchObject({ code: "locked" });
    expect((await keystore.unlock("operational", lock)).keys()).toStrictEqual([]);
  });

  it("are held by nothing that only looks like a handle", async () => {
    const lookalike = Object.create(OperationalKeys.prototype) as OperationalKeys;
    expect(lookalike.locked).toBe(true);
    expect(await refusal(() => lookalike.keys())).toBe("locked");
    expect(await refusal(() => lookalike.signer("z6Mk"))).toBe("locked");
    lookalike.lock();
    // And there is no role but the four.
    expect(await refusal(() => handleOver({ role: "owner" } as never))).toBe("argument");
  });

  it("lose a key that is removed: it is out of storage, and its signer signs no more", async () => {
    const { keystore, lock } = await made();
    const operational = await keystore.unlock("operational", lock);
    const kept = await operational.generate();
    const gone = await operational.generate();
    const signer = operational.signer(gone.publicKey);
    await operational.remove(gone.publicKey);
    expect(operational.keys()).toStrictEqual([kept]);
    expect(operational.generation).toBe(3);
    expect(() => signer.sign(utf8("after"))).toThrow(KeystoreError);
    expect(await refusal(() => operational.remove(gone.publicKey))).toBe("not-found");
    operational.lock();
    const again = await keystore.unlock("operational", lock);
    expect(again.keys()).toStrictEqual([kept]);
  });
});

describe(`${clause("L1 3.11", "L1 7.4")} a control key`, () => {
  it("signs the identity event that reveals it, and the log verifies", async () => {
    const { keystore, lock } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first, next } = await founding(keys);
    const signed = await keys.control.sign(genesis);
    expect(signed.proof).toHaveLength(1);
    expect(verified([signed])).toBe(1);
    // The next event reveals the key the genesis committed to, and commits to another.
    await keys.control.published(signed);
    const third = await keys.control.generate();
    const address = mindAddress(contentId(signed));
    const update = draftUpdate({ mind: address, seq: 0, head: contentId(signed) }, T(10), {
      controller: { keys: [next.publicKey], next: [keyHash(third.publicKey)] },
    });
    const second = await keys.control.sign(update);
    expect(verified([signed, second])).toBe(2);
    expect(keys.control.has(first.publicKey)).toBe(false);
  });

  it("is destroyed once the event it signed is published", async () => {
    const { keystore, lock, storage } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first, next } = await founding(keys);
    const signed = await keys.control.sign(genesis);
    expect(keys.control.keys().map((key) => key.publicKey)).toStrictEqual([
      first.publicKey,
      next.publicKey,
    ]);
    const generation = keys.control.generation;
    expect(await keys.control.published(signed)).toBe(1);
    // It is gone from the handle, and from what is stored.
    expect(keys.control.keys()).toStrictEqual([{ publicKey: next.publicKey, label: "next" }]);
    expect(keys.control.generation).toBe(generation + 1);
    keys.control.lock();
    const again = await (await Keystore.open({ storage })).unlock("control", lock);
    expect(again.keys()).toStrictEqual([{ publicKey: next.publicKey, label: "next" }]);
    // Nothing is left that could sign an alternative event for the position.
    const other = draftGenesis(T(1), {
      kind: "agent",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
    });
    expect(await refusal(() => again.sign(other))).toBe("not-found");
    expect(await refusal(() => again.published(signed))).toBe("not-found");
  });

  it("signs one event, as often as it is asked, and never another", async () => {
    const { keystore, lock } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first, next } = await founding(keys);
    const signed = await keys.control.sign(genesis);
    // The same event again is the same signature: Ed25519 has no randomness.
    expect(await keys.control.sign(genesis)).toStrictEqual(signed);
    // With another date for its proof it is the same event still.
    const later = await keys.control.sign(genesis, T(5));
    expect(contentId(later)).toBe(contentId(signed));
    expect(later.proof[0]?.created).toBe(T(5));
    // Another event for the same position is refused, and nothing is signed.
    const other = draftGenesis(T(0), {
      kind: "service",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
    });
    expect(await refusal(() => keys.control.sign(other))).toBe("already-signed");
    expect(keys.control.pending()).toStrictEqual([genesis]);
  });

  it("remembers the event in storage before it signs, so that a process that stops cannot sign another", async () => {
    const { keystore, lock, storage } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first, next } = await founding(keys);
    const signed = await keys.control.sign(genesis);
    // The process stops here: nothing was locked, nothing was published.
    const after = await (await Keystore.open({ storage })).unlock("control", lock);
    expect(after.keys()).toStrictEqual([
      { publicKey: first.publicKey, label: "first", signing: genesis },
      { publicKey: next.publicKey, label: "next" },
    ]);
    // The event is found again, and signing it gives what was signed before.
    const [pending] = after.pending();
    expect(pending).toStrictEqual(genesis);
    expect(await after.sign(pending as unknown as typeof genesis)).toStrictEqual(signed);
    const other = draftGenesis(T(3), {
      kind: "agent",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
    });
    expect(await refusal(() => after.sign(other))).toBe("already-signed");
  });

  it("signs nothing if the event could not be remembered first", async () => {
    const inner = memoryStorage();
    let failing = false;
    const storage: KeyStorage = {
      ...inner,
      put: (name, value, expected) =>
        failing ? Promise.reject(new Error("the disk is full")) : inner.put(name, value, expected),
    };
    const { keystore, lock } = await made("failing", storage);
    const keys = await all(keystore, lock);
    const { genesis, first } = await founding(keys);
    failing = true;
    await expect(keys.control.sign(genesis)).rejects.toThrow("the disk is full");
    // The key is as it was: it has signed nothing, and may sign this event or another.
    expect(keys.control.pending()).toStrictEqual([]);
    expect(keys.control.keys()[0]).toStrictEqual({ publicKey: first.publicKey, label: "first" });
    failing = false;
    expect((await keys.control.sign(genesis)).proof).toHaveLength(1);
  });

  it("stays where it is if its destruction could not be written", async () => {
    const inner = memoryStorage();
    let failing = false;
    const storage: KeyStorage = {
      ...inner,
      put: (name, value, expected) =>
        failing ? Promise.reject(new Error("the disk is full")) : inner.put(name, value, expected),
    };
    const { keystore, lock } = await made("failing", storage);
    const keys = await all(keystore, lock);
    const { genesis, first } = await founding(keys);
    const signed = await keys.control.sign(genesis);
    failing = true;
    await expect(keys.control.published(signed)).rejects.toThrow("the disk is full");
    // Memory says what storage says: the key is there, still bound to its event.
    expect(keys.control.has(first.publicKey)).toBe(true);
    expect(keys.control.pending()).toStrictEqual([genesis]);
    failing = false;
    expect(await keys.control.published(signed)).toBe(1);
    expect(keys.control.has(first.publicKey)).toBe(false);
  });

  it("is bound to no event that cannot be signed", async () => {
    const { keystore, lock } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first } = await founding(keys);
    const unsignable: [string, object, string?][] = [
      ["a home that is no origin", { ...genesis, homes: ["not an origin"] }],
      ["no kind", (({ kind: _, ...rest }) => rest)(genesis)],
      ["a type that is none", { ...genesis, type: "Birth" }],
      ["a date that is none", { ...genesis, created: "yesterday" }],
      ["a number that is no integer", { ...genesis, ext: { "ext.example": { share: 0.5 } } }],
      ["a proof dated by no clock", genesis, "not a time"],
    ];
    for (const [what, event, created] of unsignable) {
      expect(await refusal(() => keys.control.sign(event as never, created)), what).toBe(
        "argument",
      );
      // The key is as it was: bound to nothing.
      expect(keys.control.pending(), what).toStrictEqual([]);
      expect(keys.control.keys()[0], what).toStrictEqual({
        publicKey: first.publicKey,
        label: "first",
      });
    }
    // And it signs the event that can be signed.
    expect(verified([await keys.control.sign(genesis)])).toBe(1);
    // What is no event at all is nothing a key signed, and nothing that was published.
    for (const none of [{ share: 0.5 }, { at: new Date() }, { nested: { n: Number.NaN } }]) {
      expect(await refusal(() => keys.control.published(none))).toBe("argument");
      expect(await refusal(() => keys.control.unsent(none))).toBe("argument");
    }
    expect(keys.control.pending()).toStrictEqual([genesis]);
  });

  it("may sign another event only if its owner says the first was never sent", async () => {
    const { keystore, lock } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first, next } = await founding(keys);
    await keys.control.sign(genesis);
    const other = draftGenesis(T(0), {
      kind: "service",
      controller: { keys: [first.publicKey], next: [keyHash(next.publicKey)] },
    });
    expect(await refusal(() => keys.control.unsent(other))).toBe("not-found");
    await keys.control.unsent(genesis);
    expect(keys.control.pending()).toStrictEqual([]);
    expect(verified([await keys.control.sign(other)])).toBe(1);
  });

  it("signs with every control key the event reveals that is held, and with no other key", async () => {
    const { keystore, lock } = await made();
    const keys = await all(keystore, lock);
    const [a, b, elsewhere, next] = await Promise.all(
      [0, 1, 2, 3].map(() => keys.control.generate()),
    );
    if (a === undefined || b === undefined || elsewhere === undefined || next === undefined) {
      throw new Error("no keys");
    }
    await keys.control.remove(elsewhere.publicKey);
    const genesis = draftGenesis(T(0), {
      kind: "agent",
      controller: {
        keys: [a.publicKey, elsewhere.publicKey, b.publicKey],
        next: [keyHash(next.publicKey)],
      },
    });
    const signed = await keys.control.sign(genesis);
    expect(signed.proof.map((proof) => proof.verificationMethod.split("#")[1])).toStrictEqual([
      a.publicKey,
      b.publicKey,
    ]);
    expect(await keys.control.published(signed)).toBe(2);
    // An event that reveals no key held here, or names no control keys at all.
    const strangers = draftGenesis(T(0), {
      kind: "agent",
      controller: { keys: [elsewhere.publicKey], next: [] },
    });
    expect(await refusal(() => keys.control.sign(strangers))).toBe("not-found");
    const collective = draftGenesis(T(0), {
      kind: "collective",
      controller: { members: [MEMBER], threshold: 1 },
    });
    expect(await refusal(() => keys.control.sign(collective))).toBe("argument");
    // A collective's later event has no controller at all, and what is no event has none either.
    const { controller: _, ...bare } = collective;
    expect(await refusal(() => keys.control.sign(bare as never))).toBe("argument");
    for (const controller of ["keys", null, { keys: "key" }, { keys: [7] }]) {
      expect(await refusal(() => keys.control.sign({ ...bare, controller } as never))).toBe(
        "argument",
      );
    }
  });
});

describe("an invocation key", () => {
  // The identity events of a collective, of which this mind is a member.
  const update = (seq: number, seconds: number, mind = CLUB) =>
    draftUpdate({ mind, seq: seq - 1, head: HEAD }, T(seconds), {});

  it("signs a collective's event as its member, and remembers the position it signed for", async () => {
    const { keystore, lock, storage } = await made();
    const invocation = await keystore.unlock("invocation", lock);
    const { publicKey } = await invocation.generate();
    const as = { publicKey, member: MEMBER, versionId: formatVersionId(0, HEAD) };
    const event = update(1, 10);
    const signed = await invocation.sign(event, as);
    expect(signed.proof).toHaveLength(1);
    expect(signed.proof[0]?.verificationMethod).toBe(
      formatKeyRef(MEMBER, formatVersionId(0, HEAD), publicKey),
    );
    // The same event again, and with the proofs of other members on it.
    expect(await invocation.sign(event, as)).toStrictEqual(signed);
    const withOthers = { ...event, proof: signed.proof };
    expect((await invocation.sign(withOthers, as)).proof).toStrictEqual(signed.proof);
    // Another event for that position is duplicity by this member, and is refused.
    expect(await refusal(() => invocation.sign(update(1, 11), as))).toBe("already-signed");
    // Another position, and another collective's same position, are other positions.
    expect((await invocation.sign(update(2, 20), as)).proof).toHaveLength(1);
    expect((await invocation.sign(update(1, 11, OTHER), as)).proof).toHaveLength(1);
    // What it signed is remembered across a restart.
    invocation.lock();
    const again = await (await Keystore.open({ storage })).unlock("invocation", lock);
    expect(await refusal(() => again.sign(update(1, 12), as))).toBe("already-signed");
    expect(await again.sign(event, as)).toStrictEqual(signed);
    expect(await refusal(() => again.sign(event, { ...as, publicKey: "z6Mkother" }))).toBe(
      "not-found",
    );
  });

  it("remembers no position for an event that cannot be signed", async () => {
    const { keystore, lock } = await made();
    const invocation = await keystore.unlock("invocation", lock);
    const { publicKey } = await invocation.generate();
    const as = { publicKey, member: MEMBER, versionId: formatVersionId(0, HEAD) };
    const event = update(1, 10);
    const unsignable: [string, object, object][] = [
      ["a member that is no address", event, { ...as, member: "did:web:example.com" }],
      ["a version that is none", event, { ...as, versionId: "latest" }],
      ["an event with a member that is no part of it", { ...event, recovery: {} }, as],
      ["a date that is none", { ...event, created: "yesterday" }, as],
    ];
    for (const [what, wrong, signing] of unsignable) {
      expect(await refusal(() => invocation.sign(wrong as never, signing as never)), what).toBe(
        "argument",
      );
    }
    // The position is free: the event that can be signed is signed for it.
    expect((await invocation.sign(event, as)).proof).toHaveLength(1);
    expect(await refusal(() => invocation.sign(update(1, 11), as))).toBe("already-signed");
  });

  it("signs any genesis: a different genesis is a different mind", async () => {
    const { keystore, lock } = await made();
    const invocation = await keystore.unlock("invocation", lock);
    const { publicKey } = await invocation.generate();
    const as = { publicKey, member: MEMBER, versionId: formatVersionId(0, HEAD) };
    const club = (seconds: number) =>
      draftGenesis(T(seconds), {
        kind: "collective",
        controller: { members: [MEMBER, OTHER], threshold: 2 },
      });
    expect((await invocation.sign(club(0), as)).proof).toHaveLength(1);
    expect((await invocation.sign(club(1), as)).proof).toHaveLength(1);
    // What has neither a position nor the type of a genesis is no identity event.
    const { seq: _, ...placeless } = update(1, 10);
    expect(await refusal(() => invocation.sign(placeless as never, as))).toBe("argument");
  });
});

describe("control keys that are kept elsewhere", () => {
  it("are in a storage of their own, and nothing of them is with the rest", async () => {
    const storage = memoryStorage();
    const controlStorage = memoryStorage();
    const lock = keychainLock(memoryKeychain(), "oip-test");
    const randomness = randomnessOf("elsewhere");
    const keystore = await Keystore.create({ storage, controlStorage, locks: lock, randomness });
    expect((await storage.list()).sort()).toStrictEqual([
      "agreement",
      "invocation",
      "meta",
      "operational",
    ]);
    expect(await controlStorage.list()).toStrictEqual(["control"]);
    const control = await keystore.unlock("control", lock);
    const { publicKey } = await control.generate();
    control.lock();
    expect((await storage.list()).includes("control")).toBe(false);
    // It is found again by a keystore that is told where they are, and by no other.
    const again = await Keystore.open({ storage, controlStorage });
    const found = await again.unlock("control", lock);
    expect(found.has(publicKey)).toBe(true);
    found.lock();
    expect(await again.backupDue()).toStrictEqual(["control"]);
    const without = await Keystore.open({ storage });
    expect(await refusal(() => without.unlock("control", lock))).toBe("not-found");
    expect(await refusal(() => without.backupDue())).toBe("not-found");
    (await without.unlock("operational", lock)).lock();
    // The lock of the role is changed where the role is.
    const other = quick("a passphrase for the control keys");
    await again.changeLock("control", lock, other);
    expect((await again.unlock("control", other)).has(publicKey)).toBe(true);
    expect(await controlStorage.list()).toStrictEqual(["control"]);
    expect((await storage.list()).includes("control")).toBe(false);
  });

  it("come back from a backup into a storage of their own", async () => {
    const lock = keychainLock(memoryKeychain(), "oip-test");
    const keystore = await Keystore.create({
      storage: memoryStorage(),
      locks: lock,
      randomness: randomnessOf("elsewhere"),
    });
    const keys = await all(keystore, lock);
    const { publicKey } = await keys.control.generate();
    const backup = await keystore.backup(keys, quick());
    const storage = memoryStorage();
    const controlStorage = memoryStorage();
    const restored = await Keystore.restore({
      storage,
      controlStorage,
      locks: lock,
      backup: backup.bytes,
      backupLock: quick(),
    });
    expect(await controlStorage.list()).toStrictEqual(["control"]);
    expect((await storage.list()).includes("control")).toBe(false);
    expect((await restored.unlock("control", lock)).has(publicKey)).toBe(true);
  });

  it("are not written over: a keystore is not made where either storage holds one", async () => {
    const lock = keychainLock(memoryKeychain(), "oip-test");
    const controlStorage = memoryStorage();
    await Keystore.create({ storage: memoryStorage(), controlStorage, locks: lock });
    expect(
      await refusal(() =>
        Keystore.create({ storage: memoryStorage(), controlStorage, locks: lock }),
      ),
    ).toBe("exists");
  });
});

describe("two handles on one keystore", () => {
  it("cannot both change a role: the second is told, and a destroyed key is not written back", async () => {
    const { keystore, lock, storage } = await made();
    const keys = await all(keystore, lock);
    const { genesis, first } = await founding(keys);
    const signed = await keys.control.sign(genesis);
    // Another process opens the same storage, and holds the control keys as they are now.
    const other = await (await Keystore.open({ storage })).unlock("control", lock);
    expect(other.has(first.publicKey)).toBe(true);
    // The first destroys the key that signed.
    await keys.control.published(signed);
    // The other still has it in memory. Whatever it writes would put it back: it is refused.
    expect(await refusal(() => other.generate())).toBe("changed");
    expect(await refusal(() => other.published(signed))).toBe("changed");
    other.lock();
    const fresh = await (await Keystore.open({ storage })).unlock("control", lock);
    expect(fresh.has(first.publicKey)).toBe(false);
  });

  it("change a role one after the other when they are asked at once", async () => {
    const { keystore, lock } = await made();
    const operational = await keystore.unlock("operational", lock);
    const five = await Promise.all([0, 1, 2, 3, 4].map(() => operational.generate()));
    expect(new Set(five.map((key) => key.publicKey)).size).toBe(5);
    expect(operational.keys()).toStrictEqual(five);
    expect(operational.generation).toBe(5);
  });
});

describe("what is stored", () => {
  /** A keystore sealed under a passphrase, as most are. */
  const sealed = (name?: string) => made(name, memoryStorage(), quick());

  const edited = async (
    storage: KeyStorage,
    name: string,
    edit: (document: Record<string, unknown>) => unknown,
  ) => {
    const stored = await storage.get(name);
    if (stored === undefined) throw new Error("nothing is stored");
    const parsed = parseJsonBytes(stored.value);
    if (!parsed.ok) throw new Error("not JSON");
    const changed = edit(structuredClone(parsed.value) as Record<string, unknown>);
    const bytes = changed instanceof Uint8Array ? changed : canonicalBytes(changed);
    await storage.put(name, bytes, stored.version);
  };

  it("does not open once any part of it was changed", async () => {
    const changes: [string, (document: Record<string, unknown>) => unknown][] = [
      ["the role", (document) => ({ ...document, role: "invocation" })],
      ["the generation", (document) => ({ ...document, generation: 7 })],
      [
        "the keystore",
        (document) => ({ ...document, keystore: bytesToBase64url(new Uint8Array(16)) }),
      ],
      [
        "the salt",
        (document) => ({
          ...document,
          lock: { ...(document["lock"] as object), salt: bytesToBase64url(new Uint8Array(32)) },
        }),
      ],
      ["the nonce", (document) => ({ ...document, nonce: bytesToBase64url(new Uint8Array(24)) })],
      [
        "the ciphertext",
        (document) => {
          const text = String(document["ciphertext"]);
          return { ...document, ciphertext: (text.startsWith("A") ? "B" : "A") + text.slice(1) };
        },
      ],
    ];
    for (const [what, change] of changes) {
      const { keystore, lock, storage } = await sealed();
      const operational = await keystore.unlock("operational", lock);
      await operational.generate();
      operational.lock();
      await edited(storage, "operational", change);
      const outcome = await refusal(() => keystore.unlock("operational", lock));
      expect(["not-opened", "damaged"], what).toContain(outcome);
    }
  });

  it("is not read as another role's, or another keystore's", async () => {
    const one = await sealed("one");
    const two = await sealed("two");
    // The operational keys of another keystore, sealed under the same passphrase.
    const theirs = await two.storage.get("operational");
    const ours = await one.storage.get("operational");
    await one.storage.put("operational", theirs?.value ?? new Uint8Array(), ours?.version);
    expect(await refusal(() => one.keystore.unlock("operational", one.lock))).toBe("damaged");
    // This keystore's own invocation keys in the place of its control keys.
    const invocation = await one.storage.get("invocation");
    const control = await one.storage.get("control");
    await one.storage.put("control", invocation?.value ?? new Uint8Array(), control?.version);
    expect(await refusal(() => one.keystore.unlock("control", one.lock))).toBe("damaged");
  });

  it("asks for no more work than is accepted, whatever a document says", async () => {
    const cases: [string, (lock: Record<string, unknown>) => unknown, string][] = [
      ["a work factor of 2^21", (lock) => ({ ...lock, n: 2 ** 21 }), "unsupported"],
      [
        "a work factor that is no power of two",
        (lock) => ({ ...lock, n: 2 ** 14 + 1 }),
        "unsupported",
      ],
      ["a work factor below the least", (lock) => ({ ...lock, n: 2 ** 13 }), "unsupported"],
      ["another block size", (lock) => ({ ...lock, r: 16 }), "unsupported"],
      ["another parallelisation", (lock) => ({ ...lock, p: 2 }), "unsupported"],
      ["a short salt", (lock) => ({ ...lock, salt: "AAAA" }), "damaged"],
      ["a lock of a kind not known", () => ({ kind: "argon2id" }), "unsupported"],
      ["a lock of no kind", () => ({}), "damaged"],
      ["a lock with more in it", (lock) => ({ ...lock, extra: true }), "damaged"],
    ];
    for (const [what, change, code] of cases) {
      const { keystore, lock, storage } = await sealed();
      await edited(storage, "operational", (document) => ({
        ...document,
        lock: change(document["lock"] as Record<string, unknown>),
      }));
      // The lock is asked for no key: the document is refused before anything is derived from it.
      let asked = 0;
      const watched: Lock = {
        fresh: (context, randomness) => lock.fresh(context, randomness),
        key: (header, context) => {
          asked += 1;
          return lock.key(header, context);
        },
      };
      expect(await refusal(() => keystore.unlock("operational", watched)), what).toBe(code);
      expect(asked, what).toBe(0);
    }
  });

  it("is refused if it is not a sealed document of this format", async () => {
    const cases: [string, (document: Record<string, unknown>) => unknown, string][] = [
      ["a later format", (document) => ({ ...document, format: "oip-keystore/2" }), "unsupported"],
      ["another format", (document) => ({ ...document, format: "keystore" }), "damaged"],
      ["a member too many", (document) => ({ ...document, extra: 1 }), "damaged"],
      ["a member too few", ({ nonce: _, ...document }) => document, "damaged"],
      ["a short nonce", (document) => ({ ...document, nonce: "AAAA" }), "damaged"],
      [
        "a ciphertext shorter than a tag",
        (document) => ({ ...document, ciphertext: "AAAA" }),
        "damaged",
      ],
      ["a role that is none", (document) => ({ ...document, role: "owner" }), "damaged"],
      ["a generation that is no count", (document) => ({ ...document, generation: -1 }), "damaged"],
      ["no JSON", () => new Uint8Array([0xff, 0x00]), "damaged"],
      ["an array", () => canonicalBytes([]), "damaged"],
    ];
    for (const [what, change, code] of cases) {
      const { keystore, lock, storage } = await sealed();
      await edited(storage, "operational", change);
      expect(await refusal(() => keystore.unlock("operational", lock)), what).toBe(code);
      expect(await refusal(() => keystore.backupDue()), what).toBe(code);
    }
    const { keystore, lock, storage } = await sealed();
    const stored = await storage.get("agreement");
    await storage.delete("agreement", stored?.version ?? "");
    expect(await refusal(() => keystore.unlock("agreement", lock))).toBe("not-found");
  });
});
