// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind's identity changes in steps: bind the control keys, sign, publish,
 * destroy. Each test here stops the change at one of them, or loses a race,
 * and says what the mind is afterwards and what it can still do.
 */

import { contentId, keyHash, OipError } from "@oip/core";
import {
  type Keychain,
  keychainLock,
  Keystore,
  type KeyStorage,
  type Lock,
  memoryStorage,
  passphrase,
  SCRYPT_MIN_N,
} from "@oip/keystore";
import { clause } from "@oip/testkit";
import { at } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, Mind, type MindOptions, TransportError } from "../src/index.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const B = "https://resolver-b.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.resolver(B);
});
afterEach(() => {
  world.close();
});

function memoryKeychain(): Keychain {
  const kept = new Map<string, string>();
  return {
    get: (service, account) => Promise.resolve(kept.get(`${service}\n${account}`)),
    set: (service, account, secret) => {
      kept.set(`${service}\n${account}`, secret);
      return Promise.resolve();
    },
    delete: (service, account) => {
      kept.delete(`${service}\n${account}`);
      return Promise.resolve();
    },
  };
}

/** A storage that fails its writes while a test says so. */
function fragile(): KeyStorage & { failing: boolean } {
  const inner = memoryStorage();
  const storage = {
    ...inner,
    failing: false,
    put: (name: string, value: Uint8Array, expected: string | undefined) =>
      storage.failing
        ? Promise.reject(new Error("the disk is full"))
        : inner.put(name, value, expected),
  };
  return storage;
}

async function made(storage: KeyStorage = memoryStorage()) {
  const lock: Lock = keychainLock(memoryKeychain(), "oip-test");
  const keystore = await Keystore.create({ storage, locks: lock });
  const options: MindOptions = {
    keystore,
    lock,
    resolvers: [A, B],
    fetch: world.fetch,
    clock: world.clock,
  };
  const mind = await Mind.create(options, { kind: "agent" });
  return { keystore, lock, options, storage, mind };
}

async function refusal(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof OipError) return `oip: ${error.code}`;
    if (error instanceof TransportError) return `transport: ${error.failure}`;
    if (error instanceof Error) return `error: ${error.message}`;
    throw error;
  }
  throw new Error("nothing was refused");
}

async function controlOf(keystore: Keystore, lock: Lock) {
  const control = await keystore.unlock("control", lock);
  try {
    return { keys: control.keys().map((key) => key.publicKey), pending: control.pending() };
  } finally {
    control.lock();
  }
}

const seenBy = () => new Lookup({ resolvers: [A, B], fetch: world.fetch, clock: world.clock });

describe(`${clause("L1 3.11", "L1 7.4")} an identity change that stops before it is published`, () => {
  it("is finished by the next change, with the same event, before anything new is signed", async () => {
    const { keystore, lock, mind } = await made();
    // The resolvers cannot be reached while the update is published.
    world.clock.at = at(200);
    world.before = (request) => {
      if (request.method === "PUT") throw new TypeError("fetch failed");
    };
    expect(
      await refusal(() => mind.update({ homes: ["https://one.example"] }, { control: lock })),
    ).toBe("transport: unreachable");
    expect(mind.state.seq).toBe(0);
    // The control key is bound to the event it signed, and the key the event commits to is kept.
    const stopped = await controlOf(keystore, lock);
    expect(stopped.keys).toHaveLength(2);
    expect(stopped.pending).toHaveLength(1);
    expect(stopped.pending[0]).toMatchObject({
      type: "Update",
      seq: 1,
      homes: ["https://one.example"],
    });
    // The resolvers are back. Another change is asked for: the first is published first.
    world.before = undefined;
    world.clock.at = at(300);
    const state = await mind.update({ alsoKnownAs: ["dns:ada.example"] }, { control: lock });
    expect(state).toMatchObject({
      seq: 2,
      homes: ["https://one.example"],
      alsoKnownAs: ["dns:ada.example"],
    });
    // The event at the first position is the one that was signed and could not be sent.
    expect(contentId(mind.resolved.log.entries[1]?.event)).toBe(contentId(stopped.pending[0]));
    // One control key is left: the one the last event commits to.
    const after = await controlOf(keystore, lock);
    expect(after.pending).toStrictEqual([]);
    expect(after.keys.map((key) => keyHash(key))).toStrictEqual(
      state.controller.kind === "key" ? state.controller.next : [],
    );
    expect((await seenBy().resolve(mind.address)).duplicitous).toBe(false);
  });

  it("is finished though it was published, where the process stopped before the keys were destroyed", async () => {
    const storage = fragile();
    const { keystore, lock, mind } = await made(storage);
    world.clock.at = at(200);
    // The keystore's storage fails from the moment a resolver has the update.
    let taken = 0;
    world.before = (request) => {
      if (request.method === "PUT" && ++taken === 2) storage.failing = true;
    };
    expect(await refusal(() => mind.update({}, { control: lock }))).toBe("error: the disk is full");
    world.before = undefined;
    storage.failing = false;
    // The event is published, and the key that signed it is still in the keystore, bound to it.
    expect((await seenBy().resolve(mind.address)).state.seq).toBe(1);
    const stopped = await controlOf(keystore, lock);
    expect(stopped.keys).toHaveLength(2);
    expect(stopped.pending).toHaveLength(1);
    // The next change finds the event in the log, destroys its key, and goes on.
    world.clock.at = at(300);
    const state = await mind.update({}, { control: lock });
    expect(state.seq).toBe(2);
    const after = await controlOf(keystore, lock);
    expect(after.pending).toStrictEqual([]);
    expect(after.keys).toHaveLength(1);
    expect((await seenBy().resolve(mind.address)).duplicitous).toBe(false);
  });

  it("signs nothing where the keystore fails as it binds the key, and leaves no key behind for long", async () => {
    const storage = fragile();
    const { keystore, lock, mind } = await made(storage);
    world.clock.at = at(200);
    // The storage takes the new key, and fails from then on: the control key cannot be bound.
    let writes = 0;
    const put = storage.put.bind(storage);
    storage.put = (name, value, expected) => {
      if (name === "control" && ++writes === 2) storage.failing = true;
      return put(name, value, expected);
    };
    expect(await refusal(() => mind.update({}, { control: lock }))).toBe("error: the disk is full");
    storage.failing = false;
    storage.put = put;
    // Nothing was signed. The key that was made for the event could not be removed either.
    const stopped = await controlOf(keystore, lock);
    expect(stopped.pending).toStrictEqual([]);
    expect(stopped.keys).toHaveLength(2);
    // The next change removes it, as a key that no event commits to, and makes its own.
    const state = await mind.update({}, { control: lock });
    expect(state.seq).toBe(1);
    const after = await controlOf(keystore, lock);
    expect(after.keys.map((key) => keyHash(key))).toStrictEqual(
      state.controller.kind === "key" ? state.controller.next : [],
    );
  });

  it("signs nothing where the keystore cannot remember what is about to be signed", async () => {
    const storage = fragile();
    const { keystore, lock, mind } = await made(storage);
    world.clock.at = at(200);
    const published = world.asked.length;
    storage.failing = true;
    expect(await refusal(() => mind.update({}, { control: lock }))).toBe("error: the disk is full");
    storage.failing = false;
    // Nothing was sent to a resolver, and the keystore is as it was.
    expect(world.asked.slice(published).filter((asked) => asked.startsWith("PUT"))).toStrictEqual(
      [],
    );
    const control = await controlOf(keystore, lock);
    expect(control.pending).toStrictEqual([]);
    expect(control.keys).toHaveLength(1);
    expect((await mind.update({}, { control: lock })).seq).toBe(1);
  });
});

describe(`${clause("L1 7.4")} a keystore that holds control keys that have signed`, () => {
  /** A copy of a mind's keystore, as a backup restored on another machine is. */
  async function copyOf(keystore: Keystore, lock: Lock) {
    const keys = {
      control: await keystore.unlock("control", lock),
      operational: await keystore.unlock("operational", lock),
      invocation: await keystore.unlock("invocation", lock),
      agreement: await keystore.unlock("agreement", lock),
    };
    const sealing = passphrase("the backup passphrase", { n: SCRYPT_MIN_N });
    const backup = await keystore.backup(keys, sealing);
    for (const role of Object.values(keys)) role.lock();
    const other: Lock = keychainLock(memoryKeychain(), "oip-other");
    const restored = await Keystore.restore({
      storage: memoryStorage(),
      locks: other,
      backup: backup.bytes,
      backupLock: sealing,
    });
    return { keystore: restored, lock: other };
  }

  it("destroys them when it next changes the mind's identity, and goes on if it holds the key the log commits to", async () => {
    const first = await made();
    first.mind.close();
    // A backup taken now holds the key the genesis commits to.
    const copy = await copyOf(first.keystore, first.lock);
    // The first machine is lost. The mind is opened from the backup, and changes its identity.
    world.clock.at = at(200);
    const mind = await Mind.open({ ...first.options, keystore: copy.keystore, lock: copy.lock });
    expect((await mind.update({}, { control: copy.lock })).seq).toBe(1);
    expect((await controlOf(copy.keystore, copy.lock)).keys).toHaveLength(1);
  });

  it("can change nothing where the log has moved on to a key it does not hold", async () => {
    const first = await made();
    first.mind.close();
    const copy = await copyOf(first.keystore, first.lock);
    // The first machine changes the mind's identity: the log now commits to a key only it holds.
    world.clock.at = at(200);
    const original = await Mind.open(first.options);
    await original.update({}, { control: first.lock });
    original.close();
    // The copy holds the key that signed that event, and not the one it commits to.
    world.clock.at = at(300);
    const stale = await Mind.open({ ...first.options, keystore: copy.keystore, lock: copy.lock });
    expect(stale.state.seq).toBe(1);
    expect(await refusal(() => stale.update({}, { control: copy.lock }))).toBe("oip: forbidden");
    // The used key was destroyed on the way: the copy can sign no alternative to the event.
    expect((await controlOf(copy.keystore, copy.lock)).keys).toStrictEqual([]);
    // The mind is not duplicitous, and its everyday keys still sign.
    expect((await seenBy().resolve(stale.address)).duplicitous).toBe(false);
    expect(stale.signingKey()).toBe(original.state.keys[0]);
  });

  it("lets go of an event it signed and never published, where the log has another at that position", async () => {
    const first = await made();
    first.mind.close();
    const copy = await copyOf(first.keystore, first.lock);
    // The copy signs an update and cannot publish it.
    world.clock.at = at(200);
    const stale = await Mind.open({ ...first.options, keystore: copy.keystore, lock: copy.lock });
    world.before = (request) => {
      if (request.method === "PUT") throw new TypeError("fetch failed");
    };
    expect(
      await refusal(() =>
        stale.update({ homes: ["https://lost.example"] }, { control: copy.lock }),
      ),
    ).toBe("transport: unreachable");
    world.before = undefined;
    expect((await controlOf(copy.keystore, copy.lock)).pending).toHaveLength(1);
    // Meanwhile the first machine publishes another event for that position.
    const original = await Mind.open(first.options);
    await original.update({ homes: ["https://won.example"] }, { control: first.lock });
    // The copy does not publish its own: that would be duplicity. It lets it go, with its key.
    world.clock.at = at(300);
    const asked = world.asked.length;
    expect(await refusal(() => stale.update({}, { control: copy.lock }))).toBe("oip: forbidden");
    expect(world.asked.slice(asked).filter((request) => request.startsWith("PUT"))).toStrictEqual(
      [],
    );
    // The key it made for its own event is gone too: no event commits to it.
    const control = await controlOf(copy.keystore, copy.lock);
    expect(control.pending).toStrictEqual([]);
    expect(control.keys).toStrictEqual([]);
    const resolved = await seenBy().resolve(stale.address);
    expect(resolved.duplicitous).toBe(false);
    expect(resolved.state.homes).toStrictEqual(["https://won.example"]);
  });
});

describe(`${clause("L1 7.2")} two copies of a mind's keys that both change its identity`, () => {
  it("make the mind duplicitous for a client that asks the resolvers of both, and its log goes no further", async () => {
    const first = await made();
    first.mind.close();
    // Two machines with the same keystore, each asked to change the mind's identity at once:
    // one reaches resolver A only, the other resolver B only.
    const storage = first.storage;
    const twin = await Keystore.open({ storage: await clone(storage) });
    world.clock.at = at(200);
    const one = await Mind.open({ ...first.options, resolvers: [A] });
    const two = await Mind.open({ ...first.options, keystore: twin, resolvers: [B] });
    await one.update({ homes: ["https://one.example"] }, { control: first.lock });
    await two.update({ homes: ["https://two.example"] }, { control: first.lock });
    // A client that asks both resolvers sees both events: the mind signed twice.
    const resolved = await seenBy().resolve(one.address);
    expect(resolved.duplicitous).toBe(true);
    expect(resolved.log.entries).toHaveLength(1);
    // A machine that reaches both is refused when it tries to go on.
    one.close();
    two.close();
    const both = await Mind.open({ ...first.options, resolvers: [A, B] });
    expect(await refusal(() => both.update({}, { control: first.lock }))).toBe("oip: forbidden");
  });

  it("are told when the second of them publishes: a resolver holds another event at that position", async () => {
    const first = await made();
    first.mind.close();
    const twin = await Keystore.open({ storage: await clone(first.storage) });
    world.clock.at = at(200);
    const one = await Mind.open(first.options);
    const two = await Mind.open({ ...first.options, keystore: twin, fetch: world.direct });
    // Both have resolved the mind and found the log at its genesis. As the first is about to
    // publish its event, the second publishes another, to every resolver.
    let racing: Promise<unknown> | undefined;
    world.before = async (request) => {
      if (request.method !== "PUT") return;
      racing ??= two.update({ homes: ["https://two.example"] }, { control: first.lock });
      await racing;
    };
    const refused = await one
      .update({ homes: ["https://one.example"] }, { control: first.lock })
      .catch((thrown: unknown) => thrown);
    world.before = undefined;
    expect(refused).toBeInstanceOf(OipError);
    expect(refused).toMatchObject({ code: "duplicity" });
    // The resolvers saw the second machine's event first, and it has the position for everyone
    // who goes by them. They keep the other as evidence that the mind signed twice.
    const resolved = await seenBy().resolve(one.address);
    expect(resolved.state.homes).toStrictEqual(["https://two.example"]);
    expect(resolved.duplicitous).toBe(false);
    // The first machine publishes its event no more. Its keys for that position are destroyed,
    // and the log has moved on to a key it does not hold.
    world.clock.at = at(300);
    const asked = world.asked.length;
    expect(await refusal(() => one.update({}, { control: first.lock }))).toBe("oip: forbidden");
    expect(world.asked.slice(asked).filter((request) => request.startsWith("PUT"))).toStrictEqual(
      [],
    );
    const control = await controlOf(first.keystore, first.lock);
    expect(control.pending).toStrictEqual([]);
    expect(control.keys).toStrictEqual([]);
  });

  /** The same documents in another storage, as a copied directory is. */
  async function clone(storage: KeyStorage): Promise<KeyStorage> {
    const copy = memoryStorage();
    for (const name of await storage.list()) {
      const stored = await storage.get(name);
      if (stored !== undefined) await copy.put(name, stored.value, undefined);
    }
    return copy;
  }
});
