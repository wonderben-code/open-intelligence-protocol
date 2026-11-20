// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, keyHash, mindAddress, OipError, proofDigest } from "@oip/core";
import { judgeRecord, ownSignedTime } from "@oip/identity";
import {
  type Keychain,
  keychainLock,
  Keystore,
  type KeyStorage,
  type Lock,
  memoryStorage,
} from "@oip/keystore";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
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

/** A keychain that is a map: a lock that costs no key derivation. */
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

/** A keystore with nothing in it, its lock, and what a mind over it is made with. */
async function fresh(storage: KeyStorage = memoryStorage(), lock?: Lock) {
  const opening = lock ?? keychainLock(memoryKeychain(), "oip-test");
  const keystore = await Keystore.create({ storage, locks: opening });
  const options: MindOptions = {
    keystore,
    lock: opening,
    resolvers: [A, B],
    fetch: world.fetch,
    clock: world.clock,
  };
  return { keystore, lock: opening, options, storage };
}

/** What a call is refused with. */
async function refusal(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof OipError) return `oip: ${error.code}`;
    if (error instanceof TransportError) return `transport: ${error.failure}`;
    throw error;
  }
  throw new Error("nothing was refused");
}

/** The public keys a role of a keystore holds. */
async function held(keystore: Keystore, role: "control" | "operational", lock: Lock) {
  const keys = await keystore.unlock(role, lock);
  try {
    return keys.keys().map((key) => key.publicKey);
  } finally {
    keys.lock();
  }
}

/** Another client's view of a mind. */
const seenBy = (resolvers: readonly string[] = [A, B]) =>
  new Lookup({ resolvers, fetch: world.fetch, clock: world.clock });

describe("a mind of one's own", () => {
  it(`${clause("L1 3.11", "L1 7.4")} is made with a genesis that every resolver takes, and the control key that signed it is destroyed`, async () => {
    const { keystore, lock, options } = await fresh();
    const mind = await Mind.create(options, {
      kind: "agent",
      homes: ["https://host.example"],
      alsoKnownAs: ["https://ada.example"],
    });
    expect(mind.address).toMatch(/^did:oip:bciq/u);
    expect(keystore.mind).toBe(mind.address);
    expect(mind.publications).toStrictEqual([
      { resolver: A, taken: true },
      { resolver: B, taken: true },
    ]);
    expect(mind.state).toMatchObject({
      kind: "agent",
      seq: 0,
      homes: ["https://host.example"],
      alsoKnownAs: ["https://ada.example"],
      retired: false,
    });
    expect(mind.state.keys).toHaveLength(1);
    expect(mind.state.invocation).toHaveLength(1);
    expect(mind.state.agreement).toHaveLength(1);
    // Each resolver, asked by another client, serves the log, and it verifies.
    for (const resolver of [A, B]) {
      const other = await seenBy([resolver]).resolve(mind.address);
      expect(other.state.head).toBe(mind.state.head);
      expect(other.log.entries[0]?.time).toBe(at(100));
    }
    // The control key the genesis revealed is gone. The one it commits to is all that is left.
    mind.close();
    const control = await held(keystore, "control", lock);
    expect(control).toHaveLength(1);
    expect(mind.state.controller).toStrictEqual({
      kind: "key",
      next: control.map((key) => keyHash(key)),
      nextThreshold: 1,
    });
    const revealed = (mind.resolved.log.entries[0]?.event as { controller: { keys: string[] } })
      .controller.keys;
    expect(control).not.toContain(revealed[0]);
    // The operational key of the genesis is in the keystore.
    expect(await held(keystore, "operational", lock)).toStrictEqual([...mind.state.keys]);
  });

  it("is opened again from its keystore, and by nothing else", async () => {
    const { options, storage, lock } = await fresh();
    const made = await Mind.create(options, { kind: "agent" });
    made.close();
    // Another process: the keystore opened from storage, and the mind from the keystore.
    const keystore = await Keystore.open({ storage });
    const mind = await Mind.open({ ...options, keystore });
    expect(mind.address).toBe(made.address);
    expect(mind.state).toStrictEqual(made.state);
    expect(mind.publications).toStrictEqual([]);
    mind.close();
    // A keystore that holds no mind's keys yet, and one whose mind no resolver has.
    const empty = await fresh();
    expect(await refusal(() => Mind.open(empty.options))).toBe("oip: not-found");
    world.remove(A);
    world.remove(B);
    world.resolver(A);
    world.resolver(B);
    expect(await refusal(() => Mind.open({ ...options, keystore, lock }))).toBe("oip: not-found");
  });

  it("is made once from a keystore", async () => {
    const { options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    mind.close();
    expect(await refusal(() => Mind.create(options, { kind: "agent" }))).toBe("oip: forbidden");
  });

  it("is the same mind when a creation that stopped is begun again", async () => {
    const { keystore, lock, options } = await fresh();
    // No resolver can be reached: the genesis is signed, and not published.
    world.remove(A);
    world.remove(B);
    expect(await refusal(() => Mind.create(options, { kind: "agent" }))).toBe(
      "transport: unreachable",
    );
    expect(keystore.mind).toBeUndefined();
    const control = await keystore.unlock("control", lock);
    const [pending] = control.pending();
    control.lock();
    expect(pending?.["type"]).toBe("Genesis");
    // The roles were locked again, and the keys are where they were made.
    expect(await held(keystore, "operational", lock)).toHaveLength(1);
    // The resolvers are back. The mind that is made is the one whose genesis was signed.
    world.resolver(A);
    world.resolver(B);
    world.clock.at = at(500);
    const mind = await Mind.create(options, { kind: "service" });
    expect(mind.address).toBe(mindAddress(contentId(pending)));
    expect(mind.state.kind).toBe("agent");
    mind.close();
    expect(await held(keystore, "control", lock)).toHaveLength(1);
    expect(await held(keystore, "operational", lock)).toHaveLength(1);
  });

  it("is made with the keys an earlier call left, where it stopped before anything was signed", async () => {
    const { keystore, lock, options } = await fresh();
    const made: Record<string, string[]> = {};
    for (const role of ["control", "operational", "invocation", "agreement"] as const) {
      const keys = await keystore.unlock(role, lock);
      made[role] = [(await keys.generate()).publicKey];
      keys.lock();
    }
    const mind = await Mind.create(options, { kind: "agent" });
    const genesis = mind.resolved.log.entries[0]?.event as { controller: { keys: string[] } };
    expect(genesis.controller.keys).toStrictEqual(made["control"]);
    expect(mind.state.keys).toStrictEqual(made["operational"]);
    expect(mind.state.invocation).toStrictEqual(made["invocation"]);
    expect(mind.state.agreement).toStrictEqual(made["agreement"]);
  });

  it("is made if one resolver takes the genesis, and says which did not", async () => {
    const { options } = await fresh();
    world.remove(B);
    const mind = await Mind.create(options, { kind: "agent" });
    expect(mind.publications).toStrictEqual([
      { resolver: A, taken: true },
      { resolver: B, taken: false, failure: "unreachable" },
    ]);
    expect(mind.resolved.sources).toStrictEqual([
      { resolver: A, events: 1 },
      { resolver: B, events: undefined, failure: "unreachable" },
    ]);
  });
});

describe("what a mind signs", () => {
  it("counts for it, for a verifier that resolves the mind and has evidence of the proof", async () => {
    const { options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    world.clock.at = at(200);
    const intent = await mind.sign({
      oip: "1",
      type: "Intent",
      author: mind.address,
      created: T(200),
      want: "A translation.",
    });
    expect(intent.proof).toHaveLength(1);
    expect(intent.proof[0]?.verificationMethod).toBe(
      `${mind.address}?versionId=${mind.state.versionId}#${mind.signingKey()}`,
    );
    const other = seenBy();
    await other.resolve(mind.address);
    const judged = judgeRecord(intent);
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    // The other client first sees the proof at 210, after it last resolved the mind. The log
    // it holds is known up to 200: a key could have been removed since, and nothing counts.
    world.clock.at = at(210);
    other.seen.sawProof(proofDigest(intent.proof[0]), at(210));
    expect(ownSignedTime(judged.value, mind.address, other.view)).toBeUndefined();
    // Resolved again, the log is known up to now, and the proof counts from when it was seen.
    await other.resolve(mind.address);
    expect(ownSignedTime(judged.value, mind.address, other.view)).toBe(at(210));
  });

  it("is dated no earlier than the record, and after the proofs it already has", async () => {
    const { options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    // The record is dated ahead of this clock.
    const ahead = await mind.sign({
      oip: "1",
      type: "Intent",
      author: mind.address,
      created: T(160),
      want: "A translation.",
    });
    expect(ahead.proof[0]?.created).toBe(T(160));
    world.clock.at = at(300);
    const again = await mind.sign(ahead);
    expect(again.proof.map((proof) => proof.created)).toStrictEqual([T(160), T(300)]);
    expect(contentId(again)).toBe(contentId(ahead));
  });

  it("is nothing once the mind is closed", async () => {
    const { options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    mind.close();
    mind.close();
    await expect(
      mind.sign({ oip: "1", type: "Intent", author: mind.address, created: T(1), want: "x" }),
    ).rejects.toMatchObject({ code: "locked" });
  });
});

describe(`${clause("L1 3.7")} changing a mind's identity`, () => {
  it(`${clause("L1 3.11")} rotates the control keys with every event, and destroys the ones that signed`, async () => {
    const { keystore, lock, options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const before = await held(keystore, "control", lock);
    world.clock.at = at(200);
    const state = await mind.update({}, { control: lock });
    expect(state.seq).toBe(1);
    expect(mind.state).toStrictEqual(state);
    const after = await held(keystore, "control", lock);
    expect(after).toHaveLength(1);
    expect(after).not.toStrictEqual(before);
    expect(state.controller).toMatchObject({ next: after.map((key) => keyHash(key)) });
    // The event revealed the key the genesis committed to.
    const update = mind.resolved.log.entries[1]?.event as { controller: { keys: string[] } };
    expect(update.controller.keys).toStrictEqual(before);
    // And again, and every other client sees the log verify.
    world.clock.at = at(300);
    expect((await mind.update({}, { control: lock })).seq).toBe(2);
    const other = await seenBy().resolve(mind.address);
    expect(other.log.entries.map((entry) => entry.time)).toStrictEqual([at(100), at(200), at(300)]);
    expect(other.duplicitous).toBe(false);
  });

  it("changes what the event names, and leaves the rest", async () => {
    const { options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent", homes: ["https://old.example"] });
    const { keys, agreement, invocation } = mind.state;
    world.clock.at = at(200);
    const state = await mind.update(
      { homes: ["https://new.example"], alsoKnownAs: ["dns:ada.example"] },
      { control: lock },
    );
    expect(state).toMatchObject({
      homes: ["https://new.example"],
      alsoKnownAs: ["dns:ada.example"],
      keys,
      agreement,
      invocation,
    });
  });

  it("adds an operational key, which the mind's records may then be signed with", async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const [first] = mind.state.keys;
    world.clock.at = at(200);
    const added = await mind.addKey({ control: lock, label: "phone" });
    expect(mind.state.keys).toStrictEqual([first, added]);
    const update = mind.resolved.log.entries[1]?.event as { keys: object[] };
    expect(update.keys).toStrictEqual([{ key: first }, { key: added, label: "phone" }]);
    mind.close();
    expect(await held(keystore, "operational", lock)).toStrictEqual([first, added]);
  });

  it(`${clause("L1 6.2")} revokes an operational key: it signs nothing more, and what it signed from the time it was stolen is withdrawn`, async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const [first = ""] = mind.state.keys;
    // The last operational key is not revoked: the mind would sign nothing.
    expect(await refusal(() => mind.revokeKey(first, { control: lock }))).toBe("oip: forbidden");
    // One record signed at 150 and one at 190, with the key that is then found to have been
    // stolen at 180.
    const record = { oip: "1", type: "Intent", author: mind.address, want: "A translation." };
    world.clock.at = at(150);
    const early = await mind.sign({ ...record, created: T(150) });
    world.clock.at = at(190);
    const late = await mind.sign({ ...record, created: T(190) });
    world.clock.at = at(200);
    const second = await mind.addKey({ control: lock });
    world.clock.at = at(300);
    const state = await mind.revokeKey(first, { control: lock, compromisedSince: T(180) });
    expect(state.keys).toStrictEqual([second]);
    expect(mind.signingKey()).toBe(second);
    mind.close();
    expect(await held(keystore, "operational", lock)).toStrictEqual([second]);
    // Another client, with evidence that both proofs existed when they were made.
    const other = seenBy();
    await other.resolve(mind.address);
    const counted = [early, late].map((signed, index) => {
      const judged = judgeRecord(signed);
      if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
      other.seen.sawProof(proofDigest(signed.proof[0]), at(index === 0 ? 150 : 190));
      return ownSignedTime(judged.value, mind.address, other.view);
    });
    expect(counted).toStrictEqual([at(150), undefined]);
  });

  it(`${clause("L1 3.10")} retires the mind: no event follows, and it signs nothing`, async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    world.clock.at = at(200);
    const state = await mind.retire({ control: lock, reason: "Replaced." });
    expect(state.retired).toBe(true);
    expect(state.controller).toMatchObject({ next: [] });
    expect(await held(keystore, "control", lock)).toStrictEqual([]);
    expect(await refusal(() => mind.update({}, { control: lock }))).toBe("oip: forbidden");
    expect(() => mind.signingKey()).toThrow(OipError);
    expect((await seenBy().resolve(mind.address)).did.didDocumentMetadata.deactivated).toBe(true);
  });

  it(`${clause("L1 3.8")} acknowledges a child with a Fork`, async () => {
    const parent = await fresh();
    const mind = await Mind.create(parent.options, { kind: "agent" });
    const child = await Mind.create((await fresh()).options, { kind: "agent" });
    world.clock.at = at(200);
    const state = await mind.fork(child.address, {
      control: parent.lock,
      terms: { received: "the lease archive" },
    });
    expect(state.seq).toBe(1);
    expect(mind.resolved.log.children).toStrictEqual([{ position: 1, child: child.address }]);
    expect((await seenBy().resolve(mind.address)).did.didDocumentMetadata.children).toStrictEqual([
      child.address,
    ]);
  });

  it("dates an event no earlier than the one before it, whatever the clock says", async () => {
    const { options, lock } = await fresh();
    world.clock.at = at(500);
    const mind = await Mind.create(options, { kind: "agent" });
    // The clock was set back, by half a second.
    world.clock.at = at(499.5);
    await mind.update({}, { control: lock });
    const [genesis, update] = mind.resolved.log.entries.map((entry) => entry.event.created);
    expect([genesis, update]).toStrictEqual([T(500), T(500)]);
  });
});

describe("a change that is refused before it leaves", () => {
  it("binds no key where the event cannot be signed, and the mind changes its identity after", async () => {
    const { keystore, lock, options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const before = await held(keystore, "control", lock);
    const asked = world.asked.length;
    world.clock.at = at(200);
    const refused = await mind
      .update({ homes: ["not an origin"] }, { control: lock })
      .catch((thrown: unknown) => thrown);
    expect(refused).toBeInstanceOf(OipError);
    expect(refused).toMatchObject({ code: "invalid-record" });
    // Nothing was published, and the control keys are as they were: the key the event would
    // have committed to is gone again.
    expect(world.asked.slice(asked).filter((request) => request.startsWith("PUT"))).toStrictEqual(
      [],
    );
    expect(await held(keystore, "control", lock)).toStrictEqual(before);
    expect((await mind.update({ homes: ["https://home.example"] }, { control: lock })).seq).toBe(1);
  });

  it("frees the keys of an event that is well formed and does not verify", async () => {
    const { keystore, lock, options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const before = await held(keystore, "control", lock);
    const asked = world.asked.length;
    world.clock.at = at(200);
    // A key may not be both an operational and an invocation key (Layer 1, 3.5).
    const [invocation = ""] = mind.state.invocation;
    const refused = await mind
      .update(
        { keys: [...mind.state.keys.map((key) => ({ key })), { key: invocation }] },
        { control: lock },
      )
      .catch((thrown: unknown) => thrown);
    expect(refused).toBeInstanceOf(OipError);
    expect(refused).toMatchObject({ code: "invalid-record" });
    expect((refused as OipError).detail).toMatch(/^the event does not verify: /u);
    expect(world.asked.slice(asked).filter((request) => request.startsWith("PUT"))).toStrictEqual(
      [],
    );
    // The control key signed it and is free of it again, and the next key is gone.
    const control = await keystore.unlock("control", lock);
    expect(control.pending()).toStrictEqual([]);
    expect(control.keys().map((key) => key.publicKey)).toStrictEqual(before);
    control.lock();
    expect((await mind.update({}, { control: lock })).seq).toBe(1);
  });

  it("makes no mind from a genesis that cannot be signed, and makes one from the same keys after", async () => {
    const { keystore, lock, options } = await fresh();
    expect(
      await refusal(() => Mind.create(options, { kind: "agent", homes: ["not an origin"] })),
    ).toBe("oip: invalid-record");
    expect(keystore.mind).toBeUndefined();
    const control = await held(keystore, "control", lock);
    expect(control).toHaveLength(2);
    const mind = await Mind.create(options, { kind: "agent" });
    const genesis = mind.resolved.log.entries[0]?.event as { controller: { keys: string[] } };
    expect(genesis.controller.keys).toStrictEqual([control[0]]);
  });
});

describe("a resolver that takes a log and does not serve it yet", () => {
  it("leaves the event to be finished: its keys are kept until a resolver serves it", async () => {
    const { keystore, lock, options } = await fresh();
    const mind = await Mind.create({ ...options, resolvers: [A] }, { kind: "agent" });
    world.clock.at = at(200);
    // A resolver in front of a store that lags: it takes what is published, and serves what it had.
    const real = world.direct;
    let lagging = true;
    world.put(B, (request) =>
      request.method === "PUT" && lagging
        ? new Response('{"added":1}', {
            status: 202,
            headers: { "content-type": "application/json" },
          })
        : real(new Request(request.url.replace(B, A), request)),
    );
    mind.close();
    const slow = await Mind.open({ ...options, resolvers: [B] });
    expect(await refusal(() => slow.update({}, { control: lock }))).toBe("oip: invalid-proof");
    const control = await keystore.unlock("control", lock);
    expect(control.pending()).toHaveLength(1);
    expect(control.keys()).toHaveLength(2);
    control.lock();
    // The store has caught up. The next change publishes the event again, and it is served.
    lagging = false;
    expect((await slow.update({}, { control: lock })).seq).toBe(2);
    expect(await held(keystore, "control", lock)).toHaveLength(1);
  });

  it("does not take for a resolver's refusal what is nobody's answer", async () => {
    const { lock, options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const real = world.direct;
    const broken = (request: Request) =>
      request.method === "PUT"
        ? Promise.resolve({
            status: 202,
            body: null,
            headers: {
              get: () => {
                throw new RangeError("not a response");
              },
            },
          } as unknown as Response)
        : real(request);
    mind.close();
    const fragile = await Mind.open({ ...options, fetch: broken });
    await expect(fragile.update({}, { control: lock })).rejects.toThrow(RangeError);
  });
});

describe("a mind that is open", () => {
  it("goes by the clock of the machine, where it is given no other", async () => {
    const { options } = await fresh();
    // The resolvers of this test tell the time by the machine too.
    world.clock.at = BigInt(Date.now()) * 1_000_000n;
    const { clock: _, ...timeless } = options;
    const mind = await Mind.create(timeless, { kind: "agent" });
    const created = Date.parse(mind.resolved.log.entries[0]?.event.created ?? "");
    expect(Math.abs(created - Date.now())).toBeLessThan(60_000);
    const signed = await mind.sign({
      oip: "1",
      type: "Intent",
      author: mind.address,
      created: new Date(created).toISOString().replace(".000Z", "Z"),
      want: "A translation.",
    });
    expect(Math.abs(Date.parse(signed.proof[0]?.created ?? "") - Date.now())).toBeLessThan(60_000);
  });

  it("resolves other minds, and itself afresh", async () => {
    const one = await fresh();
    const two = await fresh();
    const ada = await Mind.create(one.options, { kind: "agent" });
    const bob = await Mind.create(two.options, { kind: "agent" });
    expect((await ada.lookup.resolve(bob.address)).state.head).toBe(bob.state.head);
    // Bob changes his identity on another machine. Ada's own view of herself is as it was
    // until she looks again.
    world.clock.at = at(200);
    await bob.update({ homes: ["https://bob.example"] }, { control: two.lock });
    expect((await ada.lookup.resolve(bob.address)).state.homes).toStrictEqual([
      "https://bob.example",
    ]);
    const head = ada.state.head;
    expect((await ada.refresh()).head).toBe(head);
    expect(ada.resolved.log.asOf).toBe(at(200));
  });

  it("holds its agreement keys unlocked, and locks them when it is closed", async () => {
    const { options } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    expect(mind.agreement.keys().map((key) => key.publicKey)).toStrictEqual([
      ...mind.state.agreement,
    ]);
    mind.close();
    expect(mind.agreement.locked).toBe(true);
  });

  it("is not opened by a lock that opens only some of its everyday keys, and leaves none unlocked", async () => {
    const storage = memoryStorage();
    const everyday = keychainLock(memoryKeychain(), "oip-test");
    const other = keychainLock(memoryKeychain(), "oip-other");
    const keystore = await Keystore.create({
      storage,
      locks: { control: everyday, operational: everyday, invocation: everyday, agreement: other },
    });
    const options: MindOptions = {
      keystore,
      lock: everyday,
      resolvers: [A, B],
      fetch: world.fetch,
      clock: world.clock,
    };
    // The agreement keys are under another lock: the mind cannot be made or opened with this one.
    await expect(Mind.create(options, { kind: "agent" })).rejects.toMatchObject({
      code: "not-opened",
    });
    // Every role is locked again.
    for (const role of ["control", "operational", "invocation"] as const) {
      (await keystore.unlock(role, everyday)).lock();
    }
    (await keystore.unlock("agreement", other)).lock();
  });

  it("is not opened where one of its everyday roles has another lock, and the other is locked again", async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    mind.close();
    await keystore.changeLock("agreement", lock, keychainLock(memoryKeychain(), "oip-other"));
    await expect(Mind.open(options)).rejects.toMatchObject({ code: "not-opened" });
    (await keystore.unlock("operational", lock)).lock();
  });

  it("signs with the first of its current keys that its keystore holds, and with none if it holds none", async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const [first = ""] = mind.state.keys;
    world.clock.at = at(200);
    const second = await mind.addKey({ control: lock });
    expect(mind.signingKey()).toBe(first);
    mind.close();
    // The first key is lost from this keystore: the mind signs with the second.
    const operational = await keystore.unlock("operational", lock);
    await operational.remove(first);
    operational.lock();
    const again = await Mind.open(options);
    expect(again.signingKey()).toBe(second);
    again.close();
    const emptied = await keystore.unlock("operational", lock);
    await emptied.remove(second);
    emptied.lock();
    const keyless = await Mind.open(options);
    expect(() => keyless.signingKey()).toThrow(OipError);
    await expect(
      keyless.sign({ oip: "1", type: "Intent", author: keyless.address, created: T(1), want: "x" }),
    ).rejects.toMatchObject({ code: "forbidden" });
  });
});

describe("the keys an identity event names", () => {
  it("keep the labels the log gave them when a key is added, and when one is added after an event that named none", async () => {
    const { options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const [first] = mind.state.keys;
    world.clock.at = at(200);
    const phone = await mind.addKey({ control: lock, label: "phone" });
    // An event that names no keys.
    await mind.update({ homes: ["https://home.example"] }, { control: lock });
    const laptop = await mind.addKey({ control: lock });
    const listed = (mind.resolved.log.entries.at(-1)?.event as { keys: object[] }).keys;
    expect(listed).toStrictEqual([{ key: first }, { key: phone, label: "phone" }, { key: laptop }]);
  });

  it("are replaced, set by set, by an update that names them", async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const agreed = await mind.agreement.generate();
    const invocation = await keystore.unlock("invocation", lock);
    const invoked = await invocation.generate({ label: "collectives" });
    invocation.lock();
    world.clock.at = at(200);
    const state = await mind.update(
      {
        agreement: [{ key: agreed.publicKey }],
        invocation: [{ key: invoked.publicKey, label: "collectives" }],
      },
      { control: lock },
    );
    expect(state.agreement).toStrictEqual([agreed.publicKey]);
    expect(state.invocation).toStrictEqual([invoked.publicKey]);
  });

  it("lose one that is revoked without a time, and one that another machine holds", async () => {
    const { keystore, options, lock } = await fresh();
    const mind = await Mind.create(options, { kind: "agent" });
    const [first = ""] = mind.state.keys;
    world.clock.at = at(200);
    const second = await mind.addKey({ control: lock });
    // A key of another machine's: in the log, and not in this keystore.
    const elsewhere = memoryStorage();
    const other = await Keystore.create({ storage: elsewhere, locks: lock });
    const theirs = await other.unlock("operational", lock);
    const remote = (await theirs.generate()).publicKey;
    await mind.update({ keys: [first, second, remote].map((key) => ({ key })) }, { control: lock });
    expect((await mind.revokeKey(remote, { control: lock })).keys).toStrictEqual([first, second]);
    const revoked = mind.resolved.log.entries.at(-1)?.event as { revoked: object[] };
    expect(revoked.revoked).toStrictEqual([{ key: remote }]);
    expect((await mind.revokeKey(first, { control: lock })).keys).toStrictEqual([second]);
    mind.close();
    expect(await held(keystore, "operational", lock)).toStrictEqual([second]);
  });
});

describe("a fork and a retirement", () => {
  it("say as much as they are given to say", async () => {
    const parent = await fresh();
    const mind = await Mind.create(parent.options, { kind: "agent" });
    const child = await Mind.create((await fresh()).options, { kind: "agent" });
    world.clock.at = at(200);
    await mind.fork(child.address, {
      control: parent.lock,
      changes: { homes: ["https://parent.example"] },
    });
    const fork = mind.resolved.log.entries[1]?.event as Record<string, unknown>;
    expect(fork["terms"]).toBeUndefined();
    expect(fork["homes"]).toStrictEqual(["https://parent.example"]);
    const state = await mind.retire({ control: parent.lock, successor: child.address });
    const retire = mind.resolved.log.entries[2]?.event as Record<string, unknown>;
    expect(retire["successor"]).toBe(child.address);
    expect(retire["reason"]).toBeUndefined();
    expect(state.retired).toBe(true);
  });
});
