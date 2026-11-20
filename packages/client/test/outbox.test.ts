// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { utf8 } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { type Inbox, MAX_QUEUED, type Message, Mind, type MindOptions } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";
const THREE = "https://host-three.example";
const SECOND = 1_000_000_000n;

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
  world.host(ONE);
  world.host(TWO);
  world.host(THREE);
});
afterEach(() => {
  world.close();
});

async function at_(home: string, more: Partial<MindOptions> = {}) {
  const made = await freshKeystore(world, [A], more);
  const mind = await Mind.create(made.options, { kind: "agent", homes: [home] });
  await mind.publishLocation();
  return { ...made, mind };
}

async function pair() {
  const ada = await at_(ONE);
  const bob = await at_(TWO);
  world.clock.at = at(160);
  return { ada, bob };
}

const later = (seconds: number): void => {
  world.clock.at += BigInt(seconds) * SECOND;
};

const hello = (to: readonly string[], body = "Hello.", more: Partial<Message> = {}): Message => ({
  to,
  verb: "inform",
  content: { mediaType: "text/plain", body },
  ...more,
});

/** Sends while a host cannot be reached. */
async function unreached<T>(host: string, send: () => Promise<T>): Promise<T> {
  world.down(host);
  try {
    return await send();
  } finally {
    world.up(host);
  }
}

const bodies = (inbox: Inbox): unknown[] =>
  inbox.received.map(({ packet }) => {
    const parts = "parts" in packet.content ? packet.content.parts : [packet.content];
    const text = parts.find((part) => part.mediaType === "text/plain");
    return text !== undefined && "body" in text ? text.body : packet.purpose.verb;
  });

describe(`${clause("L1 15.3")} a packet that no endpoint of its recipient took`, () => {
  it("is kept, where it may yet arrive, and tried again when the mind says", async () => {
    const { ada, bob } = await pair();
    const sent = await unreached(TWO, () => ada.mind.send(hello([bob.mind.address])));
    expect(sent.deliveries).toStrictEqual([
      { to: bob.mind.address, sealed: true, stored: false, failure: "unreachable", queued: true },
    ]);
    expect(await ada.mind.outbox()).toStrictEqual([
      {
        id: sent.id,
        packet: sent.packet,
        to: [{ mind: bob.mind.address, failure: "unreachable" }],
        sealed: true,
        tries: 1,
        next: at(190),
      },
    ]);
    // Bob's host is back.
    const retried = await ada.mind.retry();
    expect(retried).toMatchObject([
      {
        id: sent.id,
        deliveries: [{ to: bob.mind.address, sealed: true, stored: true }],
        waiting: 0,
        expired: false,
      },
    ]);
    expect(await ada.mind.outbox()).toStrictEqual([]);
    expect(await ada.mind.retry()).toStrictEqual([]);
    later(10);
    // It is the packet that was signed, and it arrives once.
    const inbox = await bob.mind.receive();
    expect(inbox.received.map(({ id, packet }) => ({ id, packet }))).toStrictEqual([
      { id: sent.id, packet: sent.packet },
    ]);
  });

  it("is tried again by itself when the mind next reads, each time after twice as long, up to an hour", async () => {
    const { ada, bob } = await pair();
    world.down(TWO);
    const sent = await ada.mind.send(hello([bob.mind.address], "Hello.", { expiresIn: 604_800 }));
    // Not yet due: nothing is tried.
    later(29);
    expect((await ada.mind.receive()).retried).toStrictEqual([]);
    expect((await ada.mind.outbox())[0]?.tries).toBe(1);
    // Due, and still nobody there. The next wait is twice as long.
    let waited = 30;
    later(1);
    for (let tries = 2; tries <= 10; tries++) {
      const { retried } = await ada.mind.receive();
      expect(retried, String(tries)).toMatchObject([
        { id: sent.id, deliveries: [{ stored: false, failure: "unreachable" }], waiting: 1 },
      ]);
      waited = Math.min(waited * 2, 3600);
      const [queued] = await ada.mind.outbox();
      expect(queued).toMatchObject({ tries, next: world.clock.at + BigInt(waited) * SECOND });
      later(waited - 1);
      expect((await ada.mind.receive()).retried).toStrictEqual([]);
      later(1);
    }
    expect(waited).toBe(3600);
    world.up(TWO);
    expect((await ada.mind.receive()).retried).toMatchObject([
      { deliveries: [{ stored: true }], waiting: 0 },
    ]);
    later(10);
    expect((await bob.mind.receive()).received).toHaveLength(1);
  });

  it(`${clause("L1 12.4")} is dropped once it has expired: nobody would accept it then`, async () => {
    const { ada, bob } = await pair();
    world.down(TWO);
    const sent = await ada.mind.send(hello([bob.mind.address], "Soon.", { expiresIn: 60 }));
    expect(sent.packet.expires).toBe(T(220));
    // Five minutes past its time it is still accepted, and so still tried.
    world.clock.at = at(520);
    expect(await ada.mind.retry()).toMatchObject([{ waiting: 1, expired: false }]);
    world.clock.at = at(521);
    expect(await ada.mind.retry()).toStrictEqual([
      { id: sent.id, deliveries: [], waiting: 0, expired: true },
    ]);
    expect(await ada.mind.outbox()).toStrictEqual([]);
    // One that is not yet due is dropped as well, when the mind next reads.
    await ada.mind.send(hello([bob.mind.address], "Sooner.", { expiresIn: 1 }));
    later(302);
    expect((await ada.mind.receive()).retried).toMatchObject([{ expired: true }]);
  });

  it("is kept for the recipients it did not reach, and for no other", async () => {
    const { ada, bob } = await pair();
    const cyd = await at_(THREE);
    const dee = await at_(THREE);
    world.clock.at = at(200);
    const to = [bob.mind.address, cyd.mind.address, dee.mind.address];
    const sent = await unreached(THREE, () => ada.mind.send(hello(to, "To three.")));
    expect(sent.deliveries.map(({ stored, queued }) => ({ stored, queued }))).toStrictEqual([
      { stored: true, queued: undefined },
      { stored: false, queued: true },
      { stored: false, queued: true },
    ]);
    expect((await ada.mind.outbox())[0]?.to).toStrictEqual([
      { mind: cyd.mind.address, failure: "unreachable" },
      { mind: dee.mind.address, failure: "unreachable" },
    ]);
    // Cyd can be reached again, and Dee has since said she takes no packets anywhere.
    await dee.mind.publishLocation({ endpoints: [] });
    later(40);
    const retried = await ada.mind.retry();
    expect(retried).toMatchObject([
      {
        deliveries: [
          { to: cyd.mind.address, stored: true },
          { to: dee.mind.address, stored: false, failure: "not-found" },
        ],
        waiting: 1,
      },
    ]);
    expect(await ada.mind.outbox()).toMatchObject([
      { tries: 2, to: [{ mind: dee.mind.address, failure: "not-found" }] },
    ]);
    later(10);
    expect(bodies(await cyd.mind.receive())).toStrictEqual(["To three."]);
    expect(bodies(await bob.mind.receive())).toStrictEqual(["To three."]);
  });

  it("is not kept where it was refused for what it is, or where the sender says not to keep it", async () => {
    const { ada, bob } = await pair();
    // A recipient the packet cannot be sealed to: it has no agreement key.
    const bare = await freshKeystore(world, [A]);
    const plain = await Mind.create(bare.options, { kind: "agent", homes: [THREE] });
    await plain.publishLocation();
    await plain.update({ agreement: [] }, { control: bare.lock });
    later(10);
    const sealed = await ada.mind.send(hello([plain.address]));
    expect(sealed.deliveries).toStrictEqual([
      { to: plain.address, sealed: true, stored: false, failure: "invalid-record" },
    ]);
    const unkept = await unreached(TWO, () =>
      ada.mind.send(hello([bob.mind.address], "Hello.", { queue: false })),
    );
    expect(unkept.deliveries).toStrictEqual([
      { to: bob.mind.address, sealed: true, stored: false, failure: "unreachable" },
    ]);
    expect(await ada.mind.outbox()).toStrictEqual([]);
  });

  it("is given up for a recipient that now refuses it for what it is", async () => {
    const { ada, bob } = await pair();
    const sent = await unreached(TWO, () => ada.mind.send(hello([bob.mind.address])));
    // Bob removes the key the packet would be sealed to, and has no other.
    await bob.mind.update({ agreement: [] }, { control: bob.lock });
    later(40);
    expect(await ada.mind.retry()).toMatchObject([
      { id: sent.id, deliveries: [{ stored: false, failure: "invalid-record" }], waiting: 0 },
    ]);
    expect(await ada.mind.outbox()).toStrictEqual([]);
  });

  it("is given up when the mind says so", async () => {
    const { ada, bob } = await pair();
    const sent = await unreached(TWO, () => ada.mind.send(hello([bob.mind.address])));
    expect(await ada.mind.abandon(sent.id)).toBe(true);
    expect(await ada.mind.abandon(sent.id)).toBe(false);
    expect(await ada.mind.outbox()).toStrictEqual([]);
    expect(await ada.mind.retry()).toStrictEqual([]);
    later(10);
    expect((await bob.mind.receive()).received).toStrictEqual([]);
  });
});

describe("the outbox and a session", () => {
  it(`${clause("L1 14.2", "L1 14.3")} sends the first packet of a chain again, and the session is taken up in order`, async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    const say = (body: string): Message => ({ ...hello(to, body), session: id });
    const one = await unreached(TWO, () => ada.mind.send(say("One.")));
    expect(one.deliveries).toMatchObject([{ stored: false, queued: true }]);
    await ada.mind.send(say("Two."));
    await ada.mind.send(say("Three."));
    // The first arrives last. It names the session, and the others are not judged before it.
    expect(await ada.mind.retry()).toMatchObject([{ deliveries: [{ stored: true }] }]);
    later(10);
    const inbox = await bob.mind.receive();
    expect(bodies(inbox)).toStrictEqual(["One.", "Two.", "Three."]);
    expect(inbox.refused).toStrictEqual([]);
    expect(inbox.sessions).toStrictEqual([]);
  });

  it("gives up the packets of a session the mind leaves", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const other = await ada.mind.openSession([bob.mind.address]);
    world.down(TWO);
    await ada.mind.send({ ...hello([bob.mind.address]), session: id });
    const kept = await ada.mind.send({ ...hello([bob.mind.address]), session: other.id });
    await ada.mind.send(hello([bob.mind.address], "Outside any session."));
    expect(await ada.mind.outbox()).toHaveLength(3);
    expect(await ada.mind.leaveSession(id)).toBe(true);
    const waiting = await ada.mind.outbox();
    expect(waiting).toHaveLength(2);
    expect(waiting.map((queued) => queued.id)).toContain(kept.id);
    // A packet of a session states no time after which it is refused: it waits until it arrives.
    later(30 * 24 * 3600);
    expect((await ada.mind.retry()).filter((retried) => retried.expired)).toHaveLength(1);
    expect((await ada.mind.outbox()).map((queued) => queued.id)).toStrictEqual([kept.id]);
  });
});

describe("what the client keeps of its outbox", () => {
  it("is bounded: past the bound a packet that does not arrive is told so, and not kept", async () => {
    const { ada, bob } = await pair();
    const list = ada.memory.list.bind(ada.memory);
    ada.memory.list = async () => [
      ...(await list()),
      ...Array.from({ length: MAX_QUEUED }, (_, n) => `client-out-${String(n).padStart(21, "a")}`),
    ];
    const sent = await unreached(TWO, () => ada.mind.send(hello([bob.mind.address])));
    expect(sent.deliveries).toStrictEqual([
      { to: bob.mind.address, sealed: true, stored: false, failure: "unreachable" },
    ]);
    ada.memory.list = list;
    expect(await ada.mind.outbox()).toStrictEqual([]);
    expect(MAX_QUEUED).toBe(1000);
  });

  it("is another process's to tell where that one tried a packet at the same time", async () => {
    const { ada, bob } = await pair();
    await unreached(TWO, () => ada.mind.send(hello([bob.mind.address])));
    const forget = ada.memory.delete.bind(ada.memory);
    ada.memory.delete = () => Promise.reject(new KeystoreError("changed", "another wrote it"));
    expect(await ada.mind.retry()).toStrictEqual([]);
    // A storage that fails otherwise is the mind's to know of.
    ada.memory.delete = () => Promise.reject(new KeystoreError("damaged", "the disk is gone"));
    expect(await refusal(() => ada.mind.retry())).toBe("keystore: damaged");
    ada.memory.delete = forget;
    // It arrived each time. What is left waiting is tried once more, and is a duplicate there.
    expect(await ada.mind.retry()).toMatchObject([{ deliveries: [{ stored: true }], waiting: 0 }]);
    later(10);
    expect((await bob.mind.receive()).received).toHaveLength(1);
  });

  it("is damaged where it cannot be read, and the client says so", async () => {
    const { ada, bob } = await pair();
    const sent = await unreached(TWO, () => ada.mind.send(hello([bob.mind.address])));
    const [name] = (await ada.memory.list()).filter((held) => held.startsWith("client-out-"));
    if (name === undefined) throw new Error("nothing was kept");
    const held = await ada.memory.get(name);
    const document = JSON.parse(new TextDecoder().decode(held?.value)) as Record<string, unknown>;
    let version = held?.version;
    for (const broken of [
      { ...document, packet: { oip: "1" } },
      { ...document, to: "bob" },
      { ...document, to: [null] },
      { ...document, to: [{ mind: bob.mind.address }] },
      { ...document, to: [{ mind: 7, failure: "unreachable" }] },
      { ...document, sealed: "yes" },
      { ...document, tries: 0 },
      { ...document, tries: 1.5 },
      { ...document, tries: "1" },
      { ...document, next: 7 },
      { ...document, next: "soon" },
    ]) {
      version = await ada.memory.put(name, utf8(JSON.stringify(broken)), version);
      expect(await refusal(() => ada.mind.outbox()), JSON.stringify(broken)).toBe(
        "keystore: damaged",
      );
    }
    expect(await refusal(() => ada.mind.retry())).toBe("keystore: damaged");
    expect(await refusal(() => ada.mind.abandon(sent.id))).toBe("keystore: damaged");
    await ada.memory.put(name, utf8(JSON.stringify(document)), version);
    expect(await ada.mind.outbox()).toHaveLength(1);
    // A packet kept under a name that is not its own is not the one asked about.
    expect(await ada.mind.abandon(sent.id.slice(0, 25) + "a".repeat(sent.id.length - 25))).toBe(
      false,
    );
    // One that went while the outbox was being read is no longer there to tell of.
    const list = ada.memory.list.bind(ada.memory);
    ada.memory.list = async () => [...(await list()), "client-out-aaaaaaaaaaaaaaaaaaaaa"];
    expect(await ada.mind.outbox()).toHaveLength(1);
    expect(await ada.mind.retry()).toHaveLength(1);
  });
});
