// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, MEDIA_TYPE, mindId, utf8 } from "@oip/core";
import { Keystore } from "@oip/keystore";
import { clause } from "@oip/testkit";
import { at, KeyMind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { type Inbox, type Message, Mind, type MindOptions, type Sent } from "../src/index.ts";
import { copyOf, freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const ONE = "https://host-one.example";
const TWO = "https://host-two.example";
const THREE = "https://host-three.example";

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

/** A mind at a home, which has said where it takes packets. */
async function at_(home: string, more: Partial<MindOptions> = {}) {
  const made = await freshKeystore(world, [A], more);
  const mind = await Mind.create(made.options, { kind: "agent", homes: [home] });
  await mind.publishLocation();
  return { ...made, mind };
}

/** Ada and Bob, each at a host, a minute after they were made. */
async function pair(more: Partial<MindOptions> = {}) {
  const ada = await at_(ONE, more);
  const bob = await at_(TWO);
  world.clock.at = at(160);
  return { ada, bob };
}

/** Lets time pass: ten seconds, unless told otherwise. */
const later = (seconds = 10): void => {
  world.clock.at += BigInt(seconds) * 1_000_000_000n;
};

const say = (session: string, to: readonly string[], body: string, more: Partial<Message> = {}) =>
  ({
    to,
    verb: "inform",
    content: { mediaType: "text/plain", body },
    session,
    ...more,
  }) satisfies Message;

/** Sends while a host is down: the packet is signed, has its place, and reaches nobody there. */
async function lost(host: string, send: () => Promise<Sent>): Promise<Sent> {
  world.down(host);
  try {
    return await send();
  } finally {
    world.up(host);
  }
}

/** A mind's mailbox at its home, which keeps what it is given for the mind to judge (13.5). */
const mailboxOf = (home: string, mind: Mind): string =>
  `${home}/oip/v1/minds/${mindId(mind.address) ?? ""}/mailbox`;

/** Posts a record to a URL, as anyone may. */
const post = async (url: string, record: unknown): Promise<number> =>
  (
    await world.direct(
      new Request(url, {
        method: "POST",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify(record),
      }),
    )
  ).status;

const bodies = (inbox: Inbox): unknown[] =>
  inbox.received.map(({ packet }) =>
    "body" in packet.content
      ? packet.content.body
      : "parts" in packet.content
        ? packet.content.parts.map((part) => ("body" in part ? part.body : part.ref))
        : packet.content.ref,
  );
const kinds = (inbox: Inbox): string[] => inbox.sessions.map((event) => event.kind);

describe(`${clause("L1 14.1")} a session`, () => {
  it("is named by an unsigned record of its participants, the mind that makes it among them", async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    expect(session).toStrictEqual({
      oip: "1",
      type: "Session",
      participants: [ada.mind.address, bob.mind.address].sort(),
      nonce: session.nonce,
      created: T(160),
    });
    expect(session.nonce).toMatch(/^[A-Za-z0-9_-]{22}$/u);
    expect(id).toBe(contentId(session));
    expect(await ada.mind.sessions()).toStrictEqual([{ id, session, sent: 0, chains: [] }]);
    // Naming oneself changes nothing, and each session is another.
    const again = await ada.mind.openSession([bob.mind.address, ada.mind.address]);
    expect(again.session.participants).toStrictEqual(session.participants);
    expect(again.id).not.toBe(id);
    expect(await ada.mind.sessions()).toHaveLength(2);
    // Nothing was sent.
    expect((await bob.mind.receive()).received).toStrictEqual([]);
  });

  it("is of two minds at least, each named by its address", async () => {
    const { ada } = await pair();
    expect(await refusal(() => ada.mind.openSession([]))).toBe("oip: invalid-record");
    expect(await refusal(() => ada.mind.openSession([ada.mind.address]))).toBe(
      "oip: invalid-record",
    );
    expect(await refusal(() => ada.mind.openSession(["bob"]))).toBe("oip: invalid-record");
    expect(await ada.mind.sessions()).toStrictEqual([]);
  });

  it("is not kept where the client's memory does not take it", async () => {
    const { ada, bob } = await pair();
    const put = ada.memory.put.bind(ada.memory);
    ada.memory.put = () => Promise.reject(new Error("the disk is full"));
    await expect(ada.mind.openSession([bob.mind.address])).rejects.toThrow("the disk is full");
    ada.memory.put = put;
    expect(await ada.mind.sessions()).toStrictEqual([]);
  });
});

describe(`${clause("L1 14.2", "L1 14.3")} a packet sent in a session`, () => {
  it("has the next place in its sender's chain, and the first carries the Session record", async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    const first = await ada.mind.send(say(id, to, "One."));
    const second = await ada.mind.send(say(id, to, "Two."));
    const third = await ada.mind.send(say(id, to, "Three."));
    expect(first.packet).toMatchObject({
      session: id,
      seq: 0,
      content: {
        parts: [
          { mediaType: MEDIA_TYPE, body: session },
          { mediaType: "text/plain", body: "One." },
        ],
      },
    });
    expect(first.packet.prev).toBeUndefined();
    expect(second.packet).toMatchObject({
      session: id,
      seq: 1,
      prev: first.id,
      content: { mediaType: "text/plain", body: "Two." },
    });
    expect(third.packet).toMatchObject({ seq: 2, prev: second.id });
    // It states no time after which it is refused: it can be sent again while the session lasts.
    for (const { packet } of [first, second, third]) {
      expect(packet.expires).toBeUndefined();
      expect(packet.instance).toBeUndefined();
    }
    expect((await ada.mind.sessions())[0]).toMatchObject({ id, sent: 3 });
  });

  it("carries the Session record once: content that has it already is left as it is", async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    const content = { mediaType: MEDIA_TYPE, body: session };
    const opening = await ada.mind.send({
      to: [bob.mind.address],
      verb: "open",
      content,
      session: id,
    });
    expect(opening.packet.content).toStrictEqual(content);
    // Another session's record is content like any other.
    const other = await ada.mind.openSession([bob.mind.address]);
    const sent = await ada.mind.send({
      to: [bob.mind.address],
      verb: "inform",
      content: {
        parts: [
          content,
          {
            mediaType: "text/plain",
            ref: "https://x.example/a",
            digest: `sha256:${"0".repeat(64)}`,
          },
        ],
      },
      session: other.id,
    });
    expect(sent.packet.content).toMatchObject({
      parts: [{ body: other.session }, { body: session }, { ref: "https://x.example/a" }],
    });
  });

  it("is addressed to every other participant, and is a packet of a session the mind is in", async () => {
    const { ada, bob } = await pair();
    const cyd = await at_(THREE);
    const { id } = await ada.mind.openSession([bob.mind.address, cyd.mind.address]);
    const one = say(id, [bob.mind.address], "For one of two.");
    expect(await refusal(() => ada.mind.send(one))).toBe("oip: invalid-record");
    expect(
      await refusal(() => ada.mind.send({ ...one, to: { query: { tags: ["translation"] } } })),
    ).toBe("oip: invalid-record");
    expect((await ada.mind.sessions())[0]?.sent).toBe(0);
    const all = await ada.mind.send({ ...one, to: [cyd.mind.address, bob.mind.address] });
    expect(all.packet.seq).toBe(0);
    // More may be told than take part.
    const dee = await at_(THREE);
    const more = await ada.mind.send({
      ...one,
      to: [bob.mind.address, cyd.mind.address, dee.mind.address],
    });
    expect(more.packet).toMatchObject({ seq: 1, prev: all.id });
    expect(
      await refusal(() => ada.mind.send(say(contentId({ a: 1 }), [bob.mind.address], "?"))),
    ).toBe("oip: not-found");
    expect(await refusal(() => ada.mind.resume(contentId({ a: 1 })))).toBe("oip: not-found");
  });

  it("may state when it expires, and names the instance of a mind that runs several", async () => {
    const { ada, bob } = await pair({ instance: "laptop" });
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const sent = await ada.mind.send(say(id, [bob.mind.address], "Soon.", { expiresIn: 60 }));
    expect(sent.packet).toMatchObject({ instance: "laptop", seq: 0, expires: T(220) });
    expect(
      await refusal(() => ada.mind.send(say(id, [bob.mind.address], "Never.", { expiresIn: 0 }))),
    ).toBe("oip: invalid-record");
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received).toHaveLength(1);
    expect((await bob.mind.sessions())[0]?.chains).toStrictEqual([
      { mind: ada.mind.address, instance: "laptop", received: 1 },
    ]);
    // A Resume names the instance of each chain it speaks of: the mind's own, and another's.
    expect((await ada.mind.resume(id)).packet.content).toMatchObject({
      body: { lastSent: { seq: 0, packet: sent.id, instance: "laptop" }, lastReceived: [] },
    });
    expect((await bob.mind.resume(id)).packet.content).toMatchObject({
      parts: [
        {},
        { body: { lastReceived: [{ mind: ada.mind.address, instance: "laptop", seq: 0 }] } },
      ],
    });
  });

  it("is no instance that is not a name of 64 characters at most", async () => {
    const made = await freshKeystore(world, [A]);
    const options = (instance: unknown) => ({ ...made.options, instance }) as MindOptions;
    await expect(Mind.create(options(7), { kind: "agent" })).rejects.toThrow(TypeError);
    await expect(Mind.create(options("i".repeat(65)), { kind: "agent" })).rejects.toThrow(
      "an instance is named by a string of at most 64 characters",
    );
    // Nothing was made of the mind.
    expect(made.keystore.mind).toBeUndefined();
    const mind = await Mind.create(options("i".repeat(64)), { kind: "agent" });
    mind.close();
    await expect(Mind.open(options({}))).rejects.toThrow(TypeError);
  });
});

describe(`${clause("L1 14.3")} the packets of a session that arrive`, () => {
  it("are returned in the order of their sender's chain, and the session is followed from the first", async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    const one = await ada.mind.send(say(id, [bob.mind.address], "One."));
    const two = await ada.mind.send(say(id, [bob.mind.address], "Two."));
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received.map((received) => received.id)).toStrictEqual([one.id, two.id]);
    expect(inbox.received.every((received) => received.sealed)).toBe(true);
    expect(inbox.sessions).toStrictEqual([]);
    expect(await bob.mind.sessions()).toStrictEqual([
      { id, session, sent: 0, chains: [{ mind: ada.mind.address, received: 2 }] },
    ]);
    // Bob answers in the session he was told of: his first packet carries the record too.
    const answer = await bob.mind.send(say(id, [ada.mind.address], "And three."));
    expect(answer.packet).toMatchObject({
      session: id,
      seq: 0,
      content: { parts: [{ body: session }, { body: "And three." }] },
    });
    later();
    expect(bodies(await ada.mind.receive())).toStrictEqual([[session, "And three."]]);
    expect((await ada.mind.sessions())[0]).toMatchObject({
      sent: 2,
      chains: [{ mind: bob.mind.address, received: 1 }],
    });
    // Nothing is left to read.
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it(`${clause("L1 14.2")} are refused where the session cannot be checked: its record was never seen`, async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    await lost(TWO, () => ada.mind.send(say(id, [bob.mind.address], "One.")));
    await ada.mind.send(say(id, [bob.mind.address], "Two."));
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received).toStrictEqual([]);
    expect(inbox.refused).toMatchObject([{ clause: "L1 14.2" }]);
    expect(await bob.mind.sessions()).toStrictEqual([]);
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it(`${clause("L1 14.4")} wait for one that is missing, which a Resume asks for and its sender sends again`, async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    const one = await ada.mind.send(say(id, to, "One."));
    const two = await lost(TWO, () => ada.mind.send(say(id, to, "Two.")));
    expect(two.deliveries).toMatchObject([{ stored: false, failure: "unreachable" }]);
    const three = await ada.mind.send(say(id, to, "Three."));
    const four = await ada.mind.send(say(id, to, "Four.", { seal: false }));
    later();
    // Bob has the first. The third and fourth are ahead of a gap: he asks, once.
    const first = await bob.mind.receive();
    expect(first.received.map((received) => received.id)).toStrictEqual([one.id]);
    expect(first.sources[0]?.items).toBe(3);
    expect(first.sessions).toMatchObject([
      { kind: "gap", session: id, mind: ada.mind.address, next: 1 },
      { kind: "asked", session: id },
    ]);
    const asked = first.sessions[1];
    if (asked?.kind !== "asked") throw new Error("no Resume was sent");
    expect(asked.sent.packet).toMatchObject({
      from: bob.mind.address,
      to: [ada.mind.address],
      session: id,
      seq: 0,
      purpose: { verb: "resume" },
      content: {
        parts: [
          { mediaType: MEDIA_TYPE, body: session },
          {
            mediaType: MEDIA_TYPE,
            body: {
              oip: "1",
              type: "Resume",
              session: id,
              lastReceived: [{ mind: ada.mind.address, seq: 0, packet: one.id }],
              created: T(170),
            },
          },
        ],
      },
    });
    expect(asked.sent.deliveries).toMatchObject([{ stored: true }]);
    // What waits stays in the mailbox, and the gap is told again without another Resume.
    later();
    const second = await bob.mind.receive();
    expect(second.received).toStrictEqual([]);
    expect(second.sources[0]?.items).toBe(2);
    expect(kinds(second)).toStrictEqual(["gap"]);
    // Ada reads the Resume, and sends again what Bob lacks, as it was.
    const answered = await ada.mind.receive();
    expect(answered.received.map((received) => received.packet.purpose.verb)).toStrictEqual([
      "resume",
    ]);
    expect(answered.sessions).toMatchObject([
      {
        kind: "sent-again",
        session: id,
        to: bob.mind.address,
        from: 1,
        deliveries: [
          { stored: true, sealed: true },
          { stored: true, sealed: true },
          { stored: true, sealed: false },
        ],
      },
    ]);
    // Bob now has them all, in order, each once.
    later();
    const third = await bob.mind.receive();
    expect(third.received.map((received) => received.id)).toStrictEqual([
      two.id,
      three.id,
      four.id,
    ]);
    expect(third.received.map((received) => received.sealed)).toStrictEqual([true, true, false]);
    expect(third.received[0]?.packet).toStrictEqual(two.packet);
    expect(third.sessions).toStrictEqual([]);
    expect(third.refused).toStrictEqual([]);
    expect((await bob.mind.sessions())[0]).toMatchObject({
      sent: 1,
      chains: [{ mind: ada.mind.address, received: 4 }],
    });
    const fourth = await bob.mind.receive();
    expect(fourth).toMatchObject({ received: [], refused: [], sessions: [] });
    expect(fourth.sources[0]?.items).toBe(0);
  });

  it(`${clause("L1 14.4")} are asked for again by a Resume the mind sends itself`, async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const one = await ada.mind.send(say(id, [bob.mind.address], "One."));
    later();
    await bob.mind.receive();
    const hello = await bob.mind.send(say(id, [ada.mind.address], "Hello."));
    const resume = await bob.mind.resume(id);
    expect(resume.packet).toMatchObject({
      seq: 1,
      prev: hello.id,
      purpose: { verb: "resume" },
      content: {
        mediaType: MEDIA_TYPE,
        body: {
          type: "Resume",
          session: id,
          lastSent: { seq: 0, packet: hello.id },
          lastReceived: [{ mind: ada.mind.address, seq: 0, packet: one.id }],
        },
      },
    });
    // Ada lacks nothing and Bob lacks nothing: nothing is sent again.
    later();
    const inbox = await ada.mind.receive();
    expect(inbox.received).toHaveLength(2);
    expect(inbox.sessions).toStrictEqual([]);
    // A mind that has received nothing says so.
    const fresh = await ada.mind.openSession([bob.mind.address]);
    expect((await ada.mind.resume(fresh.id)).packet.content).toMatchObject({
      parts: [{ body: fresh.session }, { body: { type: "Resume", lastReceived: [] } }],
    });
  });

  it(`${clause("L1 12.4")} are taken however old, while the chain they belong to is held`, async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    await ada.mind.send(say(id, to, "One."));
    const two = await lost(TWO, () => ada.mind.send(say(id, to, "Two.")));
    later();
    expect((await bob.mind.receive()).received).toHaveLength(1);
    // Eight days on, Ada writes again, and Bob finds what he missed.
    later(8 * 24 * 3600);
    const three = await ada.mind.send(say(id, to, "Three."));
    later();
    expect(kinds(await bob.mind.receive())).toStrictEqual(["gap", "asked"]);
    expect(kinds(await ada.mind.receive())).toStrictEqual(["sent-again"]);
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received.map((received) => received.id)).toStrictEqual([two.id, three.id]);
    expect(inbox.refused).toStrictEqual([]);
  });

  it(`${clause("L1 12.4")} open a session for seven days, and no longer`, async () => {
    const { ada, bob } = await pair();
    const cyd = await at_(THREE);
    world.clock.at = at(200);
    const forBob = await ada.mind.openSession([bob.mind.address]);
    const forCyd = await ada.mind.openSession([cyd.mind.address]);
    await ada.mind.send(say(forBob.id, [bob.mind.address], "One."));
    await ada.mind.send(say(forCyd.id, [cyd.mind.address], "One."));
    later(7 * 24 * 3600 - 60);
    expect((await bob.mind.receive()).received).toHaveLength(1);
    later(120);
    const late = await cyd.mind.receive();
    expect(late.received).toStrictEqual([]);
    expect(late.refused).toMatchObject([{ clause: "L1 12.4" }]);
  });
});

describe(`${clause("L1 14.4")} a Resume that arrives`, () => {
  /** Ada and Bob in a session in which each has sent one packet, and read the other's. */
  async function talking() {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const one = await ada.mind.send(say(id, [bob.mind.address], "One."));
    later();
    await bob.mind.receive();
    await bob.mind.send(say(id, [ada.mind.address], "Hello."));
    later();
    await ada.mind.receive();
    return { ada, bob, id, one };
  }
  const resume = (id: string, body: object): Message => ({
    to: [],
    verb: "resume",
    content: { mediaType: MEDIA_TYPE, body: { oip: "1", type: "Resume", session: id, ...body } },
    session: id,
  });

  it("is not answered where it names a packet the mind did not send at that place", async () => {
    const { ada, bob, id } = await talking();
    const sent = await bob.mind.send({
      ...resume(id, {
        lastReceived: [{ mind: ada.mind.address, seq: 0, packet: contentId({ another: 1 }) }],
        created: T(180),
      }),
      to: [ada.mind.address],
    });
    later();
    const inbox = await ada.mind.receive();
    expect(inbox.received).toHaveLength(1);
    expect(inbox.sessions).toStrictEqual([
      { kind: "invalid-resume", session: id, mind: bob.mind.address, packet: sent.id },
    ]);
  });

  it("shows a gap where its sender has sent what was never seen, and the mind asks", async () => {
    const { ada, bob, id, one } = await talking();
    // Bob says that another of his clients has sent four packets in the session.
    await bob.mind.send({
      ...resume(id, {
        lastSent: { seq: 3, packet: contentId({ fourth: 1 }), instance: "phone" },
        lastReceived: [],
        created: T(180),
      }),
      to: [ada.mind.address],
    });
    later();
    const inbox = await ada.mind.receive();
    // He lacks all of Ada's chain, by what he says: it is sent again. And she asks for his.
    expect(inbox.sessions).toMatchObject([
      { kind: "sent-again", to: bob.mind.address, from: 0, deliveries: [{ stored: true }] },
      { kind: "gap", session: id, mind: bob.mind.address, instance: "phone", next: 0 },
      { kind: "asked", session: id },
    ]);
    // And one that says this client of his has sent more than Ada has of it.
    const [chain] = (await ada.mind.sessions())[0]?.chains ?? [];
    await bob.mind.send({
      ...resume(id, {
        lastSent: { seq: 9, packet: contentId({ tenth: 1 }) },
        lastReceived: [{ mind: ada.mind.address, seq: 0, packet: one.id }],
        created: T(190),
      }),
      to: [ada.mind.address],
    });
    later();
    const second = await ada.mind.receive();
    // What he says he has of hers is short of what she sent since: that goes again too.
    expect(second.sessions).toMatchObject([
      { kind: "sent-again", from: 1 },
      { kind: "gap", session: id, mind: bob.mind.address, next: (chain?.received ?? 0) + 1 },
      { kind: "asked", session: id },
    ]);
    expect(second.sessions[1]).not.toHaveProperty("instance");
  });

  it("is read from a packet of the session it is about, with the verb resume", async () => {
    const { ada, bob, id } = await talking();
    const other = await bob.mind.openSession([ada.mind.address]);
    const wrong = { mind: ada.mind.address, seq: 0, packet: contentId({ another: 1 }) };
    // A Resume for another session than the packet's, and one sent as something else.
    await bob.mind.send({
      ...resume(id, { lastReceived: [wrong], created: T(180) }),
      to: [ada.mind.address],
      session: other.id,
    });
    await bob.mind.send({
      ...resume(id, { lastReceived: [wrong], created: T(180) }),
      to: [ada.mind.address],
      verb: "inform",
    });
    await bob.mind.send({
      to: [ada.mind.address],
      verb: "resume",
      content: { mediaType: "text/plain", body: "Where were we?" },
      session: id,
    });
    later();
    const inbox = await ada.mind.receive();
    expect(inbox.received).toHaveLength(3);
    expect(inbox.sessions).toStrictEqual([]);
  });

  it("is not answered by a mind that has left the session", async () => {
    const { ada, bob, id } = await talking();
    expect(await ada.mind.leaveSession(id)).toBe(true);
    await bob.mind.resume(id);
    later();
    const inbox = await ada.mind.receive();
    // The packet names a session Ada no longer follows, and does not carry its record.
    expect(inbox.received).toStrictEqual([]);
    expect(inbox.refused).toMatchObject([{ clause: "L1 14.2" }]);
    expect(inbox.sessions).toStrictEqual([]);
  });
});

describe(`${clause("L1 14.4")} what a session asks for and cannot be had`, () => {
  /** Bob with Ada's first packet read, her second lost and her third in his mailbox. */
  async function behind(more: Partial<MindOptions> = {}) {
    const ada = await at_(ONE);
    const bob = await at_(TWO, more);
    world.clock.at = at(160);
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    const one = await ada.mind.send(say(id, to, "One."));
    later();
    expect((await bob.mind.receive()).received).toHaveLength(1);
    await lost(TWO, () => ada.mind.send(say(id, to, "Two.")));
    await ada.mind.send(say(id, to, "Three."));
    later();
    return { ada, bob, id, one };
  }

  it("is told, and the packets that arrived are returned all the same", async () => {
    const { ada, bob, id } = await behind();
    const four = await ada.mind.send(say(id, [bob.mind.address], "Not of the session.", {}));
    expect(four.packet.seq).toBe(3);
    const plain = await ada.mind.send({
      to: [bob.mind.address],
      verb: "inform",
      content: { mediaType: "text/plain", body: "Outside any session." },
    });
    later();
    // The resolver stops answering once Bob has read his mailbox and removed what he took.
    let removed = false;
    world.before = (request) => {
      if (request.method === "DELETE") removed = true;
      else if (removed && request.url.startsWith(A)) throw new TypeError("fetch failed");
    };
    const inbox = await bob.mind.receive();
    world.before = undefined;
    expect(inbox.received.map((received) => received.id)).toStrictEqual([plain.id]);
    expect(inbox.sessions).toMatchObject([
      { kind: "gap", session: id, mind: ada.mind.address, next: 1 },
      { kind: "failed", session: id, doing: "asked", failure: "unreachable" },
    ]);
    // Nothing was asked, so the next reading asks.
    expect(kinds(await bob.mind.receive())).toStrictEqual(["gap", "asked"]);
  });

  it("is not hidden where the client itself is at fault", async () => {
    let broken = false;
    const { bob } = await behind({
      randomness: {
        bytes: (length) =>
          broken ? new Uint8Array(1) : globalThis.crypto.getRandomValues(new Uint8Array(length)),
      },
    });
    // It breaks once the mailbox is read: the Resume that asks cannot be made.
    world.before = (request) => {
      if (request.method === "GET" && request.url.endsWith("/mailbox")) broken = true;
    };
    await expect(bob.mind.receive()).rejects.toThrow(
      "the source of randomness did not give what was asked",
    );
    world.before = undefined;
  });
});

describe(`${clause("L1 14.3")} a sender that signs two packets for one place`, () => {
  it("is found out: the two are the evidence, and nothing of the chain is in order after", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    const one = await ada.mind.send(say(id, to, "One."));
    const two = await ada.mind.send(say(id, to, "Two."));
    // Ada signs another packet for the second place, outside her client.
    const { proof: _, ...unsigned } = two.packet;
    const other = await ada.mind.sign({ ...unsigned, nonce: "another-nonce" });
    expect(await post(mailboxOf(TWO, bob.mind), other)).toBe(202);
    const three = await ada.mind.send(say(id, to, "Three."));
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received.map((received) => received.id)).toStrictEqual([one.id, two.id]);
    const found = {
      kind: "equivocation",
      session: id,
      mind: ada.mind.address,
      seq: 1,
      packets: [two.id, contentId(other)].sort(),
    };
    expect(inbox.sessions).toStrictEqual([found]);
    expect(inbox.refused).toMatchObject([{ clause: "L1 14.3" }, { clause: "L1 14.3" }]);
    expect((await bob.mind.sessions())[0]?.chains).toStrictEqual([
      {
        mind: ada.mind.address,
        received: 2,
        equivocation: { kind: "equivocation", seq: 1, packets: found.packets },
      },
    ]);
    expect(three.packet.seq).toBe(2);
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });

  it("is found among the packets that waited, when the gap before them is filled", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    await ada.mind.send(say(id, to, "One."));
    const two = await lost(TWO, () => ada.mind.send(say(id, to, "Two.")));
    const three = await ada.mind.send(say(id, to, "Three.", { seal: false }));
    const { proof: _, ...unsigned } = three.packet;
    const other = await ada.mind.sign({ ...unsigned, nonce: "another-nonce" });
    expect(await post(mailboxOf(TWO, bob.mind), other)).toBe(202);
    later();
    expect(kinds(await bob.mind.receive())).toStrictEqual(["gap", "asked"]);
    expect(kinds(await ada.mind.receive())).toStrictEqual(["sent-again"]);
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received.map((received) => received.id)).toStrictEqual([two.id]);
    expect(inbox.sessions).toStrictEqual([
      {
        kind: "equivocation",
        session: id,
        mind: ada.mind.address,
        seq: 2,
        packets: [three.id, contentId(other)].sort(),
      },
    ]);
    // The two that waited have no place, and are not kept waiting.
    expect(inbox.refused).toMatchObject([{ clause: "L1 14.3" }, { clause: "L1 14.3" }]);
    expect((await bob.mind.receive()).sources[0]?.items).toBe(0);
  });
});

describe("what a client remembers of its sessions", () => {
  it(`${clause("L1 14.3")} lets a client that stops go on where it was: its own chain, and each chain it follows`, async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    const one = await ada.mind.send(say(id, to, "One."));
    // The second is signed and has its place, and the process stops before it is delivered.
    const two = await lost(TWO, () => ada.mind.send(say(id, to, "Two.")));
    later();
    expect((await bob.mind.receive()).received).toHaveLength(1);
    ada.mind.close();
    bob.mind.close();
    later();
    const adaAgain = await Mind.open(ada.options);
    const bobAgain = await Mind.open(bob.options);
    expect(await adaAgain.sessions()).toStrictEqual([{ id, session, sent: 2, chains: [] }]);
    expect(await bobAgain.sessions()).toStrictEqual([
      { id, session, sent: 0, chains: [{ mind: adaAgain.address, received: 1 }] },
    ]);
    // Ada's next packet is the third: she never signs another for the second place.
    const three = await adaAgain.send(say(id, to, "Three."));
    expect(three.packet).toMatchObject({ seq: 2, prev: two.id });
    later();
    expect(kinds(await bobAgain.receive())).toStrictEqual(["gap", "asked"]);
    // The packet that never left is sent as it was signed.
    expect(kinds(await adaAgain.receive())).toStrictEqual(["sent-again"]);
    later();
    const inbox = await bobAgain.receive();
    expect(inbox.received.map((received) => received.id)).toStrictEqual([two.id, three.id]);
    expect(inbox.received[0]?.packet).toStrictEqual(two.packet);
    // The first is told as a duplicate by its place, if it comes again.
    expect(await post(mailboxOf(TWO, bobAgain), one.packet)).toBe(202);
    const again = await bobAgain.receive();
    expect(again.received).toStrictEqual([]);
    expect(again.refused).toStrictEqual([]);
    expect(again.sources[0]?.items).toBe(1);
  });

  it(`${clause("L1 14.3")} keeps two processes that run as one instance from signing for one place`, async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    // A second process, with a copy of the keys and the same memory.
    const keystore = await Keystore.open({ storage: await copyOf(ada.storage) });
    const second = await Mind.open({ ...ada.options, keystore });
    expect(await second.sessions()).toHaveLength(1);
    const one = await ada.mind.send(say(id, to, "One."));
    const posted: string[] = [];
    world.before = (request) => {
      if (request.method === "POST") posted.push(request.url);
    };
    // The second process has not seen that, and is told before anything leaves.
    expect(await refusal(() => second.send(say(id, to, "Also one.")))).toBe("keystore: changed");
    expect(posted).toStrictEqual([]);
    world.before = undefined;
    // It finds the chain as it now stands, and so does the first after it.
    const two = await second.send(say(id, to, "Two."));
    expect(two.packet).toMatchObject({ seq: 1, prev: one.id });
    expect(await refusal(() => ada.mind.send(say(id, to, "Also two.")))).toBe("keystore: changed");
    expect((await ada.mind.send(say(id, to, "Three."))).packet).toMatchObject({
      seq: 2,
      prev: two.id,
    });
    later();
    expect((await bob.mind.receive()).received).toHaveLength(3);
  });

  it("is told where one process reads a mailbox that another has read since", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    await ada.mind.send(say(id, [bob.mind.address], "One."));
    const keystore = await Keystore.open({ storage: await copyOf(bob.storage) });
    const second = await Mind.open({ ...bob.options, keystore });
    await second.sessions();
    later();
    expect((await bob.mind.receive()).received).toHaveLength(1);
    await ada.mind.send(say(id, [bob.mind.address], "Two."));
    later();
    // The second process holds the session as it was before the first packet came.
    expect(await refusal(() => second.receive())).toBe("keystore: changed");
    // Nothing was removed: it reads again, as things stand, and has the packet.
    expect((await second.receive()).received).toHaveLength(1);
  });

  it("is told where one process holds a chain as it stood before another read on", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    await ada.mind.send(say(id, to, "One."));
    later();
    expect((await bob.mind.receive()).received).toHaveLength(1);
    const keystore = await Keystore.open({ storage: await copyOf(bob.storage) });
    const second = await Mind.open({ ...bob.options, keystore });
    expect((await second.sessions())[0]?.chains).toMatchObject([{ received: 1 }]);
    await ada.mind.send(say(id, to, "Two."));
    later();
    expect((await bob.mind.receive()).received).toHaveLength(1);
    const three = await ada.mind.send(say(id, to, "Three."));
    later();
    // For the second process the third is ahead of a gap. It cannot write that down.
    expect(await refusal(() => second.receive())).toBe("keystore: changed");
    const inbox = await second.receive();
    expect(inbox.received.map((received) => received.id)).toStrictEqual([three.id]);
    expect(inbox.sessions).toStrictEqual([]);
    // Nor can the first now leave the session as it held it.
    expect(await refusal(() => bob.mind.leaveSession(id))).toBe("keystore: changed");
    expect(await bob.mind.leaveSession(id)).toBe(true);
    expect(await bob.mind.sessions()).toStrictEqual([]);
  });

  it("is read as it stands: a session that was left while it was listed is no session", async () => {
    const { ada, bob } = await pair();
    await ada.mind.openSession([bob.mind.address]);
    ada.mind.close();
    const list = ada.memory.list.bind(ada.memory);
    ada.memory.list = async () => [...(await list()), "client-ses-aaaaaaaaaaaaaaaaaaaaa"];
    const again = await Mind.open(ada.options);
    expect(await again.sessions()).toHaveLength(1);
  });

  it("is forgotten when the mind leaves a session, with the packets it sent in it", async () => {
    const { ada, bob } = await pair();
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    const kept = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    await ada.mind.send(say(id, to, "One."));
    await ada.mind.send(say(id, to, "Two."));
    await ada.mind.send(say(kept.id, to, "Elsewhere."));
    const names = async () => (await ada.memory.list()).filter((name) => /-(ses|pkt)-/u.test(name));
    expect(await names()).toHaveLength(5);
    expect(await ada.mind.leaveSession(id)).toBe(true);
    expect(await ada.mind.leaveSession(id)).toBe(false);
    expect(await ada.mind.leaveSession(contentId({ a: 1 }))).toBe(false);
    expect(await names()).toHaveLength(2);
    expect((await ada.mind.sessions()).map((view) => view.id)).toStrictEqual([kept.id]);
    expect(await refusal(() => ada.mind.send(say(id, to, "Three.")))).toBe("oip: not-found");
    // Bob still follows it. What he sends in it is refused by Ada, unless it carries the record.
    later();
    await bob.mind.receive();
    const answer = await bob.mind.send(say(id, [ada.mind.address], "Still there?"));
    expect(answer.packet.content).toMatchObject({ parts: [{ body: session }, {}] });
    later();
    expect((await ada.mind.receive()).received).toHaveLength(1);
    expect((await ada.mind.sessions()).map((view) => view.id).sort()).toStrictEqual(
      [kept.id, id].sort(),
    );
  });

  it("is damaged where it cannot be read, and the client says so", async () => {
    const { ada, bob } = await pair();
    const { id } = await ada.mind.openSession([bob.mind.address]);
    const to = [bob.mind.address];
    await ada.mind.send(say(id, to, "One."));
    later();
    await bob.mind.receive();
    ada.mind.close();
    const [session] = (await ada.memory.list()).filter((name) => name.startsWith("client-ses-"));
    const [packet] = (await ada.memory.list()).filter((name) => name.startsWith("client-pkt-"));
    if (session === undefined || packet === undefined) throw new Error("nothing was written");
    const read = async (name: string) => {
      const held = await ada.memory.get(name);
      if (held === undefined) throw new Error(`no ${name}`);
      return {
        document: JSON.parse(new TextDecoder().decode(held.value)) as Record<string, unknown>,
        version: held.version,
      };
    };
    const write = async (name: string, document: unknown, version: string | undefined) =>
      ada.memory.put(name, utf8(JSON.stringify(document)), version);
    // The packet it sent is another's, or gone: it cannot be sent again.
    const sent = await read(packet);
    const version = await write(packet, { ...sent.document, packet: { oip: "1" } }, sent.version);
    const again = await Mind.open(ada.options);
    await bob.mind.resume(id);
    later();
    // Bob's Resume says he has everything: nothing needs reading.
    expect(kinds(await again.receive())).toStrictEqual([]);
    // One that says he has nothing asks for the packet, which cannot be read.
    const all = (): Promise<Sent> =>
      bob.mind.send({
        to: [ada.mind.address],
        verb: "resume",
        content: {
          mediaType: MEDIA_TYPE,
          body: { oip: "1", type: "Resume", session: id, lastReceived: [], created: T(200) },
        },
        session: id,
      });
    await all();
    later();
    // The packet that arrived is returned all the same, and what could not be done is told.
    const failed = await again.receive();
    expect(failed.received).toHaveLength(1);
    expect(failed.sessions).toStrictEqual([
      { kind: "failed", session: id, doing: "sent-again", failure: "damaged" },
    ]);
    // Gone altogether, it is as much.
    await ada.memory.delete(packet, version);
    await all();
    later();
    expect((await again.receive()).sessions).toStrictEqual([
      { kind: "failed", session: id, doing: "sent-again", failure: "damaged" },
    ]);
    await write(packet, sent.document, undefined);
    await all();
    later();
    expect(kinds(await again.receive())).toStrictEqual(["sent-again"]);
    again.close();
    // A session as it was written down, in each way it can be no session.
    const head = await read(session);
    const broken: unknown[] = [
      { ...head.document, session: { oip: "1", type: "Session" } },
      { ...head.document, sent: "none" },
      { ...head.document, sent: [null] },
      { ...head.document, sent: [{ id: 7, seal: true }] },
      { ...head.document, sent: [{ id, seal: "yes" }] },
      { ...head.document, instance: 7 },
      { ...head.document, chains: [{ from: "nobody", ids: [] }] },
    ];
    let at = head.version;
    for (const document of broken) {
      at = await write(session, document, at);
      const opened = await Mind.open(ada.options);
      expect(await refusal(() => opened.sessions()), JSON.stringify(document)).toBe(
        "keystore: damaged",
      );
      // It is read again the next time, and not held as it failed.
      expect(await refusal(() => opened.sessions())).toBe("keystore: damaged");
      opened.close();
    }
    // Under another session's name it is not that session.
    await write(session, head.document, at);
    await write("client-ses-aaaaaaaaaaaaaaaaaaaaa", head.document, undefined);
    const opened = await Mind.open(ada.options);
    expect(await refusal(() => opened.sessions())).toBe("keystore: damaged");
    opened.close();
  });
});

describe(`${clause("L1 14.3")} a session of three`, () => {
  it("has a chain for each sender, and each sends again what is its own", async () => {
    const { ada, bob } = await pair();
    const cyd = await at_(THREE);
    world.clock.at = at(200);
    const { id } = await ada.mind.openSession([bob.mind.address, cyd.mind.address]);
    const all = (but: Mind) =>
      [ada.mind, bob.mind, cyd.mind].filter((mind) => mind !== but).map((mind) => mind.address);
    await ada.mind.send(say(id, all(ada.mind), "Ada, one."));
    later();
    await bob.mind.receive();
    await cyd.mind.receive();
    await bob.mind.send(say(id, all(bob.mind), "Bob, one."));
    // Cyd misses Bob's second and Ada's second, and has the third of each.
    await lost(THREE, () => bob.mind.send(say(id, all(bob.mind), "Bob, two.")));
    await lost(THREE, () => ada.mind.send(say(id, all(ada.mind), "Ada, two.")));
    await bob.mind.send(say(id, all(bob.mind), "Bob, three."));
    await ada.mind.send(say(id, all(ada.mind), "Ada, three."));
    later();
    const first = await cyd.mind.receive();
    expect(bodies(first)).toHaveLength(1);
    // Two gaps, and one Resume for the session.
    expect(kinds(first)).toStrictEqual(["gap", "gap", "asked"]);
    later();
    expect((await ada.mind.receive()).sessions).toMatchObject([
      { kind: "sent-again", to: cyd.mind.address, from: 1, deliveries: [{}, {}] },
    ]);
    expect((await bob.mind.receive()).sessions).toMatchObject([
      { kind: "sent-again", to: cyd.mind.address, from: 1, deliveries: [{}, {}] },
    ]);
    later();
    const second = await cyd.mind.receive();
    expect(bodies(second).sort()).toStrictEqual(
      ["Ada, three.", "Ada, two.", "Bob, three.", "Bob, two."].sort(),
    );
    const order = bodies(second) as string[];
    expect(order.indexOf("Ada, two.")).toBeLessThan(order.indexOf("Ada, three."));
    expect(order.indexOf("Bob, two.")).toBeLessThan(order.indexOf("Bob, three."));
    expect(second.sessions).toStrictEqual([]);
  });

  it(`${clause("L1 14.4")} asks from the start for a chain of which nothing is held in order`, async () => {
    const { ada, bob } = await pair();
    const cyd = await at_(THREE);
    world.clock.at = at(200);
    const { id, session } = await ada.mind.openSession([bob.mind.address, cyd.mind.address]);
    const others = (of: Mind) =>
      session.participants.filter((participant) => participant !== of.address);
    const first = await ada.mind.send(say(id, others(ada.mind), "Ada, one."));
    later();
    await bob.mind.receive();
    await cyd.mind.receive();
    // Bob misses the first packet of Cyd's chain, and has the second.
    await lost(TWO, () => cyd.mind.send(say(id, others(cyd.mind), "Cyd, one.")));
    await cyd.mind.send(say(id, others(cyd.mind), "Cyd, two."));
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.sessions).toMatchObject([
      { kind: "gap", mind: cyd.mind.address, next: 0 },
      { kind: "asked" },
    ]);
    const asked = inbox.sessions[1];
    // His Resume says where Ada's chain stands for him, and nothing of Cyd's.
    expect(asked?.kind === "asked" && asked.sent.packet.content).toMatchObject({
      parts: [
        {},
        { body: { lastReceived: [{ mind: ada.mind.address, seq: 0, packet: first.id }] } },
      ],
    });
    expect((await bob.mind.sessions())[0]?.chains).toStrictEqual([
      { mind: ada.mind.address, received: 1 },
      { mind: cyd.mind.address, received: 0 },
    ]);
    later();
    // Ada has nothing to send him. Cyd sends both again.
    expect(kinds(await ada.mind.receive())).toStrictEqual([]);
    expect(await cyd.mind.receive()).toMatchObject({
      sessions: [{ kind: "sent-again", to: bob.mind.address, from: 0, deliveries: [{}, {}] }],
    });
    later();
    expect(bodies(await bob.mind.receive())).toStrictEqual([[session, "Cyd, one."], "Cyd, two."]);
  });
});

describe("a session and a stranger", () => {
  it(`${clause("L1 14.3")} takes no packet of a mind that is no participant`, async () => {
    const { ada, bob } = await pair();
    const eve = new KeyMind("eve");
    expect(await world.publish(A, eve)).toBe(202);
    const { id, session } = await ada.mind.openSession([bob.mind.address]);
    await ada.mind.send(say(id, [bob.mind.address], "One."));
    later();
    await bob.mind.receive();
    const intruding = eve.sign({
      oip: "1",
      type: "Packet",
      from: eve.address,
      to: [bob.mind.address, ada.mind.address],
      created: T(165),
      nonce: "eve-nonce-1",
      session: id,
      seq: 0,
      purpose: { verb: "inform" },
      content: { mediaType: MEDIA_TYPE, body: session },
    });
    expect(await post(mailboxOf(TWO, bob.mind), intruding)).toBe(202);
    later();
    const inbox = await bob.mind.receive();
    expect(inbox.received).toStrictEqual([]);
    expect(inbox.refused).toMatchObject([{ clause: "L1 14.3" }]);
    expect((await bob.mind.sessions())[0]?.chains).toHaveLength(1);
  });
});
