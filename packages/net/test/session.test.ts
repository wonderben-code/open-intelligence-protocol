// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId } from "@oip/core";
import { LogBook } from "@oip/identity";
import { type Packet, type Resume, validateRecordOfType } from "@oip/schema";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  AcceptedPackets,
  lacking,
  type ReceivedPacket,
  receivePacket,
  type Receiver,
  recordsCarried,
  sessionCarried,
  Sessions,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const SECOND = 1_000_000_000n;
const RECORD = "application/oip+json";

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const cy = new KeyMind("cy");
const eve = new KeyMind("eve");
const everyone = [ada, bob, cy, eve];
const participants = [ada, bob, cy];

const session = {
  oip: "1",
  type: "Session",
  participants: participants.map((mind) => mind.address).sort(),
  nonce: "session-0001",
  created: T(0),
};
const sid = contentId(session);

/** The packet at `seq` of a mind's chain in the session, after `prev`. The first carries the Session record. */
function link(from: Mind, seq: number, prev: object | undefined, more: JsonObject = {}): Signed {
  return from.sign({
    oip: "1",
    type: "Packet",
    from: from.address,
    to: participants.filter((mind) => mind !== from).map((mind) => mind.address),
    created: T(10 + seq),
    nonce: `nonce-${from.name}-${seq}`,
    session: sid,
    seq,
    ...(prev === undefined ? {} : { prev: contentId(prev) }),
    purpose: { verb: seq === 0 ? "open" : "inform" },
    content:
      seq === 0
        ? { mediaType: RECORD, body: session }
        : { mediaType: "text/plain", body: `Message ${seq}.` },
    ...more,
  });
}

/** The first `length` packets of a mind's chain. */
function chainOf(from: Mind, length: number, more: JsonObject = {}): Signed[] {
  const packets: Signed[] = [];
  for (let seq = 0; seq < length; seq++) packets.push(link(from, seq, packets[seq - 1], more));
  return packets;
}

/** Bob, who holds everyone's log, at a time when every packet of these tests is fresh. */
function bobAt(seconds = 100, more: Partial<Receiver> = {}): Receiver {
  const seen = witness(everyone.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of everyone) book.hold(mind.events, LATER);
  return {
    address: bob.address,
    now: at(seconds),
    view: book,
    seen,
    accepted: () => false,
    window: 3600n * SECOND,
    ...more,
  };
}

/** A packet as Bob's gate accepted it. */
function received(packet: object, receiver: Receiver = bobAt()): ReceivedPacket {
  const result = receivePacket(packet, receiver);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/** What `take` answers for a packet, or why it rejects it. */
function take(sessions: Sessions, packet: object) {
  const result = sessions.take(received(packet));
  return result.ok
    ? result.value
    : { rejected: result.issues[0].clause, path: result.issues[0].path };
}

const ids = (packets: readonly ReceivedPacket[]) => packets.map((packet) => packet.id);

describe(`${clause("L1 14.1", "L1 14.2")} the Session record a packet carries`, () => {
  it("is the one whose content ID is the packet's session, as a body or as a part", () => {
    const [first] = chainOf(ada, 1) as [Signed];
    expect(sessionCarried(first as unknown as Packet)).toStrictEqual(session);
    const parts = link(ada, 0, undefined, {
      content: {
        parts: [
          { mediaType: "text/plain", body: "Shall we begin?" },
          { mediaType: RECORD, body: session },
        ],
      },
    });
    expect(sessionCarried(parts as unknown as Packet)).toStrictEqual(session);
  });

  it("is no other record, and no record that is not well formed or not sent as one", () => {
    const carrying = (body: unknown, mediaType = RECORD) =>
      sessionCarried(
        link(ada, 0, undefined, {
          content: { mediaType, body },
        }) as unknown as Packet,
      );
    // Another session.
    expect(carrying({ ...session, nonce: "session-0002" })).toBeUndefined();
    // The right members under another media type are text, not a record (12.2).
    expect(carrying(session, "application/json")).toBeUndefined();
    // Participants out of order: no Session record at all (14.1).
    const unsorted = { ...session, participants: session.participants.toReversed() };
    const named = link(ada, 0, undefined, {
      session: contentId(unsorted),
      content: { mediaType: RECORD, body: unsorted },
    });
    expect(sessionCarried(named as unknown as Packet)).toBeUndefined();
    expect(carrying("a session")).toBeUndefined();
    expect(carrying(null)).toBeUndefined();
    // A packet outside any session carries none for one.
    const { session: _, seq: __, ...outside } = link(ada, 0, undefined);
    expect(sessionCarried({ ...outside, expires: T(100) } as unknown as Packet)).toBeUndefined();
  });

  it("stands for the session of the test vectors", () => {
    const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
    const packet = cases["packet"] as unknown as Packet;
    expect(packet.session).toBe(contentId(cases["session"] as object));
    expect(sessionCarried(packet)).toStrictEqual(cases["session"]);
  });
});

describe(`${clause("L1 14.3")} a sending chain`, () => {
  it("is each sender's packets in order, from seq 0, each naming the one before", () => {
    const sessions = new Sessions(bob.address);
    const [p0, p1, p2] = chainOf(ada, 3) as [Signed, Signed, Signed];
    expect(sessions.session(sid)).toBeUndefined();
    const first = take(sessions, p0);
    expect(first).toMatchObject({ kind: "in order", equivocation: undefined });
    expect("delivered" in first && ids(first.delivered)).toStrictEqual([contentId(p0)]);
    // The first packet opened the session for the receiver.
    expect(sessions.session(sid)).toStrictEqual(session);
    expect(sessions.size).toBe(1);
    for (const packet of [p1, p2]) {
      const placed = take(sessions, packet);
      expect("delivered" in placed && ids(placed.delivered)).toStrictEqual([contentId(packet)]);
    }
  });

  it("is one for each sender, and for each instance of a sender", () => {
    const sessions = new Sessions(bob.address);
    const mine = chainOf(ada, 2);
    const laptop = chainOf(ada, 2, { instance: "laptop" });
    const phone = chainOf(ada, 2, { instance: "phone" });
    // An instance named by the empty string is not the absent one.
    const empty = chainOf(ada, 2, { instance: "" });
    const cys = chainOf(cy, 2);
    for (const chain of [mine, laptop, phone, empty, cys]) {
      for (const packet of chain)
        expect(take(sessions, packet)).toMatchObject({ kind: "in order" });
    }
    expect(sessions.holdsChain({ session: sid, from: ada.address, instance: "phone" })).toBe(true);
    expect(sessions.holdsChain({ session: sid, from: ada.address, instance: "tablet" })).toBe(
      false,
    );
    expect(sessions.holdsChain({ session: sid, from: eve.address, instance: undefined })).toBe(
      false,
    );
  });

  it("discards a packet it has at that place already", () => {
    const sessions = new Sessions(bob.address);
    const [p0, p1] = chainOf(ada, 2) as [Signed, Signed];
    take(sessions, p0);
    take(sessions, p1);
    expect(take(sessions, p0)).toStrictEqual({ kind: "duplicate" });
    expect(take(sessions, p1)).toStrictEqual({ kind: "duplicate" });
    // The same packet with another proof on it is the same packet.
    expect(take(sessions, eve.sign(p1))).toStrictEqual({ kind: "duplicate" });
  });

  it("keeps a packet that is ahead of a gap, and delivers it when the gap is filled", () => {
    const sessions = new Sessions(bob.address);
    const [p0, p1, p2, p3] = chainOf(ada, 4) as [Signed, Signed, Signed, Signed];
    take(sessions, p0);
    expect(take(sessions, p3)).toStrictEqual({ kind: "waiting", next: 1 });
    expect(take(sessions, p2)).toStrictEqual({ kind: "waiting", next: 1 });
    // Sent again while it waits, it waits.
    expect(take(sessions, p2)).toStrictEqual({ kind: "waiting", next: 1 });
    const filled = take(sessions, p1);
    expect("delivered" in filled && ids(filled.delivered)).toStrictEqual(
      [p1, p2, p3].map((packet) => contentId(packet)),
    );
    expect(take(sessions, p3)).toStrictEqual({ kind: "duplicate" });
  });

  it("rejects a packet that is no link: its prev is not the packet before it", () => {
    const sessions = new Sessions(bob.address);
    const [p0, p1, p2] = chainOf(ada, 3) as [Signed, Signed, Signed];
    take(sessions, p0);
    const stray = link(ada, 1, p2);
    expect(take(sessions, stray)).toStrictEqual({ rejected: "L1 14.3", path: "/prev" });
    // The place is open still, for the packet that is.
    expect(take(sessions, p1)).toMatchObject({ kind: "in order" });
    // At a place already filled, a packet with another prev is no link either, and no equivocation.
    expect(take(sessions, stray)).toStrictEqual({ rejected: "L1 14.3", path: "/prev" });
    expect(sessions.equivocation({ session: sid, from: ada.address, instance: undefined })).toBe(
      undefined,
    );
    // The first packet names none before it.
    const fresh = new Sessions(bob.address);
    expect(take(fresh, link(ada, 0, p1))).toStrictEqual({ rejected: "L1 14.3", path: "/prev" });
    expect(fresh.size).toBe(0);
  });

  it("drops what waited for a place when it turns out to be no link", () => {
    const sessions = new Sessions(bob.address);
    const [p0, p1, p2] = chainOf(ada, 3) as [Signed, Signed, Signed];
    take(sessions, p0);
    const stray = link(ada, 2, p0, { nonce: "nonce-stray" });
    expect(take(sessions, stray)).toStrictEqual({ kind: "waiting", next: 1 });
    const filled = take(sessions, p1);
    expect("delivered" in filled && ids(filled.delivered)).toStrictEqual([contentId(p1)]);
    expect(take(sessions, p2)).toMatchObject({ kind: "in order" });
  });

  it("comes to the same chain in whatever order its packets arrive", () => {
    const chain = chainOf(ada, 5);
    const orders = [
      [0, 1, 2, 3, 4],
      [0, 4, 3, 2, 1],
      [0, 2, 4, 1, 3],
      [0, 3, 3, 1, 4, 2, 0],
    ];
    for (const order of orders) {
      const sessions = new Sessions(bob.address);
      const delivered: string[] = [];
      for (const index of order) {
        const placed = take(sessions, chain[index]!);
        if ("delivered" in placed) delivered.push(...ids(placed.delivered));
      }
      expect(delivered, order.join(" ")).toStrictEqual(chain.map((packet) => contentId(packet)));
    }
  });
});

describe(`${clause("L1 14.3")} the participants of a session`, () => {
  it("are the only senders in it", () => {
    const sessions = new Sessions(bob.address);
    take(sessions, link(ada, 0, undefined));
    const { proof: _, ...content } = link(ada, 0, undefined, { nonce: "nonce-eve" });
    const outsider = eve.sign({
      ...content,
      from: eve.address,
      to: participants.map((mind) => mind.address),
    });
    expect(take(sessions, outsider)).toStrictEqual({ rejected: "L1 14.3", path: "/from" });
  });

  it("are all among the recipients, but for the sender", () => {
    const sessions = new Sessions(bob.address);
    const partial = link(ada, 0, undefined, { to: [bob.address] });
    expect(take(sessions, partial)).toStrictEqual({ rejected: "L1 14.3", path: "/to" });
    expect(sessions.size).toBe(0);
    // A recipient that is no participant is not forbidden.
    const wider = link(ada, 0, undefined, { to: [bob.address, cy.address, eve.address] });
    expect(take(sessions, wider)).toMatchObject({ kind: "in order" });
    // The sender may list itself.
    const self = link(cy, 0, undefined, { to: participants.map((mind) => mind.address) });
    expect(take(sessions, self)).toMatchObject({ kind: "in order" });
  });

  it(`${clause("L1 14.2")} are known from the Session record, which the packet carries or the receiver holds`, () => {
    const sessions = new Sessions(bob.address);
    const bare = link(cy, 0, undefined, { content: { mediaType: "text/plain", body: "Hello." } });
    expect(take(sessions, bare)).toStrictEqual({ rejected: "L1 14.2", path: "/content" });
    // A later packet of a chain does not carry it either.
    const [, p1] = chainOf(ada, 2) as [Signed, Signed];
    expect(take(sessions, p1)).toStrictEqual({ rejected: "L1 14.2", path: "/content" });
    // Once any packet has brought the record, the receiver can check the others.
    expect(take(sessions, link(ada, 0, undefined))).toMatchObject({ kind: "in order" });
    expect(take(sessions, bare)).toMatchObject({ kind: "in order" });
  });

  it("is a packet in a session at all", () => {
    const sessions = new Sessions(bob.address);
    const { session: _, seq: __, proof: ___, ...outside } = link(ada, 0, undefined);
    const plain = ada.sign({ ...outside, expires: T(1000) });
    expect(take(sessions, plain)).toStrictEqual({ rejected: "L1 14.3", path: "/session" });
    const toQuery = received(link(ada, 0, undefined));
    const result = sessions.take({
      ...toQuery,
      packet: { ...toQuery.packet, to: { query: {} } },
    });
    expect(result).toMatchObject({ ok: false, issues: [{ clause: "L1 14.3", path: "/to" }] });
  });
});

describe(`${clause("L1 14.3")} equivocation in a chain`, () => {
  const chain = { session: sid, from: ada.address, instance: undefined };
  const [p0, p1, p2] = chainOf(ada, 3) as [Signed, Signed, Signed];
  const other = link(ada, 1, p0, { nonce: "nonce-other" });
  const pair = [contentId(p1), contentId(other)].sort();

  it("is two links at one place, and the chain is verified no further", () => {
    const sessions = new Sessions(bob.address);
    take(sessions, p0);
    take(sessions, p1);
    expect(sessions.equivocation(chain)).toBeUndefined();
    const found = { kind: "equivocation", seq: 1, packets: pair };
    expect(take(sessions, other)).toStrictEqual(found);
    expect(sessions.equivocation(chain)).toStrictEqual(found);
    // Every later packet of the chain, and each of the two again, gets the same answer.
    for (const packet of [p2, p1, other, p0]) expect(take(sessions, packet)).toStrictEqual(found);
    // Another sender's chain is its own.
    expect(take(sessions, link(cy, 0, undefined))).toMatchObject({ kind: "in order" });
  });

  it("is found whichever of the two came first, and named the same", () => {
    const sessions = new Sessions(bob.address);
    take(sessions, p0);
    take(sessions, other);
    expect(take(sessions, p1)).toStrictEqual({ kind: "equivocation", seq: 1, packets: pair });
  });

  it("is found at the first place too", () => {
    const sessions = new Sessions(bob.address);
    const again = link(ada, 0, undefined, { nonce: "nonce-again" });
    take(sessions, p0);
    expect(take(sessions, again)).toMatchObject({ kind: "equivocation", seq: 0 });
  });

  it("is found among packets that waited, when the gap before them is filled", () => {
    const sessions = new Sessions(bob.address);
    const twin = link(ada, 2, p1, { nonce: "nonce-twin" });
    take(sessions, p0);
    expect(take(sessions, p2)).toMatchObject({ kind: "waiting" });
    expect(take(sessions, twin)).toMatchObject({ kind: "waiting" });
    const filled = take(sessions, p1);
    const found = {
      kind: "equivocation",
      seq: 2,
      packets: [contentId(p2), contentId(twin)].sort(),
    };
    expect(filled).toMatchObject({ kind: "in order", equivocation: found });
    // The packet that filled the gap is in order. Neither of the two after it is.
    expect("delivered" in filled && ids(filled.delivered)).toStrictEqual([contentId(p1)]);
    expect(sessions.equivocation(chain)).toStrictEqual(found);
  });
});

describe("what a receiver keeps of its sessions", () => {
  it("is bounded for the packets that wait in one chain", () => {
    const sessions = new Sessions(bob.address, { maxWaiting: 2 });
    const chain = chainOf(ada, 8);
    take(sessions, chain[0]!);
    expect(take(sessions, chain[2]!)).toMatchObject({ kind: "waiting" });
    expect(take(sessions, chain[3]!)).toMatchObject({ kind: "waiting" });
    expect(take(sessions, chain[4]!)).toStrictEqual({
      rejected: "implementation limit",
      path: "/seq",
    });
    // One that waits already is no more to keep, and the next link is always taken.
    expect(take(sessions, chain[3]!)).toMatchObject({ kind: "waiting" });
    const filled = take(sessions, chain[1]!);
    expect("delivered" in filled && filled.delivered).toHaveLength(3);
    // The room is free again, all of it: a packet that waited twice took one place.
    expect(take(sessions, chain[5]!)).toMatchObject({ kind: "waiting" });
    expect(take(sessions, chain[6]!)).toMatchObject({ kind: "waiting" });
    expect(take(sessions, chain[7]!)).toMatchObject({ rejected: "implementation limit" });
  });

  it("is bounded for the sessions followed, until one is dropped", () => {
    const sessions = new Sessions(bob.address, { maxSessions: 1 });
    take(sessions, link(ada, 0, undefined));
    const second = { ...session, nonce: "session-0002" };
    const opening = link(ada, 0, undefined, {
      session: contentId(second),
      content: { mediaType: RECORD, body: second },
    });
    expect(take(sessions, opening)).toStrictEqual({
      rejected: "implementation limit",
      path: "/session",
    });
    // A packet of the session held is taken still.
    expect(take(sessions, link(cy, 0, undefined))).toMatchObject({ kind: "in order" });
    expect(sessions.drop(sid)).toBe(true);
    expect(sessions.drop(sid)).toBe(false);
    expect(sessions.size).toBe(0);
    expect(take(sessions, opening)).toMatchObject({ kind: "in order" });
  });

  it("has limits of at least one", () => {
    for (const limit of [0, -1, 1.5, Number.NaN, 2 ** 60]) {
      expect(() => new Sessions(bob.address, { maxSessions: limit })).toThrow(TypeError);
      expect(() => new Sessions(bob.address, { maxInstances: limit })).toThrow(TypeError);
      expect(() => new Sessions(bob.address, { maxWaiting: limit })).toThrow(TypeError);
    }
    const least = { maxSessions: 1, maxInstances: 1, maxWaiting: 1 };
    expect(new Sessions(bob.address, least).size).toBe(0);
    expect(() => new Sessions(undefined as never)).toThrow(TypeError);
  });

  it("is bounded for the chains of one sender in one session", () => {
    const sessions = new Sessions(bob.address, { maxInstances: 2 });
    take(sessions, link(ada, 0, undefined));
    take(sessions, link(ada, 0, undefined, { instance: "laptop" }));
    // A third instance of Ada is one chain too many, whether its packet is next or waits.
    const phone = chainOf(ada, 2, { instance: "phone" });
    for (const packet of phone) {
      expect(take(sessions, packet)).toStrictEqual({
        rejected: "implementation limit",
        path: "/instance",
      });
    }
    // The chains she has go on, and another sender has chains of its own.
    expect(take(sessions, link(ada, 1, link(ada, 0, undefined)))).toMatchObject({
      kind: "in order",
    });
    expect(take(sessions, link(cy, 0, undefined))).toMatchObject({ kind: "in order" });
    expect(take(sessions, link(cy, 0, undefined, { instance: "desk" }))).toMatchObject({
      kind: "in order",
    });
    expect(take(sessions, link(cy, 0, undefined, { instance: "car" }))).toMatchObject({
      rejected: "implementation limit",
    });
  });

  it("is the sessions of one participant: a session it is no part of is not followed", () => {
    // Bob receives a packet of a session among Ada, Cy and Eve, as a recipient beyond them.
    const others = {
      ...session,
      participants: [ada, cy, eve].map((mind) => mind.address).sort(),
      nonce: "session-0003",
    };
    const packet = link(ada, 0, undefined, {
      session: contentId(others),
      to: [bob.address, cy.address, eve.address],
      content: { mediaType: RECORD, body: others },
    });
    const sessions = new Sessions(bob.address);
    expect(take(sessions, packet)).toStrictEqual({ rejected: "L1 14.3", path: "/session" });
    expect(sessions.size).toBe(0);
  });
});

describe(`${clause("L1 12.4")} a session packet older than the receiver remembers`, () => {
  it("is taken where the receiver holds its chain, which tells it as a duplicate", () => {
    const sessions = new Sessions(bob.address);
    const accepted = new AcceptedPackets();
    const window = 600n * SECOND;
    const [p0, p1] = chainOf(ada, 2) as [Signed, Signed];
    const early = bobAt(100, { accepted: accepted.has, window, holdsChain: sessions.holdsChain });
    for (const packet of [p0, p1]) {
      const first = received(packet, early);
      accepted.record(first);
      expect(sessions.take(first)).toMatchObject({ ok: true, value: { kind: "in order" } });
    }
    // An hour later the receiver has forgotten the packets, and holds the chain.
    const late = { ...early, now: at(3700) };
    expect(accepted.forget(late.now)).toBe(2);
    const again = receivePacket(p0, late);
    if (!again.ok) throw new Error(JSON.stringify(again.issues));
    expect(again.value.duplicate).toBe(false);
    expect(sessions.take(again.value)).toStrictEqual({ ok: true, value: { kind: "duplicate" } });
    // A packet of a chain it does not hold is rejected at the gate.
    const stranger = receivePacket(link(cy, 0, undefined), late);
    expect(stranger).toMatchObject({ ok: false, issues: [{ path: "/created" }] });
    // And so is this one, once the session is dropped.
    sessions.drop(sid);
    expect(receivePacket(p0, late).ok).toBe(false);
  });
});

describe(`${clause("L1 14.3", "L1 14.4")} a gap, repaired by a Resume`, () => {
  it("is detected by the receiver, said in a Resume, and filled by what the sender sends again", () => {
    // Ada sends five packets. The second and the third are lost on the way to Bob.
    const sent = chainOf(ada, 5);
    const sessions = new Sessions(bob.address);
    const delivered: string[] = [];
    const arrive = (packet: object) => {
      const placed = take(sessions, packet);
      if ("delivered" in placed) delivered.push(...ids(placed.delivered));
      return placed;
    };
    arrive(sent[0]!);
    // The fourth arrives: Bob sees the gap, keeps the packet, and treats nothing after the
    // first as in order.
    expect(arrive(sent[3]!)).toStrictEqual({ kind: "waiting", next: 1 });
    expect(arrive(sent[4]!)).toStrictEqual({ kind: "waiting", next: 1 });
    expect(delivered).toStrictEqual([contentId(sent[0] as object)]);

    // Bob says where each chain stands for him.
    const resume = sessions.resume(sid, undefined, T(60))!;
    expect(resume.lastReceived).toStrictEqual([
      { mind: ada.address, seq: 0, packet: contentId(sent[0] as object) },
    ]);

    // Ada checks the Resume against what she sent, and sends again from where Bob stands.
    const own = { address: ada.address, sent: sent.map((packet) => contentId(packet)) };
    const from = lacking(resume, own);
    expect(from).toStrictEqual({ ok: true, value: 1 });
    for (const packet of sent.slice(from.ok ? from.value : 0)) arrive(packet);

    // Every packet was delivered to Bob once, in the order Ada sent them.
    expect(delivered).toStrictEqual(sent.map((packet) => contentId(packet)));
    // And Bob now stands where Ada does.
    const after = sessions.resume(sid, undefined, T(70))!;
    expect(lacking(after, own)).toStrictEqual({ ok: true, value: 5 });
  });
});

describe(`${clause("L1 14.4")} a Resume`, () => {
  const mine = chainOf(ada, 3);
  const cys = chainOf(cy, 2);

  it("says where each chain stands for the receiver", () => {
    const sessions = new Sessions(bob.address);
    for (const packet of [...mine, ...cys]) take(sessions, packet);
    const phone = chainOf(cy, 1, { instance: "phone" });
    take(sessions, phone[0]!);
    // A chain of which nothing is in order has no place in it.
    take(sessions, link(cy, 4, mine[0], { instance: "tablet" }));
    const lastSent = { seq: 7, packet: contentId(mine[0]) };
    const resume = sessions.resume(sid, lastSent, T(500));
    expect(resume).toStrictEqual({
      oip: "1",
      type: "Resume",
      session: sid,
      lastSent,
      lastReceived: [
        { mind: ada.address, seq: 2, packet: contentId(mine[2] as object) },
        { mind: cy.address, seq: 1, packet: contentId(cys[1] as object) },
        { mind: cy.address, instance: "phone", seq: 0, packet: contentId(phone[0] as object) },
      ],
      created: T(500),
    });
    expect(validateRecordOfType("Resume", resume).ok).toBe(true);
    // A mind that has sent nothing says nothing of its own chain.
    const silent = sessions.resume(sid, undefined, T(500))!;
    expect(Object.hasOwn(silent, "lastSent")).toBe(false);
    expect(validateRecordOfType("Resume", silent).ok).toBe(true);
    expect(
      sessions.resume(contentId({ ...session, nonce: "session-0002" }), undefined, T(500)),
    ).toBe(undefined);
  });

  it("is found in the packet that carries it", () => {
    const sessions = new Sessions(bob.address);
    for (const packet of mine) take(sessions, packet);
    const resume = sessions.resume(sid, undefined, T(500))!;
    const packet = link(cy, 0, undefined, {
      purpose: { verb: "resume" },
      content: {
        parts: [
          { mediaType: RECORD, body: session },
          { mediaType: RECORD, body: resume as unknown as JsonObject },
        ],
      },
    });
    expect(recordsCarried(packet as unknown as Packet, "Resume")).toStrictEqual([resume]);
    expect(recordsCarried(packet as unknown as Packet, "Session")).toStrictEqual([session]);
    expect(recordsCarried(packet as unknown as Packet, "Branch")).toStrictEqual([]);
  });

  it("tells a mind which of its own packets to send again", () => {
    const sent = mine.map((packet) => contentId(packet));
    const own = { address: ada.address, sent };
    const resumeWith = (lastReceived: Resume["lastReceived"]): Resume => ({
      oip: "1",
      type: "Resume",
      session: sid,
      lastReceived,
      created: T(500),
    });
    const entry = (seq: number, more: JsonObject = {}) => ({
      mind: ada.address,
      seq,
      packet: sent[seq]!,
      ...more,
    });
    // Its sender has nothing of this chain: all of it.
    expect(lacking(resumeWith([]), own)).toStrictEqual({ ok: true, value: 0 });
    const others = { mind: cy.address, seq: 1, packet: contentId(cys[1]) };
    expect(lacking(resumeWith([others]), own)).toStrictEqual({ ok: true, value: 0 });
    // It has the first: from the second on.
    expect(lacking(resumeWith([others, entry(0)]), own)).toStrictEqual({ ok: true, value: 1 });
    // It has them all: nothing.
    expect(lacking(resumeWith([entry(2)]), own)).toStrictEqual({ ok: true, value: 3 });
    // Two entries for the chain that disagree: from the lesser.
    expect(lacking(resumeWith([entry(2), entry(0)]), own)).toStrictEqual({ ok: true, value: 1 });
    // An entry for another instance of this mind is for another chain.
    expect(lacking(resumeWith([entry(1, { instance: "phone" })]), own)).toStrictEqual({
      ok: true,
      value: 0,
    });
    expect(
      lacking(resumeWith([entry(1, { instance: "phone" })]), { ...own, instance: "phone" }),
    ).toStrictEqual({ ok: true, value: 2 });
  });

  it("is refused where it names a packet the chain does not have at that place", () => {
    const sent = mine.map((packet) => contentId(packet));
    const own = { address: ada.address, sent };
    const naming = (seq: number, packet: string): Resume => ({
      oip: "1",
      type: "Resume",
      session: sid,
      lastReceived: [
        { mind: cy.address, seq: 0, packet: contentId(cys[0]) },
        { mind: ada.address, seq, packet },
      ],
      created: T(500),
    });
    const refused = { ok: false, issues: [{ clause: "L1 14.4", path: "/lastReceived/1/packet" }] };
    // Another packet at that place, this chain's packet at another place, and a place beyond its end.
    expect(lacking(naming(1, contentId(cys[1] as object)), own)).toMatchObject(refused);
    expect(lacking(naming(1, sent[2]!), own)).toMatchObject(refused);
    expect(lacking(naming(3, sent[2]!), own)).toMatchObject(refused);
  });

  it("is checked against what the receiver holds of its sender's chain", () => {
    const sessions = new Sessions(bob.address);
    for (const packet of mine) take(sessions, packet);
    const saying = (lastSent: Resume["lastSent"] | undefined, id = sid): Resume => ({
      oip: "1",
      type: "Resume",
      session: id,
      ...(lastSent === undefined ? {} : { lastSent }),
      lastReceived: [],
      created: T(500),
    });
    const place = (seq: number, of: readonly Signed[] = mine) => ({
      seq,
      packet: contentId(of[seq]),
    });
    expect(sessions.against(saying(place(2)), ada.address)).toBe("level");
    expect(sessions.against(saying(place(1)), ada.address)).toBe("ahead");
    expect(sessions.against(saying({ seq: 3, packet: place(2).packet }), ada.address)).toBe(
      "behind",
    );
    expect(sessions.against(saying({ seq: 1, packet: place(2).packet }), ada.address)).toBe(
      "conflict",
    );
    // A sender that says it sent nothing, of which the receiver holds something or nothing.
    expect(sessions.against(saying(undefined), ada.address)).toBe("ahead");
    expect(sessions.against(saying(undefined), cy.address)).toBe("level");
    // A chain the receiver has nothing of, and an instance it has nothing of.
    expect(sessions.against(saying(place(0, cys)), cy.address)).toBe("behind");
    expect(sessions.against(saying({ ...place(2), instance: "phone" }), ada.address)).toBe(
      "behind",
    );
    // A session it does not hold.
    const elsewhere = contentId({ ...session, nonce: "session-0002" });
    expect(sessions.against(saying(place(2), elsewhere), ada.address)).toBeUndefined();
  });
});

describe(`${clause("L1 14.3")} what a receiver holds of a session, written down and given back`, () => {
  /** Bob's sessions after Ada's first three packets and Cy's first, as written down and read back. */
  function kept() {
    const sessions = new Sessions(bob.address);
    for (const packet of [...chainOf(ada, 3), ...chainOf(cy, 1, { instance: "phone" })]) {
      expect(take(sessions, packet)).toMatchObject({ kind: "in order" });
    }
    const held = sessions.held(sid);
    return { sessions, written: JSON.parse(JSON.stringify(held)) as NonNullable<typeof held> };
  }

  it("is the Session record and the packets of each chain in order", () => {
    const { sessions, written } = kept();
    expect(sessions.held(contentId({ ...session, nonce: "session-0002" }))).toBeUndefined();
    expect(written).toStrictEqual({
      session,
      chains: [
        { from: ada.address, ids: chainOf(ada, 3).map((packet) => contentId(packet)) },
        {
          from: cy.address,
          instance: "phone",
          ids: chainOf(cy, 1, { instance: "phone" }).map((packet) => contentId(packet)),
        },
      ],
    });
  });

  it("lets a receiver that stopped go on where it was: the next link is in order, an old one a duplicate", () => {
    const { sessions, written } = kept();
    const again = new Sessions(bob.address);
    expect(again.restore(written)).toStrictEqual({ ok: true, value: sid });
    expect(again.size).toBe(1);
    expect(again.session(sid)).toStrictEqual(session);
    expect(again.holdsChain({ session: sid, from: ada.address, instance: undefined })).toBe(true);
    expect(again.holdsChain({ session: sid, from: cy.address, instance: "phone" })).toBe(true);
    expect(again.holdsChain({ session: sid, from: cy.address, instance: undefined })).toBe(false);
    const chain = chainOf(ada, 5);
    expect(take(again, chain[1]!)).toStrictEqual({ kind: "duplicate" });
    // A packet without the Session record is taken: the record is held again.
    expect(take(again, chain[3]!)).toMatchObject({ kind: "in order" });
    // It stands where the receiver that never stopped stands.
    expect(take(sessions, chain[3]!)).toMatchObject({ kind: "in order" });
    expect(again.resume(sid, undefined, T(50))).toStrictEqual(
      sessions.resume(sid, undefined, T(50)),
    );
    expect(again.held(sid)).toStrictEqual(sessions.held(sid));
    // What is given back is a copy: the receiver that went on did not change it.
    expect(written.chains[0]?.ids).toHaveLength(3);
  });

  it("does not hold the packets that wait ahead of a gap", () => {
    const sessions = new Sessions(bob.address);
    const chain = chainOf(ada, 3);
    expect(take(sessions, chain[0]!)).toMatchObject({ kind: "in order" });
    expect(take(sessions, chain[2]!)).toStrictEqual({ kind: "waiting", next: 1 });
    const again = new Sessions(bob.address);
    expect(again.restore(sessions.held(sid) as never).ok).toBe(true);
    // The gap is filled, and nothing waited for it here: the third is asked for again (14.4).
    const filled = take(again, chain[1]!);
    expect("delivered" in filled && ids(filled.delivered)).toStrictEqual([contentId(chain[1]!)]);
  });

  it("keeps an equivocation found: the chain is verified no further after it is taken up again", () => {
    const sessions = new Sessions(bob.address);
    const chain = chainOf(ada, 2);
    const other = link(ada, 1, chain[0], { nonce: "another-nonce" });
    expect(take(sessions, chain[0]!)).toMatchObject({ kind: "in order" });
    expect(take(sessions, chain[1]!)).toMatchObject({ kind: "in order" });
    const found = take(sessions, other);
    expect(found).toMatchObject({ kind: "equivocation", seq: 1 });
    const again = new Sessions(bob.address);
    expect(again.restore(JSON.parse(JSON.stringify(sessions.held(sid))) as never)).toStrictEqual({
      ok: true,
      value: sid,
    });
    expect(
      again.equivocation({ session: sid, from: ada.address, instance: undefined }),
    ).toStrictEqual(found);
    expect(take(again, link(ada, 2, chain[1]))).toStrictEqual(found);
  });

  it("is rejected, and nothing kept of it, where it is not what a receiver held", () => {
    const { written } = kept();
    const [first, second] = written.chains as [
      (typeof written.chains)[0],
      (typeof written.chains)[0],
    ];
    const id = first.ids[0]!;
    const rejected = (state: unknown, self = bob.address) => {
      const sessions = new Sessions(self);
      const result = sessions.restore(state as never);
      expect(sessions.size).toBe(result.ok ? 1 : 0);
      return result.ok ? "taken" : `${result.issues[0].clause} ${result.issues[0].path}`;
    };
    expect(rejected(written)).toBe("taken");
    expect(rejected(null)).toBe("L1 14.1 /session");
    expect(rejected({ ...written, session: { ...session, participants: [ada.address] } })).toBe(
      "L1 14.1 /session",
    );
    // A receiver that is no participant holds no such session.
    expect(rejected(written, eve.address)).toBe("L1 14.3 /session");
    expect(rejected({ session })).toBe("L1 14.3 /chains");
    expect(rejected({ session, chains: "none" })).toBe("L1 14.3 /chains");
    const chains = (...given: unknown[]) => rejected({ session, chains: given });
    expect(chains()).toBe("taken");
    expect(chains(null)).toBe("L1 14.3 /chains/0");
    expect(chains("a chain")).toBe("L1 14.3 /chains/0");
    expect(chains(first, { ...second, from: 7 })).toBe("L1 14.3 /chains/1");
    expect(chains({ ...first, instance: 7 })).toBe("L1 14.3 /chains/0");
    expect(chains({ ...first, instance: "i".repeat(65) })).toBe("L1 14.3 /chains/0");
    expect(chains({ ...first, instance: "i".repeat(64) })).toBe("taken");
    expect(chains({ ...first, ids: undefined })).toBe("L1 14.3 /chains/0");
    expect(chains({ ...first, ids: [id, "not a content ID"] })).toBe("L1 14.3 /chains/0");
    // A mind that is no participant has no chain in the session.
    expect(chains({ ...first, from: eve.address })).toBe("L1 14.3 /chains/0/from");
    // One chain for each sender and instance.
    expect(chains(first, { ...first, ids: [] })).toBe("L1 14.3 /chains/1");
    expect(chains(first, { ...first, instance: "phone" })).toBe("taken");
    const equivocated = (equivocation: unknown) => chains({ ...first, equivocation });
    const [a, b] = first.ids as [string, string, string];
    expect(equivocated({ kind: "equivocation", seq: 1, packets: [a, b] })).toBe("taken");
    expect(equivocated("found")).toBe("L1 14.3 /chains/0");
    expect(equivocated(null)).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: "1", packets: [a, b] })).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: 1.5, packets: [a, b] })).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: -1, packets: [a, b] })).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: 1, packets: [a] })).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: 1, packets: [a, b, a] })).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: 1, packets: [a, "another"] })).toBe("L1 14.3 /chains/0");
    expect(equivocated({ seq: 1, packets: "two" })).toBe("L1 14.3 /chains/0");
    // Two packets at one place are two packets.
    expect(equivocated({ seq: 1, packets: [a, a] })).toBe("L1 14.3 /chains/0");
  });

  it("names the two packets of an equivocation in one order, however they were written down", () => {
    const { written } = kept();
    const [first] = written.chains as [(typeof written.chains)[0]];
    const [a, b] = (first.ids as [string, string, string]).toSorted();
    const again = new Sessions(bob.address);
    expect(
      again.restore({
        session,
        chains: [{ ...first, equivocation: { kind: "equivocation", seq: 1, packets: [b, a] } }],
      } as never).ok,
    ).toBe(true);
    expect(again.held(sid)?.chains[0]?.equivocation).toStrictEqual({
      kind: "equivocation",
      seq: 1,
      packets: [a, b],
    });
  });

  it("is rejected where the session is held already, or the limits do not allow it", () => {
    const { sessions, written } = kept();
    expect(sessions.restore(written)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 14.3", path: "/session" }],
    });
    // The limit on sessions: one is followed, and no second is taken up.
    const one = new Sessions(bob.address, { maxSessions: 1 });
    expect(one.restore(written).ok).toBe(true);
    const another = { ...session, nonce: "session-0002" };
    expect(one.restore({ session: another, chains: [] } as never)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit", path: "/session" }],
    });
    expect(one.size).toBe(1);
    expect(one.drop(sid)).toBe(true);
    expect(one.restore({ session: another, chains: [] } as never).ok).toBe(true);
    // The limit on the chains of one sender.
    const [first] = written.chains as [(typeof written.chains)[0]];
    const two = {
      session,
      chains: [first, { ...first, instance: "a" }, { ...first, instance: "b" }],
    };
    expect(new Sessions(bob.address, { maxInstances: 2 }).restore(two as never)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit", path: "/chains/2/instance" }],
    });
    expect(new Sessions(bob.address, { maxInstances: 3 }).restore(two as never).ok).toBe(true);
    // A sender is held to the limit after its chains are taken up again, as before.
    const full = new Sessions(bob.address, { maxInstances: 1 });
    expect(full.restore({ session, chains: [first] } as never).ok).toBe(true);
    expect(take(full, link(ada, 0, undefined, { instance: "tablet" }))).toMatchObject({
      rejected: "implementation limit",
      path: "/instance",
    });
  });
});
