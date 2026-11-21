// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, OipError, proofDigest } from "@oip/core";
import { type FirstSeen, type IdentityView, LogBook } from "@oip/identity";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import { at, Collective, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { AcceptedPackets, type Receiver, receivePacket, recordsCarried } from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const SECOND = 1_000_000_000n;
const HOUR = 3600n * SECOND;
const DAY = 86_400;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const cy = new KeyMind("cy");
const eve = new KeyMind("eve");
/** A broker. */
const ian = new KeyMind("ian");
const everyone = [ada, bob, cy, eve, ian];

/** A packet from one mind to others, made at `seconds` and good for an hour, not yet signed. */
const draft = (
  from: Mind,
  to: readonly Mind[] | JsonObject,
  seconds: number,
  more: JsonObject = {},
): JsonObject => ({
  oip: "1",
  type: "Packet",
  from: from.address,
  to: Array.isArray(to) ? (to as readonly Mind[]).map((mind) => mind.address) : to,
  created: T(seconds),
  expires: T(seconds + 3600),
  nonce: "nonce-0001",
  purpose: { verb: "inform" },
  content: { mediaType: "text/plain", body: "The lease is translated." },
  ...more,
});

/** A session packet: it names a session and its place in a chain, and states no `expires`. */
const inSession = (from: Mind, to: readonly Mind[], seconds: number, more: JsonObject = {}) => {
  const { expires: _, ...packet } = draft(from, to, seconds, {
    session: contentId({ oip: "1", type: "Session", nonce: "session-01", created: T(0) }),
    seq: 0,
    ...more,
  });
  return packet;
};

/** A receiver that holds everyone's log, keeps its own first sight, and has accepted nothing yet. */
function receiverAt(
  of: Mind,
  seconds: number,
  more: Partial<Receiver> = {},
  minds: readonly Mind[] = everyone,
) {
  const seen = witness(minds.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  const accepted = new AcceptedPackets();
  const receiver: Receiver = {
    address: of.address,
    now: at(seconds),
    view: book,
    seen,
    accepted: accepted.has,
    window: HOUR,
    ...more,
  };
  return { receiver, seen, accepted, book };
}

/** Why a packet is rejected: the clause and the place. */
function refusal(value: unknown, receiver: Receiver) {
  const result = receivePacket(value, receiver);
  if (result.ok) throw new Error("the packet was accepted");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

describe(`${clause("L1 12.4")} receiving a packet`, () => {
  it("accepts a packet its sender signed, addressed to the receiver, within its dates", () => {
    const packet = ada.sign(draft(ada, [bob], 10)) as Signed;
    const { receiver } = receiverAt(bob, 20);
    const result = receivePacket(packet, receiver);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    expect(result.value.id).toBe(contentId(packet));
    expect(result.value.packet.from).toBe(ada.address);
    // Signed at 10 and first seen at 20: it counts from 20 (core 9.3).
    expect(result.value.time).toBe(at(20));
    expect(result.value.duplicate).toBe(false);
    expect(result.value.forgetAfter).toBe(at(10 + 3600 + 300));
    expect(result.value.broker).toBeUndefined();
    expect(result.value.judged.proofs).toHaveLength(1);
  });

  it("is addressed to the receiver when `to` lists its address", () => {
    const { receiver } = receiverAt(bob, 20);
    expect(receivePacket(ada.sign(draft(ada, [cy, bob, eve], 10)), receiver).ok).toBe(true);
    expect(refusal(ada.sign(draft(ada, [cy, eve], 10)), receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/to",
    });
    // The sender is not a recipient for having sent it.
    expect(refusal(bob.sign(draft(bob, [ada], 10)), receiver).path).toBe("/to");
  });

  it("accepts no packet addressed to a query that arrives as itself, and none to a subject", () => {
    const { receiver } = receiverAt(bob, 20);
    const toQuery = ada.sign(draft(ada, { query: { want: "A translator." } }, 10));
    expect(refusal(toQuery, receiver)).toStrictEqual({ clause: "L1 12.4", path: "/to" });
    const toSubject = ada.sign(draft(ada, { subject: "leases/*" }, 10));
    expect(refusal(toSubject, receiver)).toStrictEqual({ clause: "L1 12.1", path: "/to" });
  });

  it("carries a proof that counts by its sender's own authority", () => {
    const { receiver } = receiverAt(bob, 20);
    // In Ada's name, by Eve.
    expect(refusal(eve.sign(draft(ada, [bob], 10)), receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/proof",
    });
    // By Ada, and by Eve as well: one proof that counts is enough.
    expect(receivePacket(eve.sign(ada.sign(draft(ada, [bob], 10))), receiver).ok).toBe(true);
    // From a mind whose log the receiver does not hold.
    const stranger = new KeyMind("stranger");
    expect(refusal(stranger.sign(draft(stranger, [bob], 10)), receiver).path).toBe("/proof");
    // A signature that was changed on the way.
    const packet = ada.sign(draft(ada, [bob], 10)) as Signed;
    const [proof] = packet.proof as [JsonObject];
    const value = String(proof["proofValue"]);
    const changed = { ...packet, proof: [{ ...proof, proofValue: `${value.slice(0, -1)}z` }] };
    expect(refusal(changed, receiver).path).toBe("/proof");
  });

  it("does not count a proof by a key its sender has removed", () => {
    const zed = new KeyMind("zed");
    const early = zed.sign(draft(zed, [bob], 10)) as Signed;
    zed.update(100, { keys: [{ key: zed.operational(1).publicKey }] });
    const minds = [bob, zed];
    // First seen at 200, after the removal at 100, whatever date it states.
    expect(refusal(early, receiverAt(bob, 200, {}, minds).receiver).path).toBe("/proof");
    // By the new key it counts.
    const later = zed.sign(draft(zed, [bob], 150), { key: 1 });
    expect(receivePacket(later, receiverAt(bob, 200, {}, minds).receiver).ok).toBe(true);
  });

  it(`${clause("L1 9.5")} counts a collective's threshold for a packet the collective sends`, () => {
    const club = new Collective("club", [ada, cy, eve], 2, 5);
    const minds = [...everyone, club];
    const content = draft(club, [bob], 10);
    const byTwo = cy.sign(ada.sign(content));
    const byOne = ada.sign(content);
    expect(receivePacket(byTwo, receiverAt(bob, 20, {}, minds).receiver).ok).toBe(true);
    expect(refusal(byOne, receiverAt(bob, 20, {}, minds).receiver).path).toBe("/proof");
  });

  it("is a Packet, or a Forwarded record with one", () => {
    const { receiver } = receiverAt(bob, 20);
    const intent = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T(10),
      want: "A translation.",
    });
    expect(refusal(intent, receiver)).toStrictEqual({ clause: "L1 12.4", path: "/type" });
    // A value that is no record is refused as one.
    for (const value of [undefined, null, 7, "packet", [], {}, { type: "Packet" }]) {
      expect(receivePacket(value, receiver).ok, JSON.stringify(value)).toBe(false);
    }
  });

  it("stands for the packet of the test vectors", () => {
    const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
    const packet = cases["packet"] as Signed;
    const logs = [cases["lexis_agent_log"], cases["amina_log"]] as unknown as JsonObject[][];
    const seen = witness(logs);
    const book = new LogBook(seen);
    for (const log of logs) book.hold(log, LATER);
    const [recipient] = packet["to"] as [string];
    const created = Date.parse(String(packet["created"]));
    const result = receivePacket(packet, {
      address: recipient,
      now: BigInt(created) * 1_000_000n + 5n * SECOND,
      view: book,
      seen,
      accepted: () => false,
      window: HOUR,
    });
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    expect(result.value.id).toBe(contentId(packet));
  });
});

describe(`${clause("L1 12.4")} the dates of a packet`, () => {
  it(`${clause("L1 19")} rejects a packet made more than 300 seconds in the future`, () => {
    const { receiver } = receiverAt(bob, 1000);
    expect(receivePacket(ada.sign(draft(ada, [bob], 1300)), receiver).ok).toBe(true);
    expect(refusal(ada.sign(draft(ada, [bob], 1301)), receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/created",
    });
  });

  it(`${clause("L1 19")} rejects a packet that expired more than 300 seconds ago`, () => {
    const packet = ada.sign(draft(ada, [bob], 10, { expires: T(1000) }));
    expect(receivePacket(packet, receiverAt(bob, 1300).receiver).ok).toBe(true);
    expect(refusal(packet, receiverAt(bob, 1300.000000001).receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/expires",
    });
  });

  it(`${clause("L1 19")} rejects a packet that asks to be delivered for more than 7 days`, () => {
    const { receiver } = receiverAt(bob, 20);
    const week = ada.sign(draft(ada, [bob], 10, { expires: T(10 + 7 * DAY) }));
    const more = ada.sign(draft(ada, [bob], 10, { expires: T(10 + 7 * DAY + 1) }));
    expect(receivePacket(week, receiver).ok).toBe(true);
    expect(refusal(more, receiver)).toStrictEqual({ clause: "L1 12.4", path: "/expires" });
  });

  it("rejects a packet that states no `expires` once it is older than the receiver remembers", () => {
    const packet = ada.sign(inSession(ada, [bob], 1000));
    const window = 600n * SECOND;
    const within = receivePacket(packet, receiverAt(bob, 1600, { window }).receiver);
    if (!within.ok) throw new Error(JSON.stringify(within.issues));
    // It can be accepted until its `created` plus the window, and is remembered until then.
    expect(within.value.forgetAfter).toBe(at(1600));
    expect(refusal(packet, receiverAt(bob, 1601, { window }).receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/created",
    });
  });

  it("accepts such a packet still, where the receiver holds the state of its sending chain", () => {
    const packet = ada.sign(inSession(ada, [bob], 1000, { instance: "laptop" })) as Signed;
    const asked: unknown[] = [];
    const holdsChain = (chain: unknown) => {
      asked.push(chain);
      return true;
    };
    const window = 600n * SECOND;
    expect(receivePacket(packet, receiverAt(bob, 5000, { window, holdsChain }).receiver).ok).toBe(
      true,
    );
    expect(asked).toStrictEqual([
      { session: packet["session"], from: ada.address, instance: "laptop" },
    ]);
    // A chain it does not hold is no reason, and neither is an answer that is not `true`.
    for (const answer of [false, undefined, "yes"]) {
      const not = (() => answer) as unknown as NonNullable<Receiver["holdsChain"]>;
      expect(
        refusal(packet, receiverAt(bob, 5000, { window, holdsChain: not }).receiver).path,
      ).toBe("/created");
    }
    // It is asked only then: not of a packet within the window, nor of one that states `expires`.
    asked.length = 0;
    receivePacket(packet, receiverAt(bob, 1100, { window, holdsChain }).receiver);
    receivePacket(ada.sign(draft(ada, [bob], 10)), receiverAt(bob, 20, { holdsChain }).receiver);
    expect(asked).toStrictEqual([]);
  });

  it("judges the dates before it keeps anything, and the signature after", () => {
    // A packet that is too late is rejected for its dates, whoever signed it.
    const { receiver, seen } = receiverAt(bob, 100_000);
    const late = eve.sign(draft(ada, [bob], 10)) as Signed;
    expect(refusal(late, receiver).path).toBe("/expires");
    expect(seen.proofSeen(proofDigest(late.proof[0] as never))).toBeUndefined();
  });
});

describe(`${clause("core 9.4")} the receiver's own first sight`, () => {
  it("is recorded for the proofs of a packet addressed to the receiver, as seen now", () => {
    const packet = ada.sign(draft(ada, [bob], 10)) as Signed;
    const { receiver, seen } = receiverAt(bob, 20);
    const digest = proofDigest(packet.proof[0]);
    expect(seen.proofSeen(digest)).toBeUndefined();
    expect(receivePacket(packet, receiver).ok).toBe(true);
    expect(seen.proofSeen(digest)).toBe(at(20));
    // An earlier sight stays: the packet counts from when it was first seen.
    const again = receivePacket(packet, { ...receiver, now: at(500) });
    expect(again.ok && again.value.time).toBe(at(20));
  });

  it("is not recorded for a packet addressed to someone else, or of another type", () => {
    const { receiver, seen } = receiverAt(bob, 20);
    const other = ada.sign(draft(ada, [cy], 10)) as Signed;
    expect(receivePacket(other, receiver).ok).toBe(false);
    expect(seen.proofSeen(proofDigest(other.proof[0] as never))).toBeUndefined();
  });

  it("is the caller's to record where `seen` is left out", () => {
    const packet = ada.sign(draft(ada, [bob], 10)) as Signed;
    const { book } = receiverAt(bob, 20);
    const base = { address: bob.address, now: at(20), accepted: () => false, window: HOUR };
    // No evidence for the proof: it does not count (core 9.3).
    expect(refusal(packet, { ...base, view: book }).path).toBe("/proof");
    // Evidence from elsewhere: a witness that saw the proof when it was made.
    const seen: FirstSeen = witness(
      everyone.map((mind) => mind.events),
      [packet],
    );
    const informed = new LogBook(seen);
    for (const mind of everyone) informed.hold(mind.events, LATER);
    const result = receivePacket(packet, { ...base, view: informed });
    expect(result.ok && result.value.time).toBe(at(10));
  });
});

describe(`${clause("L1 12.4")} duplicates`, () => {
  it("are told by content ID, of packets that were accepted", () => {
    const packet = ada.sign(draft(ada, [bob], 10)) as Signed;
    const { receiver, accepted } = receiverAt(bob, 20);
    const first = receivePacket(packet, receiver);
    if (!first.ok) throw new Error(JSON.stringify(first.issues));
    expect(first.value.duplicate).toBe(false);
    accepted.record(first.value);
    expect(accepted.size).toBe(1);
    const second = receivePacket(packet, receiver);
    expect(second.ok && second.value.duplicate).toBe(true);
    // The same packet with one more proof is the same packet (core 3.1).
    const cosigned = receivePacket(eve.sign(packet), receiver);
    expect(cosigned.ok && cosigned.value.duplicate).toBe(true);
    // Another packet is another, though it differs only in its nonce.
    const other = receivePacket(ada.sign(draft(ada, [bob], 10, { nonce: "nonce-0002" })), receiver);
    expect(other.ok && other.value.duplicate).toBe(false);
  });

  it("are recorded only after the packet has verified: a corrupted copy discards nothing", () => {
    const packet = ada.sign(draft(ada, [bob], 10)) as Signed;
    const [proof] = packet.proof as [JsonObject];
    const value = String(proof["proofValue"]);
    const corrupted = { ...packet, proof: [{ ...proof, proofValue: `${value.slice(0, -1)}z` }] };
    expect(contentId(corrupted)).toBe(contentId(packet));
    const { receiver, accepted } = receiverAt(bob, 20);
    // The corrupted copy comes first. It is rejected, and there is nothing to record.
    expect(refusal(corrupted, receiver).path).toBe("/proof");
    expect(accepted.size).toBe(0);
    const genuine = receivePacket(packet, receiver);
    if (!genuine.ok) throw new Error(JSON.stringify(genuine.issues));
    expect(genuine.value.duplicate).toBe(false);
    accepted.record(genuine.value);
    // And after the genuine packet, the corrupted copy is rejected for its proof still.
    expect(refusal(corrupted, receiver).path).toBe("/proof");
  });

  it("are remembered until the packet can no longer be accepted", () => {
    const packet = ada.sign(draft(ada, [bob], 10, { expires: T(1000) }));
    const { receiver, accepted } = receiverAt(bob, 20);
    const first = receivePacket(packet, receiver);
    if (!first.ok) throw new Error(JSON.stringify(first.issues));
    accepted.record(first.value);
    expect(first.value.forgetAfter).toBe(at(1300));
    // At the last moment it could be accepted, it is remembered.
    expect(accepted.forget(at(1300))).toBe(0);
    const last = receivePacket(packet, { ...receiver, now: at(1300) });
    expect(last.ok && last.value.duplicate).toBe(true);
    // A moment later it is forgotten, and rejected for its dates.
    expect(accepted.forget(at(1300.000000001))).toBe(1);
    expect(accepted.size).toBe(0);
    expect(accepted.has(first.value.id)).toBe(false);
    expect(refusal(packet, { ...receiver, now: at(1300.000000001) }).path).toBe("/expires");
  });

  it("keeps the later time for a packet recorded twice, and forgets each in its turn", () => {
    const accepted = new AcceptedPackets();
    const { receiver } = receiverAt(bob, 20);
    const early = receivePacket(ada.sign(draft(ada, [bob], 10, { expires: T(100) })), receiver);
    const late = receivePacket(ada.sign(draft(ada, [bob], 10, { expires: T(900) })), receiver);
    if (!early.ok || !late.ok) throw new Error("not accepted");
    accepted.record(early.value);
    accepted.record(late.value);
    accepted.record({ ...early.value, forgetAfter: at(50) });
    accepted.record({ ...late.value, forgetAfter: at(2000) });
    expect(accepted.forget(at(400))).toBe(0);
    expect(accepted.forget(at(401))).toBe(1);
    expect(accepted.has(late.value.id)).toBe(true);
    expect(accepted.forget(at(2000))).toBe(0);
    expect(accepted.forget(at(2001))).toBe(1);
    expect(() => accepted.forget(5 as never)).toThrow(TypeError);
  });
});

describe(`${clause("L1 12.4", "L1 18.5")} a packet addressed to a query`, () => {
  /** A broker's wrapper around a packet, for one mind that matched its query. */
  const forward = (broker: Mind, to: Mind, packet: object, seconds: number): JsonObject => ({
    oip: "1",
    type: "Forwarded",
    broker: broker.address,
    to: to.address,
    packet: packet,
    created: T(seconds),
  });
  const query = (more: JsonObject = {}) => ({ query: { want: "A translator." }, ...more });

  it("is accepted inside a Forwarded record addressed to the receiver and signed by its broker", () => {
    const packet = ada.sign(draft(ada, query(), 10)) as Signed;
    const wrapped = ian.sign(forward(ian, bob, packet, 12)) as Signed;
    const { receiver, seen } = receiverAt(bob, 20);
    const result = receivePacket(wrapped, receiver);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    // The packet is what was received, and its content ID is what duplicates are told by.
    expect(result.value.id).toBe(contentId(packet));
    expect(result.value.broker).toBe(ian.address);
    expect(result.value.time).toBe(at(20));
    // Both signatures were first seen now.
    expect(seen.proofSeen(proofDigest(packet.proof[0] as never))).toBe(at(20));
    expect(seen.proofSeen(proofDigest(wrapped.proof[0] as never))).toBe(at(20));
  });

  it(`${clause("L1 12.1", "L1 19")} asks for at most 50 minds, of at most 8 brokers`, () => {
    const brokers = Array.from({ length: 9 }, (_, n) => new KeyMind(`broker-${n}`).address);
    const received = (to: JsonObject) => {
      const packet = ada.sign(draft(ada, to, 10));
      return receivePacket(ian.sign(forward(ian, bob, packet, 12)), receiverAt(bob, 20).receiver);
    };
    expect(received(query({ maxFanout: 50 })).ok).toBe(true);
    expect(received(query({ maxFanout: 1 })).ok).toBe(true);
    expect(received(query({ brokers: [ian.address, ...brokers.slice(0, 7)] })).ok).toBe(true);
    // Nothing here signs a packet that asks for more, so it carries the proof of one that does not.
    const asking = (to: JsonObject) => refusedAt(draft(ada, to, 10));
    for (const maxFanout of [51, 0, -1]) {
      expect(asking(query({ maxFanout })), String(maxFanout)).toStrictEqual({
        clause: "L1 12.1",
        path: "/to/maxFanout",
      });
    }
    expect(asking(query({ brokers: brokers }))).toStrictEqual({
      clause: "L1 12.1",
      path: "/to/brokers",
    });
    expect(asking(query({ brokers: [] }))).toStrictEqual({
      clause: "L1 12.1",
      path: "/to/brokers",
    });
  });

  it("is rejected where the wrapper is for another mind, or its broker did not sign it", () => {
    const packet = ada.sign(draft(ada, query(), 10));
    const { receiver } = receiverAt(bob, 20);
    expect(refusal(ian.sign(forward(ian, cy, packet, 12)), receiver)).toStrictEqual({
      clause: "L1 18.5",
      path: "/to",
    });
    // In the broker's name, by Eve.
    expect(refusal(eve.sign(forward(ian, bob, packet, 12)), receiver)).toStrictEqual({
      clause: "L1 18.5",
      path: "/proof",
    });
  });

  it("is rejected from a broker the packet does not list, when it lists any", () => {
    const { receiver } = receiverAt(bob, 20);
    const named = ada.sign(draft(ada, query({ brokers: [cy.address, ian.address] }), 10));
    expect(receivePacket(ian.sign(forward(ian, bob, named, 12)), receiver).ok).toBe(true);
    const others = ada.sign(draft(ada, query({ brokers: [cy.address] }), 10));
    expect(refusal(ian.sign(forward(ian, bob, others, 12)), receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/packet/to/brokers",
    });
  });

  it("is judged as any packet is: by its sender's proof, its dates and the receiver's memory", () => {
    const { receiver, accepted } = receiverAt(bob, 20);
    // In Ada's name, by Eve.
    const forged = eve.sign(draft(ada, query(), 10));
    expect(refusal(ian.sign(forward(ian, bob, forged, 12)), receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/packet/proof",
    });
    // A packet addressed to a query asks to be delivered for an hour at most (12.1).
    const hour = ada.sign(draft(ada, query(), 10, { expires: T(10 + 3600) }));
    const longer = ada.sign(draft(ada, query(), 10, { expires: T(10 + 3601) }));
    expect(receivePacket(ian.sign(forward(ian, bob, hour, 12)), receiver).ok).toBe(true);
    expect(refusal(ian.sign(forward(ian, bob, longer, 12)), receiver)).toStrictEqual({
      clause: "L1 12.1",
      path: "/packet/expires",
    });
    // The same packet from two brokers is one packet.
    const first = receivePacket(ian.sign(forward(ian, bob, hour, 12)), receiver);
    if (!first.ok) throw new Error(JSON.stringify(first.issues));
    accepted.record(first.value);
    const second = receivePacket(cy.sign(forward(cy, bob, hour, 13)), receiver);
    expect(second.ok && second.value.duplicate).toBe(true);
  });

  it("carries a packet addressed by a list on that packet's own proof, whatever the wrapper", () => {
    const { receiver } = receiverAt(bob, 20);
    const listed = ada.sign(draft(ada, [bob], 10));
    // The wrapper is for another mind and signed by nobody the packet knows: it adds nothing.
    const result = receivePacket(eve.sign(forward(ian, cy, listed, 12)), receiver);
    expect(result.ok && result.value.broker).toBeUndefined();
    const elsewhere = ada.sign(draft(ada, [cy], 10));
    expect(refusal(ian.sign(forward(ian, bob, elsewhere, 12)), receiver)).toStrictEqual({
      clause: "L1 12.4",
      path: "/packet/to",
    });
    const toSubject = ada.sign(draft(ada, { subject: "leases/*" }, 10));
    expect(refusal(ian.sign(forward(ian, bob, toSubject, 12)), receiver)).toStrictEqual({
      clause: "L1 12.1",
      path: "/packet/to",
    });
  });
});

describe(`${clause("L1 12.5")} what a packet carries`, () => {
  it("is data: nothing in `content` is read, held or recorded", () => {
    // The packet carries the log of a mind the receiver does not hold, and a record it signed.
    const zoe = new KeyMind("zoe");
    const record = zoe.sign({
      oip: "1",
      type: "Intent",
      author: zoe.address,
      created: T(5),
      want: "Authority over Bob.",
    }) as Signed;
    const packet = ada.sign(
      draft(ada, [bob], 10, {
        content: {
          parts: [
            { mediaType: "application/oip+json", body: zoe.events[0] as unknown as JsonObject },
            { mediaType: "application/oip+json", body: record },
          ],
        },
      }),
    );
    const { receiver, seen, book } = receiverAt(bob, 20);
    expect(receivePacket(packet, receiver).ok).toBe(true);
    const view: IdentityView = book;
    expect(view.log(zoe.address).ok).toBe(false);
    expect(seen.eventSeen(contentId(zoe.events[0] as object))).toBeUndefined();
    expect(seen.proofSeen(proofDigest(record.proof[0] as never))).toBeUndefined();
  });
});

describe(`${clause("core 8.3")} a packet that depends on an extension`, () => {
  it("is accepted only by a receiver that implements the extension", () => {
    const packet = ada.sign(
      draft(ada, [bob], 10, { ext: { "com.example": { priority: 1 } }, critical: ["com.example"] }),
    );
    expect(refusal(packet, receiverAt(bob, 20).receiver)).toStrictEqual({
      clause: "core 8.3",
      path: "/critical",
    });
    const understood = ["com.example"];
    expect(receivePacket(packet, receiverAt(bob, 20, { understood }).receiver).ok).toBe(true);
    // And so for the packet inside a Forwarded record.
    const toQuery = ada.sign(
      draft(ada, { query: { want: "A translator." } }, 10, {
        ext: { "com.example": { priority: 1 } },
        critical: ["com.example"],
      }),
    );
    const wrapped = ian.sign({
      oip: "1",
      type: "Forwarded",
      broker: ian.address,
      to: bob.address,
      packet: toQuery,
      created: T(12),
    });
    expect(receivePacket(wrapped, receiverAt(bob, 20).receiver).ok).toBe(false);
    expect(receivePacket(wrapped, receiverAt(bob, 20, { understood }).receiver).ok).toBe(true);
  });
});

describe("the receiver's own arguments", () => {
  it("are the caller's: a time or a window that is none is a TypeError", () => {
    const packet = ada.sign(draft(ada, [bob], 10));
    const { receiver } = receiverAt(bob, 20);
    expect(() => receivePacket(packet, { ...receiver, now: 20 as never })).toThrow(TypeError);
    expect(() => receivePacket(packet, { ...receiver, window: 600 as never })).toThrow(TypeError);
    // Whatever arrived: the mistake is the caller's, and is not hidden behind a rejection.
    expect(() => receivePacket(null, { ...receiver, now: 20 as never })).toThrow(
      "now is not a time",
    );
    expect(() => receivePacket(null, { ...receiver, window: 600 as never })).toThrow(
      "the window is a duration",
    );
  });

  it("never throws on what arrives", () => {
    const { receiver } = receiverAt(bob, 20);
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw new Error("read");
        },
        ownKeys: () => {
          throw new Error("keys");
        },
      },
    );
    expect(receivePacket(hostile, receiver).ok).toBe(false);
    fc.assert(
      fc.property(fc.anything(), (value) => {
        expect(receivePacket(value, receiver).ok).toBe(false);
      }),
      { numRuns: 200 },
    );
  });
});

/**
 * A packet that is not of the form Section 12 gives. Nothing here signs one (the first
 * test below), so it carries the proof of a packet that is, as a sender's own code might.
 */
const malformed = (packet: JsonObject): JsonObject => ({
  ...packet,
  proof: (ada.sign(draft(ada, [bob], 10)) as Signed).proof,
});

/** Where a packet that is not well formed is refused, as a packet is before anything else is judged. */
function refusedAt(packet: JsonObject) {
  // A receiver that holds no log and whose clock is far off: the form is judged first.
  const { receiver } = receiverAt(bob, 10 ** 8, {}, []);
  const result = receivePacket(malformed(packet), receiver);
  if (result.ok) throw new Error("the packet was accepted");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

const accepted = (packet: JsonObject) =>
  receivePacket(ada.sign(packet), receiverAt(bob, 20).receiver);

describe(`${clause("L1 12.1")} the form of a packet`, () => {
  it("is not signed by this implementation when it is not of that form", () => {
    const { nonce: _, ...bare } = draft(ada, [bob], 10);
    expect(() => ada.sign(bare)).toThrow(OipError);
    expect(() => ada.sign(draft(ada, [], 10))).toThrow(OipError);
  });

  it("is identified by its content ID, whatever proofs it carries", () => {
    const packet = draft(ada, [bob], 10);
    const once = ada.sign(packet);
    const twice = ada.sign(once, { created: T(11) });
    expect(twice.proof).toHaveLength(2);
    const received = receivePacket(twice, receiverAt(bob, 20).receiver);
    expect(received.ok && received.value.id).toBe(contentId(packet));
    expect(contentId(once)).toBe(contentId(twice));
    // Another nonce is another packet.
    expect(contentId(draft(ada, [bob], 10, { nonce: "nonce-0002" }))).not.toBe(contentId(packet));
  });

  it(`${clause("L1 19")} has 1 to 64 recipients`, () => {
    const others = Array.from({ length: 64 }, (_, n) => new KeyMind(`recipient-${n}`).address);
    const full = [bob.address, ...others.slice(0, 63)];
    expect(accepted({ ...draft(ada, [bob], 10), to: full }).ok).toBe(true);
    const over = { ...draft(ada, [bob], 10), to: [...full, others[63]!] };
    expect(refusedAt(over)).toStrictEqual({ clause: "L1 12.1", path: "/to" });
    expect(refusedAt({ ...draft(ada, [bob], 10), to: [] })).toStrictEqual({
      clause: "L1 12.1",
      path: "/to",
    });
  });

  it("has a nonce of 8 to 64 characters", () => {
    for (const nonce of ["12345678", "n".repeat(64)]) {
      expect(accepted(draft(ada, [bob], 10, { nonce })).ok).toBe(true);
    }
    for (const nonce of ["1234567", "n".repeat(65)]) {
      expect(refusedAt(draft(ada, [bob], 10, { nonce }))).toStrictEqual({
        clause: "L1 12.1",
        path: "/nonce",
      });
    }
  });

  it("states when it expires, unless it is of a session, and has a purpose and a content", () => {
    for (const member of ["expires", "purpose", "content", "nonce", "from", "to", "created"]) {
      const { [member]: _, ...without } = draft(ada, [bob], 10);
      expect(refusedAt(without), member).toStrictEqual({ clause: "L1 12.1", path: "" });
    }
    // A packet of a session needs no `expires` (Section 14).
    expect(
      receivePacket(ada.sign(inSession(ada, [bob], 10)), receiverAt(bob, 20).receiver).ok,
    ).toBe(true);
    // `seq` and `session` come together.
    expect(refusedAt(draft(ada, [bob], 10, { seq: 0 }))).toStrictEqual({
      clause: "L1 12.1",
      path: "",
    });
  });

  it("keeps its short strings short", () => {
    const cases: [JsonObject, string][] = [
      [{ instance: "i".repeat(65) }, "/instance"],
      [{ thread: "t".repeat(129) }, "/thread"],
      [{ parentThread: "t".repeat(129) }, "/parentThread"],
      [{ replyTo: "t".repeat(129) }, "/replyTo"],
      [{ purpose: { verb: "inform", goal: "g".repeat(257) } }, "/purpose/goal"],
    ];
    for (const [more, path] of cases) {
      expect(refusedAt(draft(ada, [bob], 10, more)), path).toStrictEqual({
        clause: "L1 12.1",
        path,
      });
    }
    const most = {
      instance: "i".repeat(64),
      thread: "t".repeat(128),
      parentThread: "t".repeat(128),
      replyTo: "t".repeat(128),
      purpose: { verb: "inform", goal: "g".repeat(256) },
    };
    expect(accepted(draft(ada, [bob], 10, most)).ok).toBe(true);
  });
});

describe(`${clause("L1 12.2")} the content of a packet`, () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const text = { mediaType: "text/plain", body: "The lease is translated." };
  const elsewhere = {
    mediaType: "application/pdf",
    ref: "https://files.example/lease.pdf",
    digest,
  };
  const withContent = (content: JsonObject) => draft(ada, [bob], 10, { content });

  it("is a body, or a reference with its digest, or up to 32 parts", () => {
    const bodies: JsonObject["body"][] = ["text", 7, true, null, ["a", "b"], { a: { b: "c" } }];
    for (const body of bodies) {
      expect(accepted(withContent({ mediaType: "application/json", body })).ok).toBe(true);
    }
    expect(accepted(withContent(elsewhere)).ok).toBe(true);
    expect(accepted(withContent({ parts: [text, elsewhere] })).ok).toBe(true);
  });

  it(`${clause("L1 19")} has at most 32 parts`, () => {
    const parts = (count: number) => ({ parts: Array.from({ length: count }, () => text) });
    expect(accepted(withContent(parts(32))).ok).toBe(true);
    expect(refusedAt(withContent(parts(33)))).toStrictEqual({
      clause: "L1 12.1",
      path: "/content/parts",
    });
  });

  it("is exactly one of them", () => {
    const { digest: _, ...unpinned } = elsewhere;
    const cases: [string, JsonObject, string][] = [
      ["a body and a reference", { ...text, ...elsewhere }, "/content"],
      ["parts and a body", { parts: [text], ...text }, "/content"],
      ["a reference without its digest", unpinned, "/content"],
      ["a body of no media type", { body: "text" }, "/content"],
      ["a media type and nothing", { mediaType: "text/plain" }, "/content"],
      ["nothing", {}, "/content"],
      ["parts within parts", { parts: [{ parts: [text] }] }, "/content/parts/0"],
    ];
    for (const [name, content, path] of cases) {
      expect(refusedAt(withContent(content)), name).toStrictEqual({ clause: "L1 12.1", path });
    }
  });

  it("names what is elsewhere by a SHA-256 digest in lower-case hexadecimal", () => {
    for (const wrong of [
      `sha256:${"A".repeat(64)}`,
      `sha256:${"a".repeat(63)}`,
      `sha256:${"a".repeat(65)}`,
      `sha512:${"a".repeat(64)}`,
      "a".repeat(64),
    ]) {
      expect(refusedAt(withContent({ ...elsewhere, digest: wrong })), wrong).toStrictEqual({
        clause: "L1 12.1",
        path: "/content/digest",
      });
    }
  });

  it("carries a record as the body of a part whose media type is that of records", () => {
    const session = {
      oip: "1",
      type: "Session",
      participants: [ada.address, bob.address].sort(),
      nonce: "session-0001",
      created: T(0),
    };
    const carrying = (content: JsonObject) => {
      const received = accepted(withContent(content));
      if (!received.ok) throw new Error(JSON.stringify(received.issues));
      return recordsCarried(received.value.packet, "Session");
    };
    const record = { mediaType: "application/oip+json", body: session };
    expect(carrying(record)).toStrictEqual([session]);
    expect(carrying({ parts: [text, record, record] })).toStrictEqual([session, session]);
    // Under another media type the same body is not a record of the protocol.
    expect(carrying({ mediaType: "application/json", body: session })).toStrictEqual([]);
    // A body that is not a record is data like any other (12.5): the packet is received, and carries none.
    expect(carrying({ mediaType: "application/oip+json", body: "not a record" })).toStrictEqual([]);
    expect(
      carrying({ mediaType: "application/oip+json", body: { type: "Session" } }),
    ).toStrictEqual([]);
  });
});

describe(`${clause("L1 12.3")} the verb of a packet`, () => {
  const VERBS = [
    "inform",
    "request",
    "query",
    "propose",
    "accept",
    "decline",
    "deliver",
    "ack",
    "error",
    "open",
    "resume",
    "branch",
    "close",
  ];
  const saying = (verb: string, more: JsonObject = {}) =>
    draft(ada, [bob], 10, { purpose: { verb }, ...more });

  it("is one of thirteen, or has a namespace", () => {
    for (const verb of [...VERBS, "acme:quote", "org.example:negotiate"]) {
      expect(accepted(saying(verb)).ok, verb).toBe(true);
    }
    for (const verb of ["dance", "", "acme:", ":quote", "INFORM"]) {
      expect(refusedAt(saying(verb)), verb).toStrictEqual({
        clause: "L1 12.1",
        path: "/purpose/verb",
      });
    }
  });

  it("binds nothing: a packet is received alike whatever its verb says", () => {
    const received = [...VERBS, "acme:quote"].map((verb) => {
      const result = accepted(saying(verb));
      if (!result.ok) throw new Error(JSON.stringify(result.issues));
      const { id: _, packet: __, judged, ...rest } = result.value;
      return { ...rest, proofs: judged.proofs.length };
    });
    for (const one of received) expect(one).toStrictEqual(received[0]);
  });

  it("opens, resumes and branches nothing by itself: what counts is the record in `content`", () => {
    const session = {
      oip: "1",
      type: "Session",
      participants: [ada.address, bob.address].sort(),
      nonce: "session-0001",
      created: T(0),
    };
    const carried = (packet: JsonObject) => {
      const result = accepted(packet);
      if (!result.ok) throw new Error(JSON.stringify(result.issues));
      return (["Session", "Resume", "Branch"] as const).flatMap((type) =>
        recordsCarried(result.value.packet, type),
      );
    };
    for (const verb of ["open", "resume", "branch", "accept"]) {
      expect(carried(saying(verb)), verb).toStrictEqual([]);
    }
    // And a record is carried under any verb.
    const content = { mediaType: "application/oip+json", body: session };
    expect(carried(saying("inform", { content }))).toStrictEqual([session]);
  });
});
