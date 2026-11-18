// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, proofDigest } from "@oip/core";
import {
  type FirstSeen,
  type JudgedRecord,
  judgeRecord,
  LogBook,
  ownSignedTime,
} from "@oip/identity";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import { at, Collective, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  ackEvidence,
  acknowledges,
  draftAck,
  type ReceivedPacket,
  receivePacket,
  verifyAck,
  type VerifiedAck,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const RECORD = "application/oip+json";
const HOUR = 3_600_000_000_000n;

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const cy = new KeyMind("cy");
const eve = new KeyMind("eve");
const everyone = [ada, bob, cy, eve];

const digestOf = (proof: unknown): string => proofDigest(proof);

const judged = (record: object): JudgedRecord => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

/** An offer Ada signed, which her packets carry. */
const offer = ada.sign({
  oip: "1",
  type: "Intent",
  author: ada.address,
  created: T(5),
  want: "A lease translated by Friday.",
}) as Signed;

/** A packet from Ada that carries the offer, made at 10 and good for an hour. */
const packetTo = (to: readonly Mind[] | JsonObject, more: JsonObject = {}): Signed =>
  ada.sign({
    oip: "1",
    type: "Packet",
    from: ada.address,
    to: Array.isArray(to)
      ? (to as readonly Mind[]).map((mind) => mind.address)
      : (to as JsonObject),
    created: T(10),
    expires: T(3610),
    nonce: "nonce-0001",
    purpose: { verb: "propose" },
    content: { mediaType: RECORD, body: offer },
    ...more,
  });

/** A book of everyone's logs with a record of first sight of its own. */
function verifier(minds: readonly Mind[] = everyone) {
  const seen = witness(minds.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  return { book, seen };
}

/** The packet as Bob's gate accepts it at 20. */
function receivedBy(of: Mind, packet: object): ReceivedPacket {
  const { book, seen } = verifier();
  const result = receivePacket(packet, {
    address: of.address,
    now: at(20),
    view: book,
    seen,
    accepted: () => false,
    window: HOUR,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/** Bob's acknowledgement of a packet, received at 20 and acknowledged at 21. */
const ackOf = (packet: object, by: Mind = bob, more: JsonObject = {}): Signed =>
  by.sign({
    ...draftAck({
      received: receivedBy(by, packet),
      recipient: by.address,
      at: T(20),
      created: T(21),
    }),
    ...more,
  });

/** The acknowledgement as a verifier judges it at 30, having just obtained it. */
function verified(ack: object, minds: readonly Mind[] = everyone): VerifiedAck {
  const { book, seen } = verifier(minds);
  const result = verifyAck(ack, { view: book, seen, now: at(30) });
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

describe(`${clause("L1 13.2")} an acknowledgement`, () => {
  const packet = packetTo([bob, cy]);

  it("names the packet, says when it was received, and lists the packet's own proofs", () => {
    const draft = draftAck({
      received: receivedBy(bob, packet),
      recipient: bob.address,
      at: T(20),
      created: T(21),
    });
    expect(draft).toStrictEqual({
      oip: "1",
      type: "Ack",
      author: bob.address,
      packet: contentId(packet),
      proofs: [digestOf(packet.proof[0])],
      received: T(20),
      created: T(21),
    });
    // With the content ID of the Sealed record it arrived in, if it arrived in one.
    const sealed = contentId({ oip: "1", type: "Sealed", to: bob.address });
    const inSealed = draftAck({
      received: receivedBy(bob, packet),
      recipient: bob.address,
      at: T(20),
      created: T(21),
      sealed,
    });
    expect(inSealed.sealed).toBe(sealed);
    expect(judgeRecord(bob.sign(inSealed)).ok).toBe(true);
  });

  it("lists the proofs that verified, and no entry that did not", () => {
    const [proof] = packet.proof as [JsonObject];
    const value = String(proof["proofValue"]);
    const broken = { ...proof, proofValue: `${value.slice(0, -1)}z` };
    const cosigned = eve.sign(packet) as Signed;
    const arrived = { ...cosigned, proof: [...cosigned.proof, broken] };
    const draft = draftAck({
      received: receivedBy(bob, arrived),
      recipient: bob.address,
      at: T(20),
      created: T(21),
    });
    expect(draft.proofs).toStrictEqual(cosigned.proof.map((entry) => digestOf(entry)));
  });

  it("is signed by its author's own authority", () => {
    const ack = verified(ackOf(packet));
    expect(ack.recipient).toBe(bob.address);
    expect(ack.packet).toBe(contentId(packet));
    expect(ack.received).toBe(at(20));
    // Made at 21 and first seen at 30: it counts from 30 (core 9.3).
    expect(ack.time).toBe(at(30));
    const { book, seen } = verifier();
    const context = { view: book, seen, now: at(30) };
    // In Bob's name, by Eve.
    const { proof: _, ...content } = ackOf(packet);
    expect(verifyAck(eve.sign(content), context)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 13.2", path: "/proof" }],
    });
    // With no evidence for its proof, it is not signed (core 9.3).
    expect(verifyAck(ackOf(packet), { view: verifier().book })).toMatchObject({
      ok: false,
      issues: [{ path: "/proof" }],
    });
    // Another record is no Ack.
    expect(verifyAck(offer, context)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 13.2", path: "/type" }],
    });
    for (const value of [undefined, null, 7, "ack", {}, []]) {
      expect(verifyAck(value, context).ok, JSON.stringify(value)).toBe(false);
    }
  });

  it(`${clause("L1 9.5")} is a collective's when its signers meet the threshold`, () => {
    const club = new Collective("club", [bob, cy, eve], 2, 1);
    const minds = [...everyone, club];
    const toClub = packetTo([club]);
    const { book, seen } = verifier(minds);
    const got = receivePacket(toClub, {
      address: club.address,
      now: at(20),
      view: book,
      seen,
      accepted: () => false,
      window: HOUR,
    });
    if (!got.ok) throw new Error(JSON.stringify(got.issues));
    const draft = draftAck({
      received: got.value,
      recipient: club.address,
      at: T(20),
      created: T(21),
    });
    const context = { view: book, seen, now: at(30) };
    expect(verifyAck(cy.sign(bob.sign(draft)), context).ok).toBe(true);
    expect(verifyAck(bob.sign(draft), context).ok).toBe(false);
  });

  it(`${clause("core 8.3")} is judged with a critical extension only by a verifier that implements it`, () => {
    const { proof: _, ...content } = ackOf(packet);
    const extended = bob.sign({
      ...content,
      ext: { "com.example": { queue: "inbox" } },
      critical: ["com.example"],
    });
    const { book, seen } = verifier();
    const context = { view: book, seen, now: at(30) };
    expect(verifyAck(extended, context)).toMatchObject({
      ok: false,
      issues: [{ clause: "core 8.3" }],
    });
    expect(verifyAck(extended, { ...context, understood: ["com.example"] }).ok).toBe(true);
  });

  it("is judged with the present and the record of first sight together, or with neither", () => {
    const { book, seen } = verifier();
    expect(() => verifyAck(ackOf(packet), { view: book, seen })).toThrow(TypeError);
    expect(() => verifyAck(ackOf(packet), { view: book, now: at(30) })).toThrow(TypeError);
  });

  it("stands for the acknowledgement of the test vectors, which names their packet", () => {
    const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
    const logs = [cases["lexis_agent_log"], cases["amina_log"]] as unknown as JsonObject[][];
    const seen = witness(logs, [cases["ack"] as object]);
    const book = new LogBook(seen);
    for (const log of logs) book.hold(log, LATER);
    const ack = verifyAck(cases["ack"], { view: book });
    if (!ack.ok) throw new Error(JSON.stringify(ack.issues));
    expect(acknowledges(ack.value, judged(cases["packet"] as object))).toBe(true);
  });
});

describe(`${clause("L1 13.2")} what an acknowledgement acknowledges`, () => {
  const packet = packetTo([bob, cy]);

  it("is the packet it names, for one of that packet's recipients", () => {
    const ack = verified(ackOf(packet));
    expect(acknowledges(ack, judged(packet))).toBe(true);
    // The same packet with one more proof on it is the same packet (core 3.1).
    expect(acknowledges(ack, judged(eve.sign(packet)))).toBe(true);
    // Another packet, though it differs only in its nonce.
    expect(acknowledges(ack, judged(packetTo([bob, cy], { nonce: "nonce-0002" })))).toBe(false);
    // A record that is no packet.
    expect(acknowledges(ack, judged(offer))).toBe(false);
  });

  it("is nothing from a mind the packet was not addressed to", () => {
    // Eve signs a well-formed Ack that names the packet. She is no recipient of it.
    const { proof: _, ...content } = ackOf(packet);
    const eves = verified(eve.sign({ ...content, author: eve.address }));
    expect(eves.packet).toBe(contentId(packet));
    expect(acknowledges(eves, judged(packet))).toBe(false);
    expect(ackEvidence(eves, judged(packet))).toBeUndefined();
  });

  it("is, for a packet addressed to a query, whoever received it from a broker", () => {
    const toQuery = judged(packetTo({ query: { want: "A translator." } }));
    const ack = { ...verified(ackOf(packet)), packet: contentId(toQuery.record) };
    expect(acknowledges(ack, toQuery)).toBe(true);
    // A packet addressed to a subject has no recipients yet.
    const toSubject = judged(packetTo({ subject: "leases/*" }));
    expect(acknowledges({ ...ack, packet: contentId(toSubject.record) }, toSubject)).toBe(false);
  });
});

describe(`${clause("core 9.4", "L1 13.2")} the evidence an acknowledgement is`, () => {
  const packet = packetTo([bob, cy]);
  const own = digestOf(packet.proof[0]);
  const carried = digestOf(offer.proof[0]);

  it("is for the proofs on the records the packet carries, and for its own proofs that are listed", () => {
    const evidence = ackEvidence(verified(ackOf(packet)), judged(packet));
    expect(evidence?.time).toBe(at(20));
    expect([...(evidence?.proofs ?? [])].sort()).toStrictEqual([own, carried].sort());
  });

  it("is for no proof on the packet that the Ack does not list", () => {
    // An Ack that lists none, as one made before `proofs` existed.
    const { proof: _, proofs: __, ...content } = ackOf(packet);
    const bare = verified(bob.sign(content));
    expect(ackEvidence(bare, judged(packet))?.proofs).toStrictEqual([carried]);
    // A proof added to the packet after it was acknowledged: the content ID is the same.
    const later = ada.sign(packet, { created: T(15) }) as Signed;
    expect(later.proof).toHaveLength(2);
    expect(contentId(later)).toBe(contentId(packet));
    const evidence = ackEvidence(verified(ackOf(packet)), judged(later));
    expect([...(evidence?.proofs ?? [])].sort()).toStrictEqual([own, carried].sort());
    expect(evidence?.proofs).not.toContain(digestOf(later.proof[1]));
  });

  it("is for no proof the Ack lists that is not on the packet as held", () => {
    const stray = digestOf(offer.proof[0]).replace(/.$/u, (last) => (last === "0" ? "1" : "0"));
    const ack = verified(ackOf(packet, bob, { proofs: [own, stray] }));
    const evidence = ackEvidence(ack, judged(packet));
    expect(evidence?.proofs).not.toContain(stray);
    expect(evidence?.proofs).toContain(own);
  });

  it("covers every record among the parts, and nothing that is not sent as a record", () => {
    const second = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T(6),
      want: "And a summary.",
    }) as Signed;
    const [proof] = second.proof as [JsonObject];
    const broken = {
      ...second,
      proof: [{ ...proof, proofValue: `${String(proof["proofValue"]).slice(0, -1)}z` }],
    };
    const asJson = eve.sign({
      oip: "1",
      type: "Intent",
      author: eve.address,
      created: T(7),
      want: "Something else.",
    }) as Signed;
    const multipart = packetTo([bob], {
      content: {
        parts: [
          { mediaType: RECORD, body: offer },
          { mediaType: RECORD, body: second },
          // A record whose proof does not verify, a record sent as plain JSON, and text.
          { mediaType: RECORD, body: broken },
          {
            mediaType: "application/json",
            body: asJson,
          },
          { mediaType: "text/plain", body: "Shall we?" },
        ],
      },
    });
    const evidence = ackEvidence(verified(ackOf(multipart)), judged(multipart));
    expect([...(evidence?.proofs ?? [])].sort()).toStrictEqual(
      [digestOf(multipart.proof[0]), carried, digestOf(second.proof[0])].sort(),
    );
    expect(evidence?.proofs).not.toContain(digestOf(asJson.proof[0]));
  });

  it("lets a verifier that trusts the recipient count a proof from when the packet was received", () => {
    // Zed sends Bob a packet, and later removes the key that signed it.
    const zed = new KeyMind("zed");
    const sent = zed.sign({
      oip: "1",
      type: "Packet",
      from: zed.address,
      to: [bob.address],
      created: T(10),
      expires: T(3610),
      nonce: "nonce-0001",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "The work is done." },
    }) as Signed;
    const minds = [bob, zed];
    const first = verifier(minds);
    const got = receivePacket(sent, {
      address: bob.address,
      now: at(20),
      view: first.book,
      seen: first.seen,
      accepted: () => false,
      window: HOUR,
    });
    if (!got.ok) throw new Error(JSON.stringify(got.issues));
    const ack = bob.sign(
      draftAck({ received: got.value, recipient: bob.address, at: T(20), created: T(21) }),
    );
    zed.update(100, { keys: [{ key: zed.operational(1).publicKey }] });
    // A verifier that first sees the packet at 200 does not count its proof: the key is gone.
    const late = verifier(minds);
    late.seen.sawProof(digestOf(sent.proof[0]), at(200));
    expect(ownSignedTime(judged(sent), zed.address, late.book)).toBeUndefined();
    // One that also holds Bob's acknowledgement, and takes Bob's word on time, counts it at 20.
    const informed = verifier(minds);
    const held = verifyAck(ack, { view: informed.book, seen: informed.seen, now: at(200) });
    if (!held.ok) throw new Error(JSON.stringify(held.issues));
    const evidence = ackEvidence(held.value, judged(sent));
    if (evidence === undefined) throw new Error("no evidence");
    const trusted: FirstSeen = informed.seen;
    for (const digest of evidence.proofs) trusted.sawProof(digest, evidence.time);
    expect(ownSignedTime(judged(sent), zed.address, informed.book)).toBe(at(20));
  });
});
