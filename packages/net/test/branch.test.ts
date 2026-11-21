// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId } from "@oip/core";
import { LogBook } from "@oip/identity";
import type { Session } from "@oip/schema";
import { clause, type JsonObject } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { type ReceivedPacket, receivePacket, Sessions, verifyBranch } from "../src/index.ts";

const RECORD = "application/oip+json";

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
/** Ada's fork, made from her genesis and acknowledged by a Fork event at 20. */
const kid = new KeyMind("kid", 5, { parents: [{ mind: ada.address, at: ada.versionId(0) }] });
ada.fork(20, { child: kid.address });
const forkEvent = `${ada.address}?versionId=${ada.versionId(1)}`;
/** A mind that claims Ada as a parent, which Ada has not acknowledged. */
const pretender = new KeyMind("pretender", 5, {
  parents: [{ mind: ada.address, at: ada.versionId(0) }],
});
const everyone = [ada, bob, kid, pretender];

const session = {
  oip: "1",
  type: "Session",
  participants: [ada.address, bob.address].sort(),
  nonce: "session-0001",
  created: T(0),
} as Session;
const sid = contentId(session);

const held = (id: string): Session | undefined => (id === sid ? session : undefined);

function viewOf(minds: readonly Mind[] = everyone) {
  const seen = witness(minds.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  return { book, seen };
}

/** A packet from a mind to Bob with this content, as Bob's gate accepts it at 40. */
function receivedFrom(from: Mind, content: JsonObject, more: JsonObject = {}): ReceivedPacket {
  const { book, seen } = viewOf();
  const packet = from.sign({
    oip: "1",
    type: "Packet",
    from: from.address,
    to: [bob.address],
    created: T(30),
    expires: T(3630),
    nonce: "nonce-0001",
    purpose: { verb: "branch" },
    content,
    ...more,
  });
  const result = receivePacket(packet, {
    address: bob.address,
    now: at(40),
    view: book,
    seen,
    accepted: () => false,
    window: 3_600_000_000_000n,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

const branch = (more: JsonObject = {}): JsonObject => ({
  oip: "1",
  type: "Branch",
  parentSession: sid,
  fork: forkEvent,
  created: T(30),
  ...more,
});
const carrying = (record: JsonObject) => ({ mediaType: RECORD, body: record });

function refusal(received: ReceivedPacket, lookup = held, minds: readonly Mind[] = everyone) {
  const result = verifyBranch(received, lookup, viewOf(minds).book);
  if (result.ok) throw new Error("the branch stands");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

describe(`${clause("L1 14.5")} a fork's proposal to go on from its parent's session`, () => {
  it("stands when the parent's Fork event names the sender, and the parent is a participant", () => {
    const result = verifyBranch(receivedFrom(kid, carrying(branch())), held, viewOf().book);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    expect(result.value.child).toBe(kid.address);
    expect(result.value.parent).toBe(ada.address);
    expect(result.value.parentSession).toStrictEqual(session);
    expect(result.value.branch.fork).toBe(forkEvent);
    // The record may be one part among others.
    const parts = {
      parts: [{ mediaType: "text/plain", body: "May I go on?" }, carrying(branch())],
    };
    expect(verifyBranch(receivedFrom(kid, parts), held, viewOf().book).ok).toBe(true);
  });

  it("opens nothing: the counterpart's own book of sessions is as it was", () => {
    const sessions = new Sessions(bob.address);
    const lookup = (id: string) => sessions.session(id) ?? held(id);
    expect(verifyBranch(receivedFrom(kid, carrying(branch())), lookup, viewOf().book).ok).toBe(
      true,
    );
    expect(sessions.size).toBe(0);
  });

  it("is one Branch record in the packet", () => {
    const none = receivedFrom(kid, { mediaType: "text/plain", body: "Let me in." });
    expect(refusal(none)).toStrictEqual({ clause: "L1 14.5", path: "/content" });
    const two = receivedFrom(kid, {
      parts: [carrying(branch()), carrying(branch({ created: T(31) }))],
    });
    expect(refusal(two)).toStrictEqual({ clause: "L1 14.5", path: "/content" });
    // A Branch record sent as plain JSON is no record (12.2).
    const asJson = receivedFrom(kid, { mediaType: "application/json", body: branch() });
    expect(refusal(asJson).path).toBe("/content");
  });

  it("names a session the receiver holds, of which the parent is a participant", () => {
    const received = receivedFrom(kid, carrying(branch()));
    expect(refusal(received, () => undefined)).toStrictEqual({
      clause: "L1 14.5",
      path: "/content",
    });
    // A session held, between Bob and somebody else.
    const other = { ...session, participants: [bob.address, pretender.address].sort() } as Session;
    expect(refusal(received, () => other)).toStrictEqual({ clause: "L1 14.5", path: "/content" });
  });

  it("names a Fork event of the parent whose child is the sender", () => {
    // Another event of Ada's: her genesis.
    const genesis = `${ada.address}?versionId=${ada.versionId(0)}`;
    expect(refusal(receivedFrom(kid, carrying(branch({ fork: genesis }))))).toStrictEqual({
      clause: "L1 14.5",
      path: "/content",
    });
    // A version her log does not have.
    const missing = `${ada.address}?versionId=${bob.versionId(0)}`;
    expect(refusal(receivedFrom(kid, carrying(branch({ fork: missing })))).path).toBe("/content");
    // The Fork event for the kid, sent by somebody else.
    expect(refusal(receivedFrom(pretender, carrying(branch())))).toStrictEqual({
      clause: "L1 14.5",
      path: "/content",
    });
    // And by the parent herself: she is no fork of herself.
    expect(refusal(receivedFrom(ada, carrying(branch()))).path).toBe("/content");
  });

  it(`${clause("L1 8.2")} needs the sender's lineage from that parent to be acknowledged`, () => {
    const mother = new KeyMind("mother");
    const other = new KeyMind("other");
    // A mind that does not name the mother at all, though she made a Fork event for it. It
    // names another parent, who acknowledges it.
    const stray = new KeyMind("stray", 5, {
      parents: [{ mind: other.address, at: other.versionId(0) }],
    });
    // A mind that names the mother at a version her log does not have.
    const vague = new KeyMind("vague", 5, {
      parents: [{ mind: mother.address, at: bob.versionId(0) }],
    });
    other.fork(20, { child: stray.address });
    mother.fork(20, { child: stray.address });
    mother.fork(21, { child: vague.address });
    const theirs = {
      ...session,
      participants: [bob.address, mother.address].sort(),
      nonce: "session-0002",
    } as Session;
    const minds = [bob, mother, other, stray, vague];
    for (const [child, position] of [
      [stray, 1],
      [vague, 2],
    ] as const) {
      const { book, seen } = viewOf(minds);
      const packet = child.sign({
        oip: "1",
        type: "Packet",
        from: child.address,
        to: [bob.address],
        created: T(30),
        expires: T(3630),
        nonce: "nonce-0001",
        purpose: { verb: "branch" },
        content: carrying(
          branch({
            parentSession: contentId(theirs),
            fork: `${mother.address}?versionId=${mother.versionId(position)}`,
          }),
        ),
      });
      const got = receivePacket(packet, {
        address: bob.address,
        now: at(40),
        view: book,
        seen,
        accepted: () => false,
        window: 3_600_000_000_000n,
      });
      if (!got.ok) throw new Error(JSON.stringify(got.issues));
      expect(
        refusal(got.value, () => theirs, minds),
        child.name,
      ).toStrictEqual({
        clause: "L1 8.2",
        path: "/from",
      });
    }
  });

  it("is no packet of the session it names: a fork does not send in its parent's sessions", () => {
    // The record says so of itself: a packet that claims a place in the parent's session.
    const inside = receivedFrom(kid, carrying(branch()), { session: sid, seq: 0 });
    expect(refusal(inside)).toStrictEqual({ clause: "L1 14.5", path: "/session" });
    // And the session's own book has no place for it: the fork is no participant (8.4).
    const sessions = new Sessions(bob.address);
    const opening = receivedFrom(ada, carrying(session), {
      session: sid,
      seq: 0,
      nonce: "nonce-0002",
    });
    expect(sessions.take(opening)).toMatchObject({ ok: true, value: { kind: "in order" } });
    expect(sessions.take(inside)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 14.3", path: "/from" }],
    });
  });

  it("needs the parent's log", () => {
    const received = receivedFrom(kid, carrying(branch()));
    const result = verifyBranch(received, held, viewOf([bob, kid]).book);
    expect(result.ok).toBe(false);
  });
});
