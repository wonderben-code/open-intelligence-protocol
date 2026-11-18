// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, and what the judges of this package answer
 * (ADR-0004).
 *
 * With the call stack all but spent, a check below one of these judges
 * answers with a refusal that is true of the moment and not of what was
 * judged. An answer built on it would be wrong, and a caller would keep it:
 * a feed that ends early, an older location record as the current one, a
 * packet with a place in a session it was never given. These tests make the
 * fault for certain, by noting a failure for want of room from inside the
 * work, as the places that turn one into an answer do. `spent-stack.test.ts`
 * makes it by spending the stack.
 */

import { contentId, proofDigest } from "@oip/core";
import { type IdentityView, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { type Entry, noteCutShort } from "@oip/schema";
import { clause, type JsonObject } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  AcceptedPackets,
  Challenges,
  checkpointRoot,
  committedProofs,
  currentLocation,
  currentParticipant,
  receivePacket,
  recordsCarried,
  sessionCarried,
  Sessions,
  verifyCheckpoint,
  verifyFeed,
  verifyHello,
  verifyParticipant,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const SPENT = { ok: false, issues: [{ clause: "implementation limit", path: "" }] };
const RECORD = "application/oip+json";

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const minds = [ada, bob];

const judged = (record: object): JudgedRecord => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

/**
 * A view of everyone's logs, with evidence for the records given, that notes a check cut
 * short each time it is asked for a log while `cut.now` is set, and then answers as usual.
 */
function cutting(records: readonly object[] = []) {
  const seen = witness(
    minds.map((mind) => mind.events),
    records,
  );
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  const cut = { now: false };
  const view: IdentityView = {
    evidence: book.evidence,
    log: (mind) => {
      if (cut.now) noteCutShort(new RangeError("Maximum call stack size exceeded"));
      return book.log(mind);
    },
  };
  return { view, cut, seen };
}

/** Runs `work` with a `toJSON` on every object: nothing can be serialised (core 2). */
function unfit<T>(work: () => T): T {
  Object.defineProperty(Object.prototype, "toJSON", {
    value: () => "rewritten",
    configurable: true,
    writable: true,
  });
  try {
    return work();
  } finally {
    delete (Object.prototype as { toJSON?: unknown }).toJSON;
  }
}

const intent = (seconds: number) =>
  ada.sign({
    oip: "1",
    type: "Intent",
    author: ada.address,
    created: T(seconds),
    want: `Thing ${seconds}.`,
  }) as Signed;

/** A feed of Ada that publishes the records, one entry each. */
function feedOf(records: readonly Signed[]): Signed[] {
  const entries: Signed[] = [];
  for (const [seq, record] of records.entries()) {
    entries.push(
      ada.sign({
        oip: "1",
        type: "Entry",
        author: ada.address,
        seq,
        ...(seq === 0 ? {} : { prev: contentId(entries[seq - 1] as object) }),
        created: T(50 + seq),
        object: contentId(record),
        objectType: String(record["type"]),
        proofs: record.proof.map((proof) => proofDigest(proof as never)),
      }),
    );
  }
  return entries;
}

const location = (seq: number, more: JsonObject = {}) =>
  ada.sign({
    oip: "1",
    type: "Location",
    author: ada.address,
    seq,
    created: T(10 + seq),
    ttl: 900,
    status: "active",
    endpoints: [],
    ...more,
  }) as Signed;

describe(`${clause("core 4.4")} a check that was cut short, in a feed`, () => {
  const entries = feedOf([intent(1), intent(2), intent(3)]);

  it("is no feed that ends early: `verifyFeed` refuses, and is right when asked again", () => {
    const { view, cut } = cutting(entries);
    cut.now = true;
    expect(verifyFeed(entries, ada.address, view)).toMatchObject(SPENT);
    cut.now = false;
    const feed = verifyFeed(entries, ada.address, view);
    expect(feed.ok && feed.value.entries).toHaveLength(3);
  });

  it("is no checkpoint refused for its signature, and no proof left out", () => {
    const { view, cut } = cutting(entries);
    const feed = verifyFeed(entries, ada.address, view);
    if (!feed.ok) throw new Error(JSON.stringify(feed.issues));
    const ids = feed.value.entries.map((entry) => entry.id);
    const checkpoint = ada.sign({
      oip: "1",
      type: "Checkpoint",
      author: ada.address,
      created: T(60),
      size: 3,
      head: ids[2]!,
      root: checkpointRoot(ids)!,
    });
    const held = cutting([...entries, checkpoint]);
    expect(verifyCheckpoint(judged(checkpoint), feed.value, held.view).ok).toBe(true);
    held.cut.now = true;
    expect(verifyCheckpoint(judged(checkpoint), feed.value, held.view)).toMatchObject(SPENT);
    // Nothing is hashed in a process that can serialise nothing: no proof is found committed,
    // and none is said to be missing.
    const [entry] = entries as [Signed];
    const record = judged(intent(1));
    expect(committedProofs(entry as unknown as Entry, record)).toHaveLength(1);
    expect(unfit(() => committedProofs(entry as unknown as Entry, record))).toBeUndefined();
    expect(cut.now).toBe(false);
  });
});

describe(`${clause("core 4.4")} a check that was cut short, for a location or a profile`, () => {
  it("is no older location record taken for the current one", () => {
    const records = [location(1), location(2)];
    const { view, cut } = cutting(records);
    const held = records.map((record) => judged(record));
    cut.now = true;
    expect(currentLocation(held, ada.address, view)).toBeUndefined();
    cut.now = false;
    expect(currentLocation(held, ada.address, view)?.record.seq).toBe(2);
  });

  it("is no profile refused, and none passed over for an older one", () => {
    const profile = (seconds: number) =>
      ada.sign({
        oip: "1",
        type: "Participant",
        author: ada.address,
        created: T(seconds),
        name: "Ada",
        kind: "agent",
      }) as Signed;
    const [older, newer] = [profile(10), profile(20)];
    const entries = feedOf([older, newer]);
    const { view, cut } = cutting([older, newer, ...entries]);
    const feed = verifyFeed(entries, ada.address, view);
    if (!feed.ok) throw new Error(JSON.stringify(feed.issues));
    const profiles = [older, newer].map((record) => judged(record));
    cut.now = true;
    expect(verifyParticipant(judged(newer), view)).toMatchObject(SPENT);
    expect(currentParticipant(profiles, ada.address, view, { feed: feed.value })).toBeUndefined();
    cut.now = false;
    expect(verifyParticipant(judged(newer), view).ok).toBe(true);
    expect(currentParticipant(profiles, ada.address, view, { feed: feed.value })?.id).toBe(
      contentId(newer),
    );
  });
});

describe(`${clause("core 4.4")} a check that was cut short, for a packet`, () => {
  const session = {
    oip: "1",
    type: "Session",
    participants: minds.map((mind) => mind.address).sort(),
    nonce: "session-0001",
    created: T(0),
  };
  const sid = contentId(session);
  const link = (from: Mind, seq: number, prev: object | undefined): Signed =>
    from.sign({
      oip: "1",
      type: "Packet",
      from: from.address,
      to: [bob.address],
      created: T(10 + seq),
      nonce: `nonce-000${seq}`,
      session: sid,
      seq,
      ...(prev === undefined ? {} : { prev: contentId(prev) }),
      purpose: { verb: "inform" },
      content:
        seq === 0
          ? { mediaType: RECORD, body: session }
          : { mediaType: "text/plain", body: `Message ${seq}.` },
    });

  it("is no packet rejected for its signature: `receivePacket` refuses, and nothing is remembered", () => {
    const { view, cut, seen } = cutting();
    const accepted = new AcceptedPackets();
    const receiver = {
      address: bob.address,
      now: at(100),
      view,
      seen,
      accepted: accepted.has,
      window: 3_600_000_000_000n,
    };
    const packet = link(ada, 0, undefined);
    cut.now = true;
    expect(receivePacket(packet, receiver)).toMatchObject(SPENT);
    cut.now = false;
    const again = receivePacket(packet, receiver);
    expect(again.ok && again.value.duplicate).toBe(false);
  });

  it("is no place in a session: `take` keeps nothing, and delivers the packet when it comes again", () => {
    const { view, seen } = cutting();
    const receiver = {
      address: bob.address,
      now: at(100),
      view,
      seen,
      accepted: () => false,
      window: 3_600_000_000_000n,
    };
    const first = receivePacket(link(ada, 0, undefined), receiver);
    if (!first.ok) throw new Error(JSON.stringify(first.issues));
    const sessions = new Sessions(bob.address);
    // The Session record cannot be checked against the session's ID where nothing is hashed.
    expect(unfit(() => sessions.take(first.value))).toMatchObject(SPENT);
    expect(sessions.size).toBe(0);
    expect(sessions.holdsChain({ session: sid, from: ada.address, instance: undefined })).toBe(
      false,
    );
    const taken = sessions.take(first.value);
    expect(taken.ok && taken.value.kind).toBe("in order");
    // And the records a packet carries are none, there, and not some.
    const packet = first.value.packet;
    expect(unfit(() => sessionCarried(packet))).toBeUndefined();
    expect(recordsCarried(packet, "Session")).toHaveLength(1);
  });
});

describe(`${clause("core 4.4")} a check that was cut short, for a Hello`, () => {
  it("authenticates nobody and uses no challenge up", () => {
    const { view, cut, seen } = cutting();
    const challenges = new Challenges();
    challenges.issue("nonce-for-ada-0001", at(95));
    const hello = ada.sign(
      { oip: "1", type: "Hello", author: ada.address, created: T(99) },
      { more: { challenge: "nonce-for-ada-0001", domain: "https://host.example" } },
    );
    const server = { origin: "https://host.example", now: at(100), challenges, view, seen };
    cut.now = true;
    expect(verifyHello(hello, server)).toMatchObject(SPENT);
    expect(challenges.size).toBe(1);
    cut.now = false;
    expect(verifyHello(hello, server).ok).toBe(true);
    expect(challenges.size).toBe(0);
  });
});

describe("a failure that is no check cut short", () => {
  it("is a mistake in the calling program, and is not hidden", () => {
    const { view } = cutting();
    const broken: IdentityView = {
      evidence: view.evidence,
      log: () => {
        throw new Error("the view is broken");
      },
    };
    const records = [location(1)].map((record) => judged(record));
    expect(() => currentLocation(records, ada.address, broken)).toThrow("the view is broken");
    const entries = feedOf([intent(1)]);
    expect(() => verifyFeed(entries, ada.address, broken)).toThrow("the view is broken");
  });
});
