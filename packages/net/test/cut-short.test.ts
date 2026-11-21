// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, and what the judges of this package answer
 * (ADR-0010).
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

import {
  contentId,
  encodeX25519Multikey,
  formatKeyRef,
  proofDigest,
  x25519PublicKey,
} from "@oip/core";
import { type IdentityView, type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { cutShortCount, type Entry, noteCutShort } from "@oip/schema";
import { clause, type JsonObject } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AcceptedPackets,
  ackEvidence,
  acknowledges,
  Challenges,
  checkpointRoot,
  committedProofs,
  currentLocation,
  currentParticipant,
  draftAck,
  type InnerList,
  parseDictionary,
  receivePacket,
  receiveSealed,
  recordsCarried,
  RequestNonces,
  sealPacket,
  sessionCarried,
  Sessions,
  signatureBase,
  signRequest,
  verifyAck,
  verifyBranch,
  verifyCheckpoint,
  verifyFeed,
  verifyHello,
  verifyParticipant,
  verifyRequest,
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

describe(`${clause("core 4.4")} a check that was cut short, for an acknowledgement`, () => {
  it("is no Ack refused for its signature, and no evidence for some proofs and not others", () => {
    const { view, cut, seen } = cutting();
    const packet = ada.sign({
      oip: "1",
      type: "Packet",
      from: ada.address,
      to: [bob.address],
      created: T(10),
      expires: T(3610),
      nonce: "nonce-0001",
      purpose: { verb: "propose" },
      content: { mediaType: RECORD, body: intent(5) },
    });
    const got = receivePacket(packet, {
      address: bob.address,
      now: at(20),
      view,
      seen,
      accepted: () => false,
      window: 3_600_000_000_000n,
    });
    if (!got.ok) throw new Error(JSON.stringify(got.issues));
    const ack = bob.sign(
      draftAck({ received: got.value, recipient: bob.address, at: T(20), created: T(21) }),
    );
    cut.now = true;
    expect(verifyAck(ack, { view, seen, now: at(30) })).toMatchObject(SPENT);
    cut.now = false;
    const held = verifyAck(ack, { view, seen, now: at(30) });
    if (!held.ok) throw new Error(JSON.stringify(held.issues));
    expect(ackEvidence(held.value, got.value.judged)?.proofs).toHaveLength(2);
    // Where nothing is hashed, nothing is acknowledged and nothing is evidence.
    expect(unfit(() => acknowledges(held.value, got.value.judged))).toBe(false);
    expect(unfit(() => ackEvidence(held.value, got.value.judged))).toBeUndefined();

    // A check cut short while the proofs of the record the packet carries are verified. The
    // carried record reads as it is, counts its readings, and notes a check cut short from
    // one reading on.
    const carried = (got.value.packet.content as { body: object }).body;
    const reading = (from: number) => {
      const read = { times: 0 };
      const body = new Proxy(carried, {
        ownKeys: (target) => {
          if (++read.times >= from)
            noteCutShort(new RangeError("Maximum call stack size exceeded"));
          return Reflect.ownKeys(target);
        },
      });
      const packet = {
        ...got.value.judged,
        record: { ...got.value.packet, content: { mediaType: RECORD, body } },
      } as unknown as JudgedRecord;
      return { read, packet };
    };
    // Read without a fault, the packet is the one acknowledged, with both its proofs.
    const whole = reading(Number.POSITIVE_INFINITY);
    expect(acknowledges(held.value, whole.packet)).toBe(true);
    const whileNamed = whole.read.times;
    expect(whileNamed).toBeGreaterThan(0);
    expect(ackEvidence(held.value, reading(Number.POSITIVE_INFINITY).packet)?.proofs).toHaveLength(
      2,
    );
    // Cut short after the packet was found to be the one acknowledged: no evidence at all,
    // and not evidence for the packet's own proof alone.
    expect(ackEvidence(held.value, reading(whileNamed + 1).packet)).toBeUndefined();
  });
});

describe(`${clause("core 4.4")} a check that was cut short, for a sealed packet`, () => {
  it("seals nothing and receives nothing, and does both when asked again", async () => {
    const secret = new Uint8Array(32).fill(3);
    const carol = new KeyMind("carol", 0, {
      agreement: [{ key: encodeX25519Multikey(x25519PublicKey(secret)) }],
    });
    const seen = witness([ada.events, carol.events]);
    const book = new LogBook(seen);
    for (const mind of [ada, carol]) book.hold(mind.events, LATER);
    const cut = { now: false };
    const view: IdentityView = {
      evidence: book.evidence,
      log: (mind) => {
        if (cut.now) noteCutShort(new RangeError("Maximum call stack size exceeded"));
        return book.log(mind);
      },
    };
    const packet = ada.sign({
      oip: "1",
      type: "Packet",
      from: ada.address,
      to: [carol.address],
      created: T(10),
      expires: T(3610),
      nonce: "nonce-0001",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "Hello." },
    });
    const draft = { packet, to: carol.address, view, randomness: new Uint8Array(32).fill(8) };
    cut.now = true;
    expect(await sealPacket(draft)).toMatchObject(SPENT);
    cut.now = false;
    const sealed = await sealPacket(draft);
    if (!sealed.ok) throw new Error(JSON.stringify(sealed.issues));
    const receiver = {
      address: carol.address,
      now: at(20),
      view,
      seen,
      accepted: () => false,
      window: 3_600_000_000_000n,
      agreementKey: () => secret,
    };
    cut.now = true;
    expect(await receiveSealed(sealed.value, receiver)).toMatchObject(SPENT);
    cut.now = false;
    expect((await receiveSealed(sealed.value, receiver)).ok).toBe(true);
    // Cut short while the record is opened, before any packet is judged: it is refused, and
    // not called a record that does not open.
    const whileOpening = {
      ...receiver,
      agreementKey: () => {
        noteCutShort(new RangeError("Maximum call stack size exceeded"));
        return secret;
      },
    };
    expect(await receiveSealed(sealed.value, whileOpening)).toMatchObject(SPENT);
  });
});

describe(`${clause("core 4.4")} a check that was cut short, for a fork's proposal`, () => {
  it("is no proposal refused for its lineage", () => {
    const parent = new KeyMind("parent");
    const child = new KeyMind("child", 5, {
      parents: [{ mind: parent.address, at: parent.versionId(0) }],
    });
    parent.fork(20, { child: child.address });
    const all = [parent, child, bob];
    const seen = witness(all.map((mind) => mind.events));
    const book = new LogBook(seen);
    for (const mind of all) book.hold(mind.events, LATER);
    const cut = { now: false };
    const view: IdentityView = {
      evidence: book.evidence,
      log: (mind) => {
        if (cut.now) noteCutShort(new RangeError("Maximum call stack size exceeded"));
        return book.log(mind);
      },
    };
    const session = {
      oip: "1",
      type: "Session",
      participants: [bob.address, parent.address].sort(),
      nonce: "session-0009",
      created: T(0),
    };
    const packet = child.sign({
      oip: "1",
      type: "Packet",
      from: child.address,
      to: [bob.address],
      created: T(30),
      expires: T(3630),
      nonce: "nonce-0001",
      purpose: { verb: "branch" },
      content: {
        mediaType: RECORD,
        body: {
          oip: "1",
          type: "Branch",
          parentSession: contentId(session),
          fork: `${parent.address}?versionId=${parent.versionId(1)}`,
          created: T(30),
        },
      },
    });
    const got = receivePacket(packet, {
      address: bob.address,
      now: at(40),
      view,
      seen,
      accepted: () => false,
      window: 3_600_000_000_000n,
    });
    if (!got.ok) throw new Error(JSON.stringify(got.issues));
    const held = () => session as never;
    cut.now = true;
    expect(verifyBranch(got.value, held, view)).toMatchObject(SPENT);
    cut.now = false;
    expect(verifyBranch(got.value, held, view).ok).toBe(true);
  });
});

describe(`${clause("core 4.4")} a check that was cut short, for an authenticated request`, () => {
  it("authenticates nobody and remembers no nonce", async () => {
    const { view, cut } = cutting();
    const nonces = new RequestNonces();
    const request = {
      method: "GET",
      url: "https://mailbox.example/oip/mbox/abc",
      headers: [] as [string, string][],
    };
    const added = await signRequest(
      request,
      {
        keyRef: formatKeyRef(ada.address, ada.versionId(), ada.operational().publicKey),
        created: at(100),
        nonce: "nonce-0001",
      },
      ada.operational(),
    );
    const signed = { ...request, headers: added };
    const server = { now: at(110), view, nonces };
    cut.now = true;
    expect(verifyRequest(signed, server)).toMatchObject(SPENT);
    expect(nonces.size).toBe(0);
    cut.now = false;
    expect(verifyRequest(signed, server).ok).toBe(true);
    expect(nonces.size).toBe(1);
  });
});

describe(`${clause("L1 13.3")} a check that was cut short, for what a request's signature is read from`, () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("builds no signature base for a request that could not be read", () => {
    const covered: InnerList = {
      kind: "list",
      items: [{ kind: "item", value: { kind: "string", value: "date" }, parameters: [] }],
      parameters: [],
    };
    const spent = {
      method: "GET",
      url: "https://mailbox.example/oip/mbox/abc",
      headers: new Proxy([], {
        get: () => {
          throw new RangeError("Maximum call stack size exceeded");
        },
      }),
    };
    expect(signatureBase(spent as never, covered)).toMatchObject(SPENT);
    const read = { ...spent, headers: [["Date", "Tue, 20 Apr 2021 02:07:55 GMT"]] };
    expect(signatureBase(read as never, covered)).toMatchObject({ ok: true });
  });

  it("reads nothing of a field where the reading found no room, and notes it", () => {
    // The text is text, and cannot be made to throw: a spy stands in for the call that
    // found no room.
    vi.spyOn(RegExp.prototype, "exec").mockImplementationOnce(() => {
      throw new RangeError("Maximum call stack size exceeded");
    });
    const before = cutShortCount();
    expect(parseDictionary("a=1")).toBeUndefined();
    expect(cutShortCount()).toBe(before + 1);
    expect(parseDictionary("a=1")?.size).toBe(1);
    // Text that is no dictionary is no sign of anything else.
    expect(parseDictionary("a=")).toBeUndefined();
    expect(cutShortCount()).toBe(before + 1);
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

  it("is not hidden by a judge that waits either", async () => {
    const { view } = cutting();
    const broken: IdentityView = {
      evidence: view.evidence,
      log: () => {
        throw new Error("the view is broken");
      },
    };
    const packet = ada.sign({
      oip: "1",
      type: "Packet",
      from: ada.address,
      to: [bob.address],
      created: T(10),
      expires: T(3610),
      nonce: "nonce-0001",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "Hello." },
    });
    await expect(
      sealPacket({ packet, to: bob.address, view: broken, randomness: new Uint8Array(32) }),
    ).rejects.toThrow("the view is broken");
  });
});
