// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the judges of this package answer with the call stack all but spent.
 * `spent-stack.test.ts` runs it in a process of its own (`inNode` says why)
 * and reads what it prints.
 */

import { contentId, proofDigest } from "@oip/core";
import { type JudgedRecord, judgeRecord, LogBook } from "@oip/identity";
import { tally, withStackSpent } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";

import {
  AcceptedPackets,
  Challenges,
  currentLocation,
  receivePacket,
  type Receiver,
  Sessions,
  verifyFeed,
  verifyHello,
} from "../src/index.ts";

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");
const minds = [ada, bob];

function judgedOf(value: object): JudgedRecord {
  const judged = judgeRecord(value);
  if (!judged.ok) throw new Error(judged.issues[0].message);
  return judged.value;
}

/** A book that has verified nothing yet: the judges below are the first to ask it. */
function coldBook() {
  const seen = witness(minds.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  return { book, seen };
}

const session = {
  oip: "1",
  type: "Session",
  participants: minds.map((mind) => mind.address).sort(),
  nonce: "session-0001",
  created: T(0),
};
const sid = contentId(session);

function link(from: Mind, seq: number, prev: object | undefined) {
  return from.sign({
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
        ? { mediaType: "application/oip+json", body: session }
        : { mediaType: "text/plain", body: `Message ${seq}.` },
  });
}

/** A session followed from a spent stack: every packet is delivered once, and none is lost. */
function sessions(): unknown {
  const { book, seen } = coldBook();
  const accepted = new AcceptedPackets();
  const followed = new Sessions(bob.address);
  const receiver: Receiver = {
    address: bob.address,
    now: at(100),
    view: book,
    seen,
    accepted: accepted.has,
    window: 3_600_000_000_000n,
    holdsChain: followed.holdsChain,
  };
  const chain: object[] = [];
  for (let seq = 0; seq < 4; seq++) chain.push(link(ada, seq, chain[seq - 1]));
  const delivered: string[] = [];
  const kinds: string[] = [];
  /** Receives one packet and takes it into the session, as a receiver does. */
  const deliver = (packet: object): string => {
    const got = receivePacket(packet, receiver);
    if (!got.ok) return `not received: ${got.issues[0].clause}`;
    const placed = followed.take(got.value);
    if (!placed.ok) return `not placed: ${placed.issues[0].clause}`;
    if (placed.value.kind === "in order") {
      for (const one of placed.value.delivered) delivered.push(one.id);
    }
    return placed.value.kind;
  };
  // Each packet arrives with the stack spent, over and over, and then once more with room.
  for (const packet of chain) {
    for (const kind of withStackSpent(() => deliver(packet), 50)) kinds.push(kind);
    kinds.push(deliver(packet));
  }
  return {
    kinds: tally(kinds, (kind) => kind),
    deliveredOnce: delivered.join() === chain.map((packet) => contentId(packet)).join(),
    delivered: delivered.length,
  };
}

function packets(): unknown {
  const { book, seen } = coldBook();
  const packet = ada.sign({
    oip: "1",
    type: "Packet",
    from: ada.address,
    to: [bob.address],
    created: T(10),
    expires: T(4000),
    nonce: "nonce-0001",
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "Hello." },
  });
  const receiver: Receiver = {
    address: bob.address,
    now: at(20),
    view: book,
    seen,
    accepted: () => false,
    window: 3_600_000_000_000n,
  };
  const kind = (): string => {
    const got = receivePacket(packet, receiver);
    if (got.ok) return got.value.id === contentId(packet) ? "received" : "received another";
    return `refused: ${got.issues[0].clause}`;
  };
  return { received: tally(withStackSpent(kind), (answer) => answer), after: kind() };
}

function feeds(): unknown {
  const entries: object[] = [];
  const records = [0, 1, 2].map((n) =>
    ada.sign({ oip: "1", type: "Intent", author: ada.address, created: T(n), want: `Thing ${n}.` }),
  );
  for (const [seq, record] of records.entries()) {
    entries.push(
      ada.sign({
        oip: "1",
        type: "Entry",
        author: ada.address,
        seq,
        ...(seq === 0 ? {} : { prev: contentId(entries[seq - 1]!) }),
        created: T(50 + seq),
        object: contentId(record),
        objectType: "Intent",
        proofs: (record as { proof: object[] }).proof.map((proof) => proofDigest(proof as never)),
      }),
    );
  }
  const seen = witness(
    minds.map((mind) => mind.events),
    entries,
  );
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  const kind = (): string => {
    const feed = verifyFeed(entries, ada.address, book);
    if (!feed.ok) return `refused: ${feed.issues[0].clause}`;
    return `${feed.value.entries.length} entries, ${feed.value.refused.length} refused`;
  };
  return { verified: tally(withStackSpent(kind), (answer) => answer), after: kind() };
}

function locations(): unknown {
  const record = ada.sign({
    oip: "1",
    type: "Location",
    author: ada.address,
    seq: 1,
    created: T(10),
    ttl: 900,
    status: "active",
    endpoints: [],
  });
  const older = ada.sign({
    oip: "1",
    type: "Location",
    author: ada.address,
    seq: 0,
    created: T(5),
    ttl: 900,
    status: "active",
    endpoints: [],
  });
  const seen = witness(
    minds.map((mind) => mind.events),
    [record, older],
  );
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  const judged = [older, record].map((value) => judgedOf(value));
  const kind = (): string => {
    const current = currentLocation(judged, ada.address, book);
    return current === undefined ? "none" : `seq ${current.record.seq}`;
  };
  return { current: tally(withStackSpent(kind), (answer) => answer), after: kind() };
}

function hellos(): unknown {
  const { book, seen } = coldBook();
  const challenges = new Challenges();
  challenges.issue("nonce-for-ada-0001", at(95));
  const hello = ada.sign(
    { oip: "1", type: "Hello", author: ada.address, created: T(99) },
    { more: { challenge: "nonce-for-ada-0001", domain: "https://host.example" } },
  );
  const server = { origin: "https://host.example", now: at(100), challenges, view: book, seen };
  const kind = (): string => {
    const open = challenges.size;
    const answer = verifyHello(hello, server);
    if (answer.ok) return "authenticated";
    // A refusal for want of room leaves the challenge open.
    return challenges.size === open ? `refused: ${answer.issues[0].clause}` : "refused, and used";
  };
  const answers = withStackSpent(kind);
  // The challenge is used up by the first answer that stands, then or now, and by no other.
  const once = answers.filter((answer) => answer === "authenticated").length;
  const after = kind();
  return {
    answered: tally(answers, (answer) => answer),
    authenticatedOnce: once + (after === "authenticated" ? 1 : 0) === 1,
    open: challenges.size,
  };
}

// The session comes first, while the code is as cold as the books.
const report = {
  sessions: sessions(),
  packets: packets(),
  feeds: feeds(),
  locations: locations(),
  hellos: hellos(),
};
process.stdout.write(JSON.stringify(report));
